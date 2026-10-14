use std::io::Write;
use std::process::{Command, Stdio};

#[test]
fn actual_upcall_state_restores_fx_only_for_its_valid_one_shot_return() {
    let context = include_str!("../../../core/src/task/context.rs");
    let start = context.find("const FXSAVE_AREA_SIZE:").unwrap();
    let end = context.find("/// CPU コンテキスト").unwrap();
    let thread = include_str!("../../../core/src/task/thread.rs");
    let first = thread.find("const THREAD_UPCALL_QUEUE_CAPACITY:").unwrap();
    let last = thread.find("// L4 風").unwrap();
    let mut program = String::from("mod task { pub mod context {\n");
    program.push_str(&context[start..end]);
    program.push_str(
        r#"
pub fn verify_reserved_snapshot_bytes() {
    let state=FxSaveArea {bytes:[0xa7;512]};
    let bytes=state.snapshot_bytes();
    assert_eq!(bytes[5],0);
    assert!(bytes[416..].iter().all(|byte|*byte==0));
    for slot in 0..8 {
        assert!(bytes[32+slot*16..32+slot*16+10].iter().all(|byte|*byte==0xa7));
        assert!(bytes[32+slot*16+10..32+slot*16+16].iter().all(|byte|*byte==0));
    }
    assert!(bytes[160..416].iter().all(|byte|*byte==0xa7));
    assert_eq!(state.bytes,[0xa7;512]);
}
"#,
    );
    program.push_str("\n} pub mod thread {\n");
    program.push_str(&thread[first..last]);
    program.push_str(
        r#"
pub fn probe() {
    super::context::verify_reserved_snapshot_bytes();
    let mut original = super::context::FxSaveArea::initial();
    original.save_current();
    let mut state = ThreadUpcallState::new();
    let user = UserUpcallContext {
        user_rsp:99,r15:15,r14:14,r13:13,r12:12,rbx:3,rbp:4,user_rflags:0x202,
        user_rip:77,r9:9,r8:8,r10:10,rdx:2,rsi:5,rdi:6,rax:1,rcx:88,r11:11
    };
    let pattern = [0xa7u8;16]; let changed = [0x5bu8;16];
    let initial=0x3f80u32; let clobbered=0x5f80u32;
    state.install(0x1000,0x8000,false).unwrap();
    assert_eq!(state.snapshot(0),Err(ThreadUpcallError::InvalidToken));
    for _ in 0..3 {
        assert!(state.begin(user).is_none());
        state.enqueue(7).unwrap();
        unsafe { core::arch::asm!("movdqu xmm15, [{}]", "ldmxcsr [{}]",
            in(reg) pattern.as_ptr(),in(reg) &initial,out("xmm15") _,options(nostack)); }
        let delivery=state.begin(user).unwrap();
        assert_eq!(state.snapshot(delivery.token+1),Err(ThreadUpcallError::InvalidToken));
        let (captured,mut fx)=state.snapshot(delivery.token).unwrap();
        assert_eq!(captured,user);
        assert_eq!(&fx[400..416],&pattern);
        assert_eq!(u32::from_le_bytes(fx[24..28].try_into().unwrap()),initial);
        assert_eq!(fx[5],0);
        assert!(fx[416..].iter().all(|byte|*byte==0));
        for slot in 0..8 {assert!(fx[32+slot*16+10..32+slot*16+16].iter().all(|byte|*byte==0));}
        fx.fill(0xff);
        assert_ne!(state.snapshot(delivery.token).unwrap().1,fx);
        unsafe { core::arch::asm!("movdqu xmm15, [{}]", "ldmxcsr [{}]",
            in(reg) changed.as_ptr(),in(reg) &clobbered,out("xmm15") _,options(nostack)); }
        assert!(state.begin(user).is_none());
        assert_eq!(state.request_return(delivery.token+1),Err(ThreadUpcallError::InvalidToken));
        assert!(state.take_restored_context().is_none());
        let mut value=0u32;
        unsafe { core::arch::asm!("stmxcsr [{}]",in(reg) &mut value,options(nostack)); }
        assert_eq!(value,clobbered);
        state.request_return(delivery.token).unwrap();
        assert_eq!(state.snapshot(delivery.token),Err(ThreadUpcallError::InvalidToken));
        assert_eq!(state.take_restored_context(),Some(user));
        assert_eq!(state.snapshot(delivery.token),Err(ThreadUpcallError::InvalidToken));
        let mut bytes=[0u8;16];
        unsafe { core::arch::asm!("movdqu [{}], xmm15", "stmxcsr [{}]",
            in(reg) bytes.as_mut_ptr(),in(reg) &mut value,options(nostack)); }
        assert_eq!(bytes,pattern); assert_eq!(value,initial);
        assert_eq!(state.request_return(delivery.token),Err(ThreadUpcallError::InvalidToken));
    }
    assert!(state.begin_exception(user,14).is_none());
    state.install(0x1000,0x8000,true).unwrap();
    state.enqueue(0xa7).unwrap();
    let exception=state.begin_exception(user,14).unwrap();
    assert_eq!(exception.payload,14);
    assert_eq!(state.pending_len,1);
    assert_eq!(state.install(0x2000,0x9000,false),Err(ThreadUpcallError::Active));
    assert!(state.begin_exception(user,14).is_none());
    assert!(state.begin(user).is_none());
    state.request_return(exception.token).unwrap();
    assert_eq!(state.take_restored_context(),Some(user));
    let asynchronous=state.begin(user).unwrap();
    assert_eq!(asynchronous.payload,0xa7);
    assert_eq!(state.pending_len,0);
    state.request_return(asynchronous.token).unwrap();
    state.take_restored_context().unwrap();
    let event=state.begin_exception(user,14).unwrap();
    let (_,fx)=state.snapshot(event.token).unwrap();
    assert_eq!(state.request_context_restore(user,fx),Err(ThreadUpcallError::Active));
    assert_eq!(state.snapshot(event.token).unwrap(),(user,fx));
    let mut invalid_fx=fx;
    invalid_fx[24..28].copy_from_slice(&0x80001f80u32.to_le_bytes());
    invalid_fx[28..32].copy_from_slice(&u32::MAX.to_le_bytes());
    assert_eq!(state.request_return_context(event.token,user,invalid_fx),Err(ThreadUpcallError::InvalidContext));
    assert_eq!(state.snapshot(event.token).unwrap(),(user,fx));
    assert_eq!(state.request_return_context(event.token+1,user,fx),Err(ThreadUpcallError::InvalidToken));
    let mut changed_context=user;changed_context.rax=0x1234;
    let mut independent=ThreadUpcallState::new();
    assert_eq!(independent.entry,0);
    independent.request_context_restore(changed_context,fx).unwrap();
    assert_eq!(independent.take_restored_context(),Some(changed_context));
    assert!(independent.take_restored_context().is_none());
    state.request_return_context(event.token,changed_context,fx).unwrap();
    assert_eq!(state.take_restored_context(),Some(changed_context));
    assert_eq!(state.request_return_context(event.token,user,fx),Err(ThreadUpcallError::InvalidToken));
    state.install(0x1000,0x8000,false).unwrap();
    assert!(state.begin_exception(user,14).is_none());
    // A self-selected continuation needs no fabricated delivery token. It
    // still validates MXCSR against this CPU, not the user's spoofed mask.
    assert_eq!(state.request_context_restore(user,invalid_fx),Err(ThreadUpcallError::InvalidContext));
    assert!(state.saved_context.is_none() && !state.restore_pending);
    state.enqueue(0x55).unwrap();
    let selected=0x5f80u32;
    let mut selected_fx=fx;
    selected_fx[24..28].copy_from_slice(&selected.to_le_bytes());
    state.request_context_restore(changed_context,selected_fx).unwrap();
    assert_eq!(state.request_context_restore(user,fx),Err(ThreadUpcallError::Active));
    assert_eq!(state.install(0x2000,0x9000,false),Err(ThreadUpcallError::Active));
    assert!(state.begin(user).is_none());
    assert_eq!(state.pending_len,1);
    assert_eq!(state.take_restored_context(),Some(changed_context));
    let mut restored_mxcsr=0u32;
    unsafe {core::arch::asm!("stmxcsr [{}]",in(reg)&mut restored_mxcsr,options(nostack));}
    assert_eq!(restored_mxcsr,selected);
    assert!(state.take_restored_context().is_none());
    let queued=state.begin(user).unwrap();
    assert_eq!(queued.payload,0x55);
    state.request_return(queued.token).unwrap();
    assert_eq!(state.take_restored_context(),Some(user));
    original.restore_current();
}
} } fn main() { task::thread::probe(); }
"#,
    );
    let directory = std::env::temp_dir().join(format!(
        "mochios-upcall-fx-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&directory).unwrap();
    let binary = directory.join("probe");
    let run = |source: &str| {
        let mut compiler = Command::new("rustc")
            .args(["--edition=2024", "-Awarnings", "-", "-o"])
            .arg(&binary)
            .stdin(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        compiler
            .stdin
            .take()
            .unwrap()
            .write_all(source.as_bytes())
            .unwrap();
        let compiled = compiler.wait_with_output().unwrap();
        assert!(
            compiled.status.success(),
            "{}",
            String::from_utf8_lossy(&compiled.stderr)
        );
        Command::new(&binary).output().unwrap()
    };
    let result = run(&program);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let without_restore = program.replace("self.saved_fx_state.restore_current();", "");
    assert_ne!(without_restore, program);
    let negative = run(&without_restore);
    std::fs::remove_dir_all(&directory).unwrap();
    assert!(
        !negative.status.success(),
        "missing FX restoration was not detected"
    );
}

#[test]
fn fx_state_layout_and_native_probe_numbers_match_current_abi() {
    let context = include_str!("../../../core/src/task/context.rs");
    assert!(context.contains("#[repr(C, align(16))]"));
    assert!(context.contains("FXSAVE_AREA_SIZE: usize = 512"));
    assert!(context.contains("offset_of!(Context, fx_state) == 0x60"));
    assert!(context.contains("size_of::<Context>() == 0x260"));
    let probe = include_str!("native_upcall_fx_state.c");
    use mnu_abi::SyscallNumber;
    for (name, number) in [
        ("INSTALL", SyscallNumber::ThreadUpcallInstall),
        ("RETURN", SyscallNumber::ThreadUpcallReturn),
        ("THREAD_HANDLE", SyscallNumber::ThreadHandleCreate),
        ("INTERRUPT", SyscallNumber::ThreadInterrupt),
        ("CLOSE", SyscallNumber::HandleClose),
    ] {
        assert!(probe.contains(&format!("{name} = {}", number as u64)));
    }
}
