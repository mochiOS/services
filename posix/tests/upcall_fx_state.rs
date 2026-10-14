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
    program.push_str("\n} pub mod thread {\n");
    program.push_str(&thread[first..last]);
    program.push_str(
        r#"
pub fn probe() {
    let mut original = super::context::FxSaveArea::initial();
    original.save_current();
    let mut state = ThreadUpcallState::new();
    let user = UserUpcallContext {
        user_rsp:99,r15:15,r14:14,r13:13,r12:12,rbx:3,rbp:4,user_rflags:0x202,
        user_rip:77,r9:9,r8:8,r10:10,rdx:2,rsi:5,rdi:6,rax:1
    };
    let pattern = [0xa7u8;16]; let changed = [0x5bu8;16];
    let initial=0x3f80u32; let clobbered=0x5f80u32;
    state.install(0x1000,0x8000).unwrap();
    for _ in 0..3 {
        assert!(state.begin(user).is_none());
        state.enqueue(7).unwrap();
        unsafe { core::arch::asm!("movdqu xmm15, [{}]", "ldmxcsr [{}]",
            in(reg) pattern.as_ptr(),in(reg) &initial,out("xmm15") _,options(nostack)); }
        let delivery=state.begin(user).unwrap();
        unsafe { core::arch::asm!("movdqu xmm15, [{}]", "ldmxcsr [{}]",
            in(reg) changed.as_ptr(),in(reg) &clobbered,out("xmm15") _,options(nostack)); }
        assert!(state.begin(user).is_none());
        assert_eq!(state.request_return(delivery.token+1),Err(ThreadUpcallError::InvalidToken));
        assert!(state.take_restored_context().is_none());
        let mut value=0u32;
        unsafe { core::arch::asm!("stmxcsr [{}]",in(reg) &mut value,options(nostack)); }
        assert_eq!(value,clobbered);
        state.request_return(delivery.token).unwrap();
        assert_eq!(state.take_restored_context(),Some(user));
        let mut bytes=[0u8;16];
        unsafe { core::arch::asm!("movdqu [{}], xmm15", "stmxcsr [{}]",
            in(reg) bytes.as_mut_ptr(),in(reg) &mut value,options(nostack)); }
        assert_eq!(bytes,pattern); assert_eq!(value,initial);
        assert_eq!(state.request_return(delivery.token),Err(ThreadUpcallError::InvalidToken));
    }
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
