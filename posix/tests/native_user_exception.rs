use std::io::Write;
use std::process::{Command, Stdio};

#[test]
fn actual_exception_delivery_preserves_snapshot_and_rejects_kernel_or_invalid_contexts() {
    let thread = include_str!("../../../core/src/task/thread.rs");
    let begin = thread.find("pub struct UserUpcallContext {").unwrap();
    let end = begin + thread[begin..].find("\n}\n").unwrap() + 3;
    let source = include_str!("../../../core/src/syscall/upcall.rs");
    let mut program = String::from("#[derive(Clone,Copy,Debug,PartialEq,Eq)]\n");
    program.push_str(&thread[begin..end]);
    program.push_str(r#"
thread_local! {
    static MODE:std::cell::Cell<u8>=const {std::cell::Cell::new(0)};
    static SAVED:std::cell::Cell<Option<UserUpcallContext>>=const {std::cell::Cell::new(None)};
    static METADATA:std::cell::Cell<Option<(u64,u64)>>=const {std::cell::Cell::new(None)};
}
fn copy_to_user_native(address:u64, bytes:&[u8])->Result<(),()> {
    if MODE.with(|v|v.get())==4 {return Err(());}
    METADATA.with(|v|v.set(Some((address,u64::from_ne_bytes(bytes.try_into().unwrap())))));
    Ok(())
}
mod mnu_abi {
    pub const THREAD_UPCALL_KIND_EXCEPTION:u64=1;
    #[repr(u64)] pub enum MemoryFaultCause { AccessDenied=2 }
}
mod task {
    pub fn current_thread_id()->Option<u64> {if crate::MODE.with(|v|v.get())==3 {None}else{Some(11)}}
    pub struct Thread;
    pub struct Delivery { pub entry:u64,pub stack_top:u64,pub payload:u64,pub token:u64 }
    impl Thread {
        pub fn begin_exception_upcall(&mut self,context:crate::UserUpcallContext,vector:u64)->Option<Delivery> {
            assert_eq!(vector,14);
            if matches!(crate::MODE.with(|v|v.get()),1..=3) {return None;}
            crate::SAVED.with(|v|v.set(Some(context)));
            Some(Delivery{entry:0x1000,stack_top:0x9000,payload:vector,token:77})
        }
    }
    pub fn with_thread_mut<T>(id:u64,body:impl FnOnce(&mut Thread)->T)->Option<T> {
        assert_eq!(id,11);Some(body(&mut Thread))
    }
}
"#);
    program.push_str("mod actual { use super::*;\n");
    for name in [
        "prepare_user_exception",
        "valid_user_return",
        "read_interrupt_context",
        "write_interrupt_context",
    ] {
        let start = source.find(&format!("fn {name}(")).unwrap();
        let end = start + source[start..].find("\n}\n").unwrap() + 3;
        program.push_str(&source[start..end]);
    }
    program.push_str(
        r#"
pub fn verify() {
    let mut raw=core::array::from_fn::<_,21,_>(|i|0x100+i as u64);
    raw[15]=6;raw[16]=0x4000;raw[17]=0x23;raw[18]=0x10702;raw[19]=0x8000;raw[20]=0x1b;
    let original=raw;
    for mode in 1..=3 {
        MODE.with(|v|v.set(mode));
        assert!(!prepare_user_exception(&mut raw,0x5000,mnu_abi::MemoryFaultCause::AccessDenied));assert_eq!(raw,original);
        assert_eq!(METADATA.with(|v|v.get()),None);
    }
    MODE.with(|v|v.set(0));
    for (slot,value) in [(17,8),(16,0),(19,0xffff800000000000)] {
        raw=original;raw[slot]=value;let invalid=raw;
        assert!(!prepare_user_exception(&mut raw,0x5000,mnu_abi::MemoryFaultCause::AccessDenied));assert_eq!(raw,invalid);
    }
    MODE.with(|v|v.set(4));raw=original;
    assert!(!prepare_user_exception(&mut raw,0x5000,mnu_abi::MemoryFaultCause::AccessDenied));
    assert_eq!(raw,original);assert_eq!(METADATA.with(|v|v.get()),None);
    MODE.with(|v|v.set(0));
    raw=original;
    assert!(prepare_user_exception(&mut raw,0x5000,mnu_abi::MemoryFaultCause::AccessDenied));
    assert_eq!(METADATA.with(|v|v.get()),Some((0x9008,2)));
    let saved=SAVED.with(|v|v.get().unwrap());
    assert_eq!((saved.user_rip,saved.user_rsp,saved.user_rflags),(0x4000,0x8000,original[18]));
    assert_eq!((saved.rcx,saved.r11,saved.rax),(original[13],original[4],original[14]));
    let mut expected=original;
    expected[8]=14;expected[9]=77;expected[12]=1;expected[13]=0x5000;
    expected[7]=6;expected[6]=0x4000;expected[16]=0x1000;expected[19]=0x9000;
    expected[18]&=!((1<<10)|(1<<8)|(1<<16));
    assert_eq!(raw,expected);
}
}
fn main() {actual::verify();}
"#,
    );
    let directory = std::env::temp_dir().join(format!(
        "mochios-user-exception-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&directory).unwrap();
    let binary = directory.join("probe");
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
        .write_all(program.as_bytes())
        .unwrap();
    let compiled = compiler.wait_with_output().unwrap();
    assert!(
        compiled.status.success(),
        "{}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    let result = Command::new(binary).output().unwrap();
    std::fs::remove_dir_all(directory).unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
}

#[test]
fn native_exception_entry_is_opt_in_and_runs_after_vm_recovery_without_posix_policy() {
    assert_eq!(mnu_abi::THREAD_UPCALL_EXCEPTIONS, 1);
    assert_eq!(mnu_abi::THREAD_UPCALL_KIND_INTERRUPT, 0);
    assert_eq!(mnu_abi::THREAD_UPCALL_KIND_EXCEPTION, 1);
    assert_eq!(core::mem::size_of::<mnu_abi::ThreadUpcallConfig>(), 64);
    let entry = include_str!("../../../core/src/interrupt/page_fault.rs");
    for register in [
        "rax", "rcx", "rdx", "rbx", "rbp", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12", "r13",
        "r14", "r15",
    ] {
        assert!(entry.contains(&format!("\"push {register}\"")));
        assert!(entry.contains(&format!("\"pop {register}\"")));
    }
    assert!(entry.find("\"add rsp, 8\"").unwrap() < entry.find("\"iretq\"").unwrap());
    assert!(entry.contains("\"and rsp, -16\""));
    assert!(entry.contains("kpti_enter_for_trap(raw[17] & 3 == 3)"));
    let idt = include_str!("../../../core/src/interrupt/idt.rs");
    let body = idt
        .split("pub(super) fn page_fault_handler(")
        .nth(1)
        .unwrap();
    let deliver = body.find("prepare_user_exception(").unwrap();
    assert!(body.find("resolve_user_copy_on_write(").unwrap() < deliver);
    assert!(body.find("handle_user_memory_fault(").unwrap() < deliver);
    assert!(body.find("try_grow_user_stack(").unwrap() < deliver);
    for forbidden in ["SIGSEGV", "SIGBUS", "posix.service"] {
        assert!(!entry.contains(forbidden));
        assert!(!body.contains(forbidden));
    }
    let probe = include_str!("native_user_exception.c");
    for (name, value) in [
        ("MAP", mnu_abi::SyscallNumber::MemoryMap),
        ("UNMAP", mnu_abi::SyscallNumber::MemoryUnmap),
        ("PROTECT", mnu_abi::SyscallNumber::MemoryProtect),
        ("INSTALL", mnu_abi::SyscallNumber::ThreadUpcallInstall),
        ("RETURN", mnu_abi::SyscallNumber::ThreadUpcallReturn),
        ("INSPECT", mnu_abi::SyscallNumber::ThreadUpcallInspect),
        ("RETURN_CONTEXT", mnu_abi::SyscallNumber::ThreadUpcallReturnContext),
    ] {
        assert!(probe.contains(&format!("{name} = {}", value as u64)));
    }
    assert_eq!(core::mem::size_of::<mnu_abi::ThreadUpcallSnapshot>(), 656);
    assert_eq!(
        core::mem::offset_of!(mnu_abi::ThreadUpcallSnapshot, fx_state),
        144
    );
}

#[test]
fn production_fault_causes_preserve_origin_instead_of_guessing_from_errno() {
    let process = include_str!("../../../core/src/syscall/process.rs");
    let abi = include_str!("../../../core/crates/abi/src/lib.rs");
    let mut program = String::from(
        r#"
mod mem { pub mod vm_object {
    #[derive(Clone,Copy,Debug,PartialEq,Eq)]
    pub enum VmPageError { OutsideBacking, Operation(u64) }
} }
mod mnu_abi {
#[repr(u64)] #[derive(Debug,PartialEq,Eq)]
"#,
    );
    let start = abi.find("pub enum MemoryFaultCause {").unwrap();
    let end = start + abi[start..].find("\n}\n").unwrap() + 3;
    program.push_str(&abi[start..end]);
    program.push_str("\npub mod status {\n");
    program.push_str(include_str!("../../../core/crates/abi/src/status.rs"));
    program.push_str("\n}\n");
    program.push_str("}\n#[derive(Debug,PartialEq,Eq)]\n");
    let start = process.find("pub(crate) enum MemoryFault {").unwrap();
    let end = process[start..].find("/// Resolves one page,").unwrap() + start;
    program.push_str(&process[start..end]);
    program.push_str(
        r#"
fn main() {
    use mem::vm_object::VmPageError;
    use mnu_abi::MemoryFaultCause::*;
    assert_eq!(MemoryFault::Unmapped.cause(),Unmapped);
    assert_eq!(MemoryFault::AccessDenied.cause(),AccessDenied);
    assert_eq!(MemoryFault::Backing(VmPageError::OutsideBacking).cause(),OutsideBacking);
    // Legacy numeric errno values must not be interpreted as native fault
    // categories. Only explicit native tags carry resource/retry semantics.
    for error in [(-5i64) as u64,(-22i64) as u64,(-13i64) as u64,(-12i64) as u64,(-11i64) as u64] {
        assert_eq!(MemoryFault::Backing(VmPageError::Operation(error)).cause(),BackingFailure);
        assert_eq!(MemoryFault::Operation(error).cause(),Unresolved);
        assert!(!MemoryFault::Operation(error).is_retryable());
    }
    for (error,cause) in [(mnu_abi::status::Error::ResourceUnavailable,ResourceUnavailable),
        (mnu_abi::status::Error::BackingFailure,BackingFailure),
        (mnu_abi::status::Error::AccessDenied,AccessDenied)] {
        assert_eq!(MemoryFault::Operation(error.into_raw()).cause(),cause);
        assert_eq!(MemoryFault::Backing(VmPageError::Operation(error.into_raw())).cause(),cause);
    }
}
"#,
    );
    let directory = std::env::temp_dir().join(format!(
        "mochios-native-fault-cause-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&directory).unwrap();
    let binary = directory.join("probe");
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
        .write_all(program.as_bytes())
        .unwrap();
    let compiled = compiler.wait_with_output().unwrap();
    if !compiled.status.success() {
        std::fs::remove_dir_all(&directory).unwrap();
        panic!("{}", String::from_utf8_lossy(&compiled.stderr));
    }
    let result = Command::new(binary).output().unwrap();
    std::fs::remove_dir_all(directory).unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
}
