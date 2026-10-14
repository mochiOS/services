use std::io::Write;
use std::process::{Command, Stdio};

#[test]
fn actual_registration_defers_callbacks_until_stack_metadata_is_published() {
    let runtime = include_str!("../../../user/crates/newlib-runtime/src/lib.rs");
    let start = runtime.find("fn setup_signal_delivery(").unwrap();
    let end = start + runtime[start..].find("\n}\n").unwrap() + 3;
    let guard = include_str!("../../../user/crates/posix-client/src/upcall_guard.rs");
    let mut program = String::from(
        r#"
extern crate self as mochios_posix_client;
use core::sync::atomic::{AtomicU32,AtomicUsize,Ordering};
#[allow(non_camel_case_types)]type c_int=i32;
const EOVERFLOW:i32=75;const SIGNAL_UPCALL_STACK_SIZE:usize=65536;const NATIVE_READ_WRITE:u64=3;
static FAILURE:AtomicU32=AtomicU32::new(0);
static STAGE:AtomicU32=AtomicU32::new(0);
static DEPTH:AtomicU32=AtomicU32::new(0);
static INSTALLED:AtomicU32=AtomicU32::new(0);
struct ThreadControl{native_handle:AtomicU32,native_delivery_defer:AtomicU32,signal_mask:AtomicU32,
    signal_upcall_stack:AtomicUsize,signal_upcall_stack_size:AtomicUsize}
static CONTROL:ThreadControl=ThreadControl{native_handle:AtomicU32::new(61),native_delivery_defer:AtomicU32::new(0),
    signal_mask:AtomicU32::new(37),signal_upcall_stack:AtomicUsize::new(0x20000),signal_upcall_stack_size:AtomicUsize::new(8192)};
fn stage()->Result<(),i32>{
    assert_eq!(CONTROL.native_delivery_defer.load(Ordering::Acquire),DEPTH.load(Ordering::Acquire)+1);
    let stage=STAGE.fetch_add(1,Ordering::AcqRel)+1;
    // At install/registration returns a pending native callback could run.
    // It must never observe the old fork-copied stack as the current stack.
    if INSTALLED.load(Ordering::Acquire)!=0{
        assert_ne!(CONTROL.native_delivery_defer.load(Ordering::Acquire),0);
    }
    if FAILURE.load(Ordering::Acquire)==stage{Err(5)}else{Ok(())}
}
fn has_posix_environment()->Result<bool,i32>{Ok(true)}
mod posix_protocol{pub const SIGNAL_MASK_INITIALIZE:u32=3;}
fn service_signal_mask(_:&ThreadControl,operation:u32,mask:u32)->Result<(),i32>{
    assert_eq!(operation,3);assert_eq!(mask,37);stage()
}
fn posix_signal_upcall(){}
fn syscall_errno(result:Result<u64,i32>)->Result<u64,i32>{result}
struct ObjectHandleAttachment{handle:u32,rights:u64}
struct Client;
fn posix_client()->Result<Client,i32>{stage()?;Ok(Client)}
fn map_posix_client_error(error:i32)->i32{error}
impl Client{fn register_signal_thread(&self,attachment:ObjectHandleAttachment)->Result<(),i32>{
    assert_eq!(attachment.handle,73);assert_eq!(attachment.rights,12);
    assert_eq!(CONTROL.native_handle.load(Ordering::Acquire),73);
    stage()
}}
mod syscall {
    use super::*;
    pub enum SyscallNumber{ThreadHandleCreate,MemoryMap,MemoryUnmap,ThreadUpcallInstall,HandleClose}
    pub const THREAD_UPCALL_EXCEPTIONS:u64=1;pub const HANDLE_RIGHT_WAIT:u64=4;pub const HANDLE_RIGHT_SIGNAL:u64=8;
    pub struct ThreadUpcallConfig{pub entry:u64,pub stack_base:u64,pub stack_size:u64,pub flags:u64,pub defer_word:u64,pub reserved:[u64;3]}
    pub fn raw_syscall0(_:SyscallNumber)->Result<u64,i32>{stage()?;Ok(73)}
    pub fn raw_syscall1(_:SyscallNumber,handle:u64)->Result<u64,i32>{assert!(matches!(handle,61|73));Ok(0)}
    pub fn raw_syscall2(op:SyscallNumber,a:u64,b:u64)->Result<u64,i32>{
        match op {
            SyscallNumber::ThreadUpcallInstall=>{
                let config=unsafe{&*(a as *const ThreadUpcallConfig)};
                assert_eq!(b,core::mem::size_of::<ThreadUpcallConfig>() as u64);
                assert_ne!(config.entry,0);assert_eq!(config.stack_base,0x10000);
                assert_eq!(config.stack_size,65536);assert_eq!(config.flags,1);assert_eq!(config.reserved,[0;3]);
                assert_eq!(config.defer_word,CONTROL.native_delivery_defer.as_ptr() as u64);
                stage()?;INSTALLED.store(1,Ordering::Release);Ok(0)
            }
            SyscallNumber::MemoryUnmap=>{assert_eq!(a,0x10000);assert_eq!(b,65536);Ok(0)}
            _=>panic!("unexpected syscall"),
        }
    }
    pub fn raw_syscall6(_:SyscallNumber,a:u64,b:u64,c:u64,d:u64,e:u64,f:u64)->Result<u64,i32>{
        assert_eq!((a,b,c,d,e,f),(0,65536,3,0,0,0));stage()?;Ok(0x10000)
    }
}
pub mod upcall_guard {
"#,
    );
    program.push_str(guard);
    program.push_str("\n}\n");
    program.push_str(&runtime[start..end]);
    program.push_str(
        r#"
fn main(){
    for depth in [0,2] {
        for failure in 0..=6 {
            FAILURE.store(failure,Ordering::Release);STAGE.store(0,Ordering::Release);
            INSTALLED.store(0,Ordering::Release);DEPTH.store(depth,Ordering::Release);
            CONTROL.native_delivery_defer.store(depth,Ordering::Release);
            CONTROL.native_handle.store(61,Ordering::Release);
            CONTROL.signal_upcall_stack.store(0x20000,Ordering::Release);
            CONTROL.signal_upcall_stack_size.store(8192,Ordering::Release);
            let result=setup_signal_delivery(&CONTROL);
            assert_eq!(result,if failure==0{Ok(())}else{Err(5)},"failure stage {failure}");
            assert_eq!(CONTROL.native_delivery_defer.load(Ordering::Acquire),depth);
            if failure==0{
                assert_eq!(STAGE.load(Ordering::Acquire),6);
                assert_eq!(CONTROL.signal_upcall_stack.load(Ordering::Acquire),0x10000);
                assert_eq!(CONTROL.signal_upcall_stack_size.load(Ordering::Acquire),65536);
            }else{
                assert_eq!(CONTROL.signal_upcall_stack.load(Ordering::Acquire),0x20000);
                assert_eq!(CONTROL.signal_upcall_stack_size.load(Ordering::Acquire),8192);
            }
        }
    }
    STAGE.store(0,Ordering::Release);
    CONTROL.native_delivery_defer.store(u32::MAX,Ordering::Release);
    assert_eq!(setup_signal_delivery(&CONTROL),Err(EOVERFLOW));
    assert_eq!(STAGE.load(Ordering::Acquire),0);
    assert_eq!(CONTROL.native_delivery_defer.load(Ordering::Acquire),u32::MAX);
}
"#,
    );
    let directory = std::env::temp_dir().join(format!(
        "mochios-signal-registration-{}",
        std::process::id()
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
        let output = compiler.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        Command::new(&binary).output().unwrap()
    };
    let output = run(&program);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let begin = program.find("    let _preparation =").unwrap();
    let end =
        begin + program[begin..].find(".ok_or(EOVERFLOW)?;").unwrap() + ".ok_or(EOVERFLOW)?;".len();
    let broken = format!("{}{}", &program[..begin], &program[end..]);
    assert!(
        !run(&broken).status.success(),
        "unguarded registration was not detected"
    );
    std::fs::remove_dir_all(directory).unwrap();
}
