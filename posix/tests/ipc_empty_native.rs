#[allow(dead_code)]
#[path = "support/native_error_probe.rs"]
mod probe;

#[test]
fn asynchronous_receive_guards_distinguish_empty_from_failures() {
    let mut program = probe::program();
    let sources = [
        include_str!("../../service-manager/src/bootstrap.rs"),
        include_str!("../../service-manager/src/readiness.rs"),
        include_str!("../../service-manager/src/driver_controller.rs"),
        include_str!("../../mboot-agent/src/runtime.rs"),
        include_str!("../../drivers/src/control_worker.rs"),
        include_str!("../../linux/src/runtime.rs"),
        include_str!("../../network/src/service.rs"),
        include_str!("../../../drivers/virtio-net-driver/src/service.rs"),
    ];
    for (index, source) in sources.iter().enumerate() {
        let native = source
            .find(".native_error()")
            .expect("native receive guard");
        let start = source[..native].rfind("if ").unwrap() + 3;
        let end = native + source[native..].find("=>").unwrap();
        let condition = source[start..end].trim();
        assert!(condition.contains("NativeError::NotReady"));
        program.push_str(&format!(
            "fn guard_{index}(error:SysError)->bool{{let err=error;{condition}}}\n"
        ));
    }
    program.push_str("fn main(){\n");
    for index in 0..sources.len() {
        program.push_str(&format!(r#"
assert!(guard_{index}(SysError::from(NativeError::NotReady.into_raw())));
for status in [EAGAIN,EACCES,NativeError::ResourceUnavailable.into_raw(),NativeError::NotFound.into_raw(),NativeError::InvalidAddress.into_raw()]{{assert!(!guard_{index}(SysError::from(status)));}}
"#));
    }
    program.push_str("}\n");
    probe::run(&program);
    let kernel = include_str!("../../../core/src/syscall/ipc.rs");
    assert!(!kernel.contains("EAGAIN"));
    for retired in [
        "recv_from_sender_for_kernel_nonblocking",
        "recv_blocking_from_sender_for_kernel",
        "pop_from_sender_copy",
    ] {
        assert!(!kernel.contains(retired));
    }
}

#[test]
fn viewkit_and_shell_recognize_only_native_empty_and_preserve_other_errors() {
    let connection = include_str!("../../../libraries/viewkit/src/platform/mochios/connection.rs");
    let backend = include_str!("../../../libraries/viewkit/src/platform/mochios/mod.rs");
    let mut program = probe::program();
    program.push_str(r#"
use std::{cell::Cell,io};
const EVENT_BUFFER_SIZE:usize=32;
thread_local!{static RESULT:Cell<i64>=const{Cell::new(16)};}
mod mochi_user_platform{pub mod ipc{#[derive(Clone,Copy,Default)]pub struct IpcObjectHandles{pub count:u32}}}
mod syscall{
    pub use crate::mochi_user_syscall::*;
    pub enum SyscallNumber{IpcRecvObjectHandles,IpcWait}
    pub fn call4(_:SyscallNumber,pointer:u64,length:u64,_:u64,endpoint:u64)->SysResult<u64>{
        assert_eq!(length,32);assert!(endpoint==0||endpoint==5001);
        let result=crate::RESULT.get();if result<0{return Err(SysError::from_raw(result));}
        unsafe{std::ptr::write_bytes(pointer as*mut u8,0x5a,result as usize);}Ok((41<<32)|result as u64)
    }
    pub fn call3(_:SyscallNumber,_:u64,_:u64,_:u64)->SysResult<u64>{
        let result=crate::RESULT.get();if result<0{Err(SysError::from_raw(result))}else{Ok((41<<32)|result as u64)}
    }
}
static mut EVENT_BUF:[u8;EVENT_BUFFER_SIZE]=[0;EVENT_BUFFER_SIZE];
static mut EVENT_OBJECT_HANDLES:mochi_user_platform::ipc::IpcObjectHandles=mochi_user_platform::ipc::IpcObjectHandles{count:0};
#[derive(Debug)]struct ReceivedHandles;
impl ReceivedHandles{fn from_raw(raw:mochi_user_platform::ipc::IpcObjectHandles)->Result<Self,MochiOsBackendError>{assert_eq!(raw.count,0);Ok(Self)}}
#[derive(Debug,PartialEq)]
"#);
    let errors = probe::between(
        backend,
        "pub enum MochiOsBackendError {",
        "impl MochiOsBackendError {",
    );
    program.push_str(
        &errors
            .lines()
            .filter(|line| !line.trim_start().starts_with("#[error("))
            .collect::<Vec<_>>()
            .join("\n"),
    );
    program.push_str(probe::between(
        connection,
        "pub(super) fn syscall_result",
        "pub(super) fn perf_log",
    ));
    program.push_str(probe::between(
        connection,
        "pub(super) fn ipc_wait_object_handles_raw(",
        "pub(super) unsafe fn zero_raw(",
    ));
    program.push_str(&connection[connection.find("pub(super) fn try_recv_event()").unwrap()..]);
    // These pub(super) functions normally live in the backend submodule.
    program = program.replace("pub(super)", "pub(crate)");
    program.push_str(
        r#"
fn sys_error_to_io(error:SysError)->io::Error{io::Error::other(format!("{}",error.raw()))}
mod shell{use crate::{syscall,sys_error_to_io,io};
"#,
    );
    let shell = include_str!("../../../binaries/msh/src/main.rs");
    program.push_str(probe::between(
        shell,
        "fn ipc_try_wait(",
        "fn wait_foreground_child(",
    ));
    program.push_str(r#"
pub fn run()->io::Result<Option<u64>>{ipc_try_wait(&mut[0;32])}
}
fn main(){
    for error in [NativeError::LimitExceeded,NativeError::InvalidAddress,NativeError::ResourceUnavailable,NativeError::BackingFailure,NativeError::InvalidArgument,NativeError::AccessDenied,NativeError::NotReady,NativeError::AlreadyExists,NativeError::NotFound,NativeError::PeerClosed]{
        RESULT.set(error.into_raw()as i64);
        assert_eq!(syscall_result::<u64>(Err(SysError::from(error.into_raw()))),Err(MochiOsBackendError::Native(error)));
        if error==NativeError::NotReady{assert!(try_recv_event().unwrap().is_none());assert!(shell::run().unwrap().is_none());}
        else{assert_eq!(try_recv_event().unwrap_err(),MochiOsBackendError::Native(error));assert!(shell::run().is_err());}
        // Blocking receive must not hide a broken execution context as empty.
        assert_eq!(read_event_blocking(5001).unwrap_err(),MochiOsBackendError::Native(error));
    }
    RESULT.set(EAGAIN as i64);assert_eq!(try_recv_event().unwrap_err(),MochiOsBackendError::Syscall(11));assert!(shell::run().is_err());
    RESULT.set(16);let(len,bytes,_)=try_recv_event().unwrap().unwrap();assert_eq!(len,16);assert_eq!(&bytes[..16],&[0x5a;16]);
    assert!(read_event_blocking(5001).unwrap().is_some());assert_eq!(shell::run().unwrap(),Some((41<<32)|16));
}
"#);
    probe::run(&program);
}

#[test]
fn native_rpc_failures_never_fall_back_to_an_unrelated_queue_receive() {
    let mut program = probe::program();
    program.push_str(r#"
use std::{cell::Cell,io};
thread_local!{static RESULT:Cell<i64>=const{Cell::new(123)};static CALLS:Cell<usize>=const{Cell::new(0)};}
mod platform{pub mod ipc{
    pub fn call(endpoint:u64,request:&[u8],reply:&mut[u8])->crate::SysResult<u64>{
        assert_eq!(endpoint,17);assert_eq!(request,b"req");assert_eq!(reply.len(),8);crate::CALLS.set(crate::CALLS.get()+1);
        let result=crate::RESULT.get();if result<0{Err(crate::SysError::from_raw(result))}else{Ok(result as u64)}
    }
}}
fn syscall_error(error:SysError)->io::Error{io::Error::other(format!("{}",error.raw()))}
mod manager{use crate::{platform,mochi_user_syscall};
"#);
    let source = include_str!("../../service-manager/src/spawn_support.rs");
    let source = &source[source.find("pub(crate) fn call_with_wait(").unwrap()..];
    program.push_str(&source[..source.find("\n}\n").unwrap() + 3]);
    program.push_str("}\nmod drivers{use crate::{platform,mochi_user_syscall};\n");
    program.push_str(probe::between(
        include_str!("../../drivers/src/spawn_support.rs"),
        "fn call_capability_service(",
        "pub(crate) fn resolve_capabilities(",
    ));
    program.push_str("pub fn run()->crate::SysResult<u64>{call_capability_service(17,b\"req\",&mut[0;8])}\n}\nmod gcc{use crate::{platform,syscall_error,io};\n");
    let gcc = include_str!("../../../binaries/coreutils/src/bin/gcc.rs");
    let gcc = &gcc[gcc.find("fn call_with_wait(").unwrap()..];
    program.push_str(&gcc[..gcc.find("\n}\n").unwrap() + 3]);
    program.push_str(r#"
pub fn run()->io::Result<u64>{call_with_wait(17,b"req",&mut[0;8])}
}
fn main(){
    for status in [EAGAIN,NativeError::NotReady.into_raw(),NativeError::NotFound.into_raw(),NativeError::AccessDenied.into_raw(),NativeError::ResourceUnavailable.into_raw()]{
        RESULT.set(status as i64);CALLS.set(0);
        assert_eq!(manager::call_with_wait(17,b"req",&mut[0;8]),Err(SysError::from(status)));
        assert_eq!(drivers::run(),Err(SysError::from(status)));assert!(gcc::run().is_err());assert_eq!(CALLS.get(),3);
    }
    RESULT.set(123);assert_eq!(manager::call_with_wait(17,b"req",&mut[0;8]),Ok(123));assert_eq!(drivers::run(),Ok(123));assert_eq!(gcc::run().unwrap(),123);
}
"#);
    let package = include_str!("../../package/src/main.rs");
    assert!(
        package.contains(
            "let message = platform::ipc::call(service, &encoded[..length], &mut reply)?;"
        )
    );
    assert!(!package.contains("platform::ipc::try_wait("));
    probe::run(&program);
}
