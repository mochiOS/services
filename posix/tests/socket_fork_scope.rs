//! Execute the production stream adapter, deadline and resource scopes with
//! controlled native I/O. This does not replace the native fork/COW probe.
#[allow(dead_code)]
#[path = "support/native_error_probe.rs"]
mod probe;

#[test]
fn stream_waits_allow_fork_but_datagram_jobs_and_signal_dispatch_do_not() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let runtime = include_str!("../../../user/crates/newlib-runtime/src/lib.rs");
    let socket = include_str!("../../../user/crates/newlib-runtime/src/socket.rs");
    let client = include_str!("../../../user/crates/posix-client/src/socket.rs");
    let mut program = format!(
        r#"
#![allow(dead_code)]
extern crate self as mochios_posix_client;
use std::ffi::{{c_int,c_void}};
use std::sync::atomic::{{AtomicU32, AtomicU64, Ordering}};
#[path = "{root}/user/crates/posix-client/src/upcall_guard.rs"] pub mod upcall_guard;
#[path = "{root}/user/crates/newlib-runtime/src/callback_resources.rs"] mod callback_resources;
#[path = "{root}/user/crates/newlib-runtime/src/io_resources.rs"] mod io_resources;
const EAGAIN:c_int=11; const EINVAL:c_int=22; const EFAULT:c_int=14;
const EIO:c_int=5; const EPIPE:c_int=32; const EINTR:c_int=4;
pub mod newlib_errno{{pub const EOPNOTSUPP:i32=95;pub fn from_status(value:i64)->i32{{-value as i32}}}}
mod posix_protocol{{pub const SIGNAL_PIPE:u32=13;}}
mod wire{{pub const CONTROL_GET_RECEIVE_TIMEOUT:u64=1;pub const CONTROL_GET_SEND_TIMEOUT:u64=2;}}
#[derive(Clone,Copy,PartialEq,Debug)] enum FdKind{{ObjectSocket,ObjectDatagram,ObjectStreamRead,ObjectStreamWrite}}
impl FdKind{{fn is_socket(self)->bool{{true}}}}
#[derive(Clone,Copy)] struct Object{{kind:FdKind,lower_handle:u64}}
#[derive(Clone,Copy)] struct FdEntry{{handle:Object}}
struct Lease(FdEntry);
impl std::ops::Deref for Lease{{type Target=FdEntry;fn deref(&self)->&FdEntry{{&self.0}}}}
impl Drop for Lease{{fn drop(&mut self){{assert_ne!(CONTROL.native.load(Ordering::Acquire),0);assert_eq!(PINS.fetch_sub(1,Ordering::AcqRel),1);}}}}
struct ThreadControl{{native:AtomicU32,active_signal_scope_id:AtomicU64,callback_resources:callback_resources::Chain,nonrestart_signal_generation:AtomicU64}}
static CONTROL:ThreadControl=ThreadControl{{native:AtomicU32::new(0),active_signal_scope_id:AtomicU64::new(0),callback_resources:callback_resources::Chain::new(),nonrestart_signal_generation:AtomicU64::new(0)}};
static KIND:AtomicU32=AtomicU32::new(0);
static PINS:AtomicU32=AtomicU32::new(0);
static CALLS:AtomicU32=AtomicU32::new(0);
static WAITS:AtomicU32=AtomicU32::new(0);
static SIGNALS:AtomicU32=AtomicU32::new(0);
static BROKEN:AtomicU32=AtomicU32::new(0);
fn register_current_thread()->Option<(u32,&'static ThreadControl)>{{Some((1,&CONTROL))}}
fn defer_native_delivery()->Option<upcall_guard::Guard<'static>>{{upcall_guard::Guard::enter(&CONTROL.native)}}
fn with_fd_entry(fd:i32)->Result<Lease,i32>{{
    assert!(CONTROL.callback_resources.capture_for_fork().is_none());
    assert_eq!(fd,3);PINS.fetch_add(1,Ordering::AcqRel);
    Ok(Lease(FdEntry{{handle:Object{{kind:if KIND.load(Ordering::Acquire)==0{{FdKind::ObjectSocket}}else{{FdKind::ObjectDatagram}},lower_handle:17}}}}))
}}
fn monotonic_nanoseconds()->Result<u64,i32>{{Ok(100)}}
fn io_cancellation_requested(_: &ThreadControl)->bool{{false}}
fn handle_is_nonblocking(_:FdEntry)->Result<bool,i32>{{Ok(false)}}
fn assert_admission(allowed:bool){{
    let capture=CONTROL.callback_resources.capture_for_fork();assert_eq!(capture.is_some(),allowed);drop(capture);
}}
fn generate_thread_signal(signal:u32)->Result<(),i32>{{
    assert_admission(false);assert_eq!(signal,13);SIGNALS.fetch_add(1,Ordering::AcqRel);Ok(())
}}
fn wait_for_handle_capacity(entry:FdEntry,_:u64,_:&ThreadControl,_:u64,_:u32,deadline:u64)->Result<u64,i32>{{
    assert_eq!(entry.handle.lower_handle,17);assert_eq!(deadline,1100);assert_admission(true);
    WAITS.fetch_add(1,Ordering::AcqRel);Ok(1)
}}
fn syscall_errno(result:Result<u64,i32>)->Result<u64,i32>{{result}}
mod syscall{{
    pub const HANDLE_SIGNAL_READABLE:u64=1;pub const HANDLE_SIGNAL_WRITABLE:u64=2;
    pub const HANDLE_WAIT_INFINITE:u64=u64::MAX;
    #[derive(Clone,Copy)]pub enum SyscallNumber{{HandleWrite,HandleRead,HandleReadAt}}
    pub fn raw_syscall3(_:SyscallNumber,handle:u64,_:u64,length:u64)->Result<u64,i32>{{
        super::assert_admission(true);assert_eq!((handle,length),(17,1));
        if super::BROKEN.load(super::Ordering::Acquire)!=0{{return Err(super::EPIPE)}}
        if super::CALLS.fetch_add(1,super::Ordering::AcqRel)==0{{Err(super::EAGAIN)}}else{{Ok(1)}}
    }}
    pub fn raw_syscall4(op:SyscallNumber,h:u64,b:u64,n:u64,_:u64)->Result<u64,i32>{{raw_syscall3(op,h,b,n)}}
}}
mod socket_record{{
    use super::*;pub struct Record{{pub count:isize}}
    pub fn io(_:FdEntry,_:u64,_:usize,_:i32,_:bool)->Result<Record,i32>{{assert_admission(false);Ok(Record{{count:1}})}}
}}
mod socket{{
    use super::*;
    pub const MSG_DONTWAIT:i32=0x40;pub const MSG_PEEK:i32=2;
    pub const MSG_WAITALL:i32=0x100;pub const MSG_NOSIGNAL:i32=0x4000;
"#,
        root = root.display(),
    );
    program.push_str(probe::between(
        client,
        "pub fn socket_deadline(",
        "/// Query options",
    ));
    program.push_str(probe::between(
        client,
        "#[derive(Clone, Copy, Debug, PartialEq, Eq)]\npub struct MessageOptions",
        "/// C socket tags",
    ));
    program.push_str(probe::between(
        socket,
        "pub(super) struct SocketWait",
        "#[unsafe(no_mangle)]",
    ));
    program.push_str(
        r#"
fn control(entry:FdEntry,tag:u64,_:&[u8],output:&mut[u8])->Result<(),i32>{
    assert_eq!(entry.handle.lower_handle,17);assert!(tag==1||tag==2);assert_admission(true);
    output.copy_from_slice(&1000u64.to_le_bytes());Ok(())
}
}
use socket::SocketWait;
"#,
    );
    program.push_str(probe::between(
        runtime,
        "fn stream_io_since_wait<T>(",
        "fn io_cancellation_requested(",
    ));
    program.push_str("mod implementation {use super::*;\n");
    program.push_str(probe::between(
        socket,
        "fn message_io(",
        "#[unsafe(no_mangle)]",
    ));
    for signature in ["pub extern \"C\" fn _read(", "pub extern \"C\" fn _write("] {
        program.push_str(probe::between(runtime, signature, "#[unsafe(no_mangle)]"));
    }
    program.push_str(
        r#"
fn syscall_read(entry:FdEntry,buffer:*mut c_void,length:usize)->Result<isize,i32>{message_entry(entry,buffer as u64,length,0,false)}
fn syscall_write(entry:FdEntry,buffer:*const c_void,length:usize)->Result<isize,i32>{message_entry(entry,buffer as u64,length,0,true)}
fn set_errno(_:i32){}
fn record_stdio_io(_: &Result<isize,i32>){}
fn result_with_errno(result:Result<isize,i32>,failed:isize)->isize{result.unwrap_or(failed)}
pub fn run(){
    for scalar in [false,true]{for datagram in [false,true]{for sending in [false,true]{for broken in [false,true]{
        KIND.store(u32::from(datagram),Ordering::Release);BROKEN.store(u32::from(broken),Ordering::Release);
        CALLS.store(0,Ordering::Release);WAITS.store(0,Ordering::Release);SIGNALS.store(0,Ordering::Release);
        let expected=if broken&&!datagram{Err(EPIPE)}else{Ok(1)};
        if scalar{
            let value=if sending{_write(3,0x1234 as *const _,1)}else{_read(3,0x1234 as *mut _,1)};
            assert_eq!(value,expected.unwrap_or(-1));
        }else{assert_eq!(message_io(3,0x1234,1,0,sending),expected);}
        assert_eq!(PINS.load(Ordering::Acquire),0);assert_eq!(CONTROL.native.load(Ordering::Acquire),0);
        assert!(CONTROL.callback_resources.reset_empty());
        assert_eq!(WAITS.load(Ordering::Acquire),u32::from(!broken&&!datagram));
        assert_eq!(SIGNALS.load(Ordering::Acquire),u32::from(broken&&sending&&!datagram));
    }}}}
    KIND.store(0,Ordering::Release);BROKEN.store(1,Ordering::Release);SIGNALS.store(0,Ordering::Release);
    assert_eq!(message_io(3,0x1234,1,socket::MSG_NOSIGNAL,true),Err(EPIPE));
    assert_eq!(SIGNALS.load(Ordering::Acquire),0);assert!(CONTROL.callback_resources.reset_empty());
}
}
fn main(){implementation::run();}
"#,
    );
    probe::run(&program);
}
