//! Run the production poll/select loops with real fault-safe memory copies
//! and resource owners; only FD lookup/readiness/native waiting are controlled.
#[allow(dead_code)]
#[path = "support/native_error_probe.rs"]
mod probe;

#[test]
fn multiplex_fixes_fd_ownership_before_fork_admission_and_preserves_error_cleanup() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let runtime = include_str!("../../../user/crates/newlib-runtime/src/lib.rs");
    let mut program = format!(
        r#"
#![allow(dead_code)]
extern crate self as mochios_posix_client;
extern crate self as mnu_abi;
use std::ffi::{{c_char,c_int}};
use std::sync::atomic::{{AtomicU32,AtomicU64,AtomicUsize,Ordering}};
#[derive(Debug,PartialEq)]pub enum SyscallNumber{{MemoryCopy}}
pub mod memory_copy{{pub const MAX_BYTES:usize=4096;}}
#[path="{root}/services/posix/tests/support/user_copy_native.rs"]mod user_copy_native;
use user_copy_native::syscall_errno;
#[path="{root}/user/crates/newlib-runtime/src/user_copy.rs"]mod user_copy;
#[path="{root}/user/crates/newlib-runtime/src/multiplex_memory.rs"]mod multiplex_memory;
#[path="{root}/user/crates/newlib-runtime/src/callback_resources.rs"]mod callback_resources;
#[path="{root}/user/crates/newlib-runtime/src/io_resources.rs"]mod io_resources;
#[path="{root}/user/crates/posix-client/src/upcall_guard.rs"]pub mod upcall_guard;
#[path="{root}/user/crates/posix-client/src/multiplex.rs"]pub mod multiplex;
pub mod fd{{pub fn access_allows_read(flags:u32)->bool{{flags&3!=1}}pub fn access_allows_write(flags:u32)->bool{{flags&3!=0}}}}
const MAX_FDS:usize=64;
const EFAULT:i32=14;const EINVAL:i32=22;const EIO:i32=5;const EAGAIN:i32=11;
const EBADF:i32=9;const EOVERFLOW:i32=75;const EINTR:i32=4;
const ENOENT:i32=2;const ENAMETOOLONG:i32=91;const PAGE_SIZE:usize=4096;
mod posix_protocol{{pub const MAX_PATH_LEN:usize=4096;}}
const POLLNVAL:i16=32;const POLLHUP:i16=16;const POLLERR:i16=8;
#[repr(C)]#[derive(Clone,Copy,Default)]struct PollFd{{fd:i32,events:i16,revents:i16}}
#[repr(C)]struct FdSet{{bits:[u64;1]}}
#[repr(C)]struct Timeval{{tv_sec:i64,tv_usec:i64}}
#[repr(C)]struct NewlibTimespec{{tv_sec:i64,tv_nsec:i64}}
#[derive(Clone,Copy,PartialEq,Debug)]enum FdKind{{Unused,ObjectStreamRead,ObjectStreamWrite,ObjectPty,ObjectTerminalFile,ObjectSocket,ObjectDatagram,ObjectSeqPacket,ObjectFile,ObjectFifo}}
impl FdKind{{fn is_socket(self)->bool{{matches!(self,Self::ObjectSocket|Self::ObjectDatagram|Self::ObjectSeqPacket)}}}}
#[derive(Clone,Copy)]struct Object{{kind:FdKind,lower_handle:u64,open_flags:i32}}
#[derive(Clone,Copy)]struct FdEntry{{handle:Object}}
struct Lease(FdEntry);
impl std::ops::Deref for Lease{{type Target=FdEntry;fn deref(&self)->&FdEntry{{&self.0}}}}
impl Drop for Lease{{fn drop(&mut self){{
    assert_ne!(CONTROL.native.load(Ordering::Acquire),0);
    assert!(CONTROL.callback_resources.capture_for_fork().is_none());
    PINS.fetch_sub(1,Ordering::AcqRel);
}}}}
struct ThreadControl{{native:AtomicU32,active_signal_scope_id:AtomicU64,callback_resources:callback_resources::Chain}}
static CONTROL:ThreadControl=ThreadControl{{native:AtomicU32::new(0),active_signal_scope_id:AtomicU64::new(0),callback_resources:callback_resources::Chain::new()}};
static PINS:AtomicU32=AtomicU32::new(0);static EXPECTED_PINS:AtomicU32=AtomicU32::new(0);
static WAIT_ERROR:AtomicU32=AtomicU32::new(0);static QUERY_ERROR:AtomicU32=AtomicU32::new(0);
static WAITS:AtomicU32=AtomicU32::new(0);static ORIGINAL:AtomicUsize=AtomicUsize::new(0);
fn register_current_thread()->Option<(u32,&'static ThreadControl)>{{Some((1,&CONTROL))}}
fn defer_native_delivery()->Option<upcall_guard::Guard<'static>>{{upcall_guard::Guard::enter(&CONTROL.native)}}
fn with_fd_entry(fd:i32)->Result<Lease,i32>{{
    assert_ne!(CONTROL.native.load(Ordering::Acquire),0);
    assert!(CONTROL.callback_resources.capture_for_fork().is_none());
    let kind=match fd{{3=>FdKind::ObjectStreamRead,4=>FdKind::ObjectSocket,5=>FdKind::ObjectDatagram,
        6=>FdKind::ObjectPty,7=>FdKind::ObjectTerminalFile,8=>FdKind::ObjectStreamWrite,9=>FdKind::ObjectFile,_=>return Err(EBADF)}};
    PINS.fetch_add(1,Ordering::AcqRel);Ok(Lease(FdEntry{{handle:Object{{kind,lower_handle:(100+fd) as u64,open_flags:0}}}}))
}}
fn assert_wait_owner(){{
    assert_eq!(PINS.load(Ordering::Acquire),EXPECTED_PINS.load(Ordering::Acquire));
    assert_eq!(CONTROL.native.load(Ordering::Acquire),0);
    drop(CONTROL.callback_resources.capture_for_fork().expect("stable multiplex owner blocked fork"));
}}
mod syscall{{
    pub use super::user_copy_native::syscall::*;
    pub const HANDLE_WAIT_POLL:u64=0;pub const HANDLE_WAIT_INFINITE:u64=u64::MAX;
    pub const HANDLE_SIGNAL_READABLE:u64=1;pub const HANDLE_SIGNAL_WRITABLE:u64=2;pub const HANDLE_SIGNAL_PEER_CLOSED:u64=4;
    #[derive(Clone,Copy,Default)]pub struct HandleWaitItem{{pub handle:u32,pub minimum_write_bytes:u32,pub interests:u64,pub observed:u64}}
}}
fn wait_for_multiplex(items:&mut[syscall::HandleWaitItem],_:u64,_:&ThreadControl,_:u64)->Result<(),i32>{{
    assert_wait_owner();WAITS.fetch_add(1,Ordering::AcqRel);
    if WAIT_ERROR.load(Ordering::Acquire)!=0{{return Err(EINTR)}}
    for item in items{{assert!((103..=108).contains(&item.handle));item.observed=item.interests&3;}}Ok(())
}}
mod socket{{
    use super::*;
    pub fn poll_events(entry:FdEntry,events:i16)->Result<i16,i32>{{
        assert_wait_owner();assert!(matches!(entry.handle.lower_handle,104|105));
        let original=ORIGINAL.swap(0,Ordering::AcqRel);
        if original!=0{{unsafe{{(*(original as *mut PollFd).add(1)).fd=99;}}}}
        if QUERY_ERROR.load(Ordering::Acquire)!=0{{Err(EIO)}}else{{Ok(events&1)}}
    }}
}}
"#,
        root = root.display(),
    );
    for signature in ["fn select_with_deadline(", "fn poll_with_deadline("] {
        let start = runtime.find(signature).unwrap();
        let end = start + runtime[start..].find("\n}\n").unwrap() + 3;
        program.push_str(&runtime[start..end]);
    }
    program.push_str(
        r#"
fn clean(){assert_eq!(PINS.load(Ordering::Acquire),0);assert_eq!(CONTROL.native.load(Ordering::Acquire),0);assert!(CONTROL.callback_resources.reset_empty());}
fn main(){
    let mut fds=[PollFd{fd:3,events:1,revents:0},PollFd{fd:4,events:1,revents:0},
                 PollFd{fd:3,events:1,revents:0},PollFd{fd:-1,events:1,revents:0},PollFd{fd:99,events:1,revents:0}];
    EXPECTED_PINS.store(3,Ordering::Release);ORIGINAL.store(fds.as_mut_ptr() as usize,Ordering::Release);
    assert_eq!(poll_with_deadline(fds.as_mut_ptr(),5,u64::MAX,&CONTROL,0),Ok(4));
    assert_eq!(fds[1].fd,4);assert_eq!(fds[4].revents,POLLNVAL);clean();
    let mut mask=FdSet{bits:[(1<<3)|(1<<4)]};EXPECTED_PINS.store(2,Ordering::Release);
    assert_eq!(select_with_deadline(5,&mut mask,std::ptr::null_mut(),std::ptr::null_mut(),u64::MAX,&CONTROL,0),Ok(2));
    assert_eq!(mask.bits[0],(1<<3)|(1<<4));clean();
    mask.bits[0]=(1<<3)|(1<<31);
    assert_eq!(select_with_deadline(32,&mut mask,std::ptr::null_mut(),std::ptr::null_mut(),0,&CONTROL,0),Err(EBADF));clean();
    assert_eq!(select_with_deadline(5,1usize as *mut _,std::ptr::null_mut(),std::ptr::null_mut(),0,&CONTROL,0),Err(EFAULT));clean();
    assert_eq!(poll_with_deadline(1usize as *mut _,1,0,&CONTROL,0),Err(EFAULT));clean();
    assert_eq!(poll_with_deadline(std::ptr::null_mut(),65,0,&CONTROL,0),Err(EINVAL));clean();
    for fd in 3..=8{
        let mut fd=PollFd{fd,events:1,revents:0};EXPECTED_PINS.store(1,Ordering::Release);
        assert!(poll_with_deadline(&mut fd,1,u64::MAX,&CONTROL,0).is_ok());clean();
    }
    for query_error in [false,true]{
        WAIT_ERROR.store(u32::from(!query_error),Ordering::Release);QUERY_ERROR.store(u32::from(query_error),Ordering::Release);
        let mut fd=PollFd{fd:4,events:1,revents:0};EXPECTED_PINS.store(1,Ordering::Release);
        assert_eq!(poll_with_deadline(&mut fd,1,u64::MAX,&CONTROL,0),Err(if query_error{EIO}else{EINTR}));clean();
    }
    WAIT_ERROR.store(0,Ordering::Release);QUERY_ERROR.store(0,Ordering::Release);EXPECTED_PINS.store(0,Ordering::Release);
    assert_eq!(poll_with_deadline(std::ptr::null_mut(),0,0,&CONTROL,0),Ok(0));clean();
}
"#,
    );
    probe::run(&program);
}
