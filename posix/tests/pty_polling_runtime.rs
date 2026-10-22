//! An ordinary provider read can complete with zero without extra authority.
#[allow(dead_code)]
#[path = "support/native_error_probe.rs"]
mod probe;

#[test]
fn actual_runtime_pty_read_returns_empty_success_without_wait_or_control_query() {
    let runtime = include_str!("../../../user/crates/newlib-runtime/src/lib.rs");
    let mut program = String::from(
        r#"
#![allow(dead_code)]
use std::ffi::{c_void,c_int};
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize,Ordering};
const EBADF:i32=9;const EAGAIN:i32=11;const EISDIR:i32=21;
mod posix_protocol {pub const SIGNAL_TTIN:u32=21;}
mod mnu_abi {pub const STREAM_IO_TRY:u64=1;}
mod mochios_posix_client {pub mod fd {pub fn access_allows_read(_:u32)->bool{true}}}
#[derive(Clone,Copy,PartialEq,Eq)]enum FdKind{
 Stdin,ObjectFile,ObjectSpecial,ObjectSharedMemory,ObjectStreamRead,
 ObjectPty,ObjectStreamWrite,ObjectDirectory,Other,
}
impl FdKind{fn is_socket(self)->bool{false}}
#[derive(Clone,Copy)]struct Handle{kind:FdKind,open_flags:u64,lower_handle:u64}
#[derive(Clone,Copy)]struct FdEntry{handle:Handle}
static REPLIES:Mutex<std::collections::VecDeque<Result<u64,i32>>>=Mutex::new(std::collections::VecDeque::new());
static WAITS:AtomicUsize=AtomicUsize::new(0);
static READS:AtomicUsize=AtomicUsize::new(0);
mod socket{
 pub fn message_entry(_:crate::FdEntry,_:u64,_:usize,_:u32,_:bool)->Result<isize,i32>{panic!("not a socket")}
}
mod syscall{
 #[derive(Debug,PartialEq)]pub enum SyscallNumber{HandleRead,StreamRead}
 pub const HANDLE_SIGNAL_READABLE:u64=1;
 pub const HANDLE_SIGNAL_PEER_CLOSED:u64=4;
 pub fn raw_syscall3(n:SyscallNumber,handle:u64,buffer:u64,length:u64)->Result<u64,i32>{
  assert_eq!(n,SyscallNumber::HandleRead);assert_eq!(handle,7);assert_eq!(buffer,0x1234);assert_eq!(length,32);
  crate::READS.fetch_add(1,crate::Ordering::Relaxed);
  crate::REPLIES.lock().unwrap().pop_front().expect("no speculative extra reads")
 }
 pub fn raw_syscall4(_:SyscallNumber,_:u64,_:u64,_:u64,_:u64)->Result<u64,i32>{panic!("not a stream")}
}
fn syscall_errno(value:Result<u64,i32>)->Result<u64,i32>{value}
fn stream_io(_:FdEntry,_:u64,_:impl FnMut()->Result<u64,i32>)->Result<u64,i32>{panic!("not a stream")}
fn retry_terminal_operation<T>(signal:u32,mut call:impl FnMut()->Result<T,i32>)->Result<T,i32>{
 assert_eq!(signal,posix_protocol::SIGNAL_TTIN);call()
}
fn handle_is_nonblocking(entry:FdEntry)->Result<bool,i32>{Ok(entry.handle.open_flags!=0)}
fn wait_for_handle(_:FdEntry,interests:u64)->Result<u64,i32>{
 assert_eq!(interests,syscall::HANDLE_SIGNAL_READABLE|syscall::HANDLE_SIGNAL_PEER_CLOSED);
 WAITS.fetch_add(1,Ordering::Relaxed);Ok(interests)
}
"#,
    );
    program.push_str(probe::between(
        runtime,
        "fn syscall_read(",
        "fn refill_dir_stream(",
    ));
    program.push_str(
        r#"
fn main(){
 let mut entry=FdEntry{handle:Handle{kind:FdKind::ObjectPty,lower_handle:7,open_flags:0}};
 for reply in [Ok(0),Ok(4),Ok(0)]{
  REPLIES.lock().unwrap().push_back(reply);
  assert_eq!(syscall_read(entry,0x1234usize as *mut _,32),reply.map(|v|v as isize));
 }
 assert_eq!(WAITS.load(Ordering::Relaxed),0);
 assert_eq!(READS.load(Ordering::Relaxed),3);
 // Canonical/other waiting modes still wait on EAGAIN, not on an empty success.
 REPLIES.lock().unwrap().extend([Err(EAGAIN),Ok(0)]);
 assert_eq!(syscall_read(entry,0x1234usize as *mut _,32),Ok(0));
 assert_eq!(WAITS.load(Ordering::Relaxed),1);
 // Nonblocking readers can receive a zero-byte success too; EAGAIN is returned
 // directly when the provider reports it, without adding a wait.
 entry.handle.open_flags=1;
 for reply in [Err(EAGAIN),Ok(0)]{
  REPLIES.lock().unwrap().push_back(reply);
  assert_eq!(syscall_read(entry,0x1234usize as *mut _,32),reply.map(|v|v as isize));
 }
 assert_eq!(WAITS.load(Ordering::Relaxed),1);
 let before=READS.load(Ordering::Relaxed);
 assert_eq!(syscall_read(entry,std::ptr::null_mut(),0),Ok(0));
 assert_eq!(READS.load(Ordering::Relaxed),before);
 assert!(REPLIES.lock().unwrap().is_empty());
}
"#,
    );
    probe::run(&program);
}
