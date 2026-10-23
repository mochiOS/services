//! Execute the production child-wait loops with interruption at the endpoint
//! boundary. The backend preserves a child event unless it publishes success.
#[allow(dead_code)]
#[path = "support/native_error_probe.rs"]
mod probe;

#[test]
fn actual_child_waits_cancel_before_admission_and_preserve_committed_results() {
    let runtime = include_str!("../../../user/crates/newlib-runtime/src/lib.rs");
    let mut program = String::from(
        r#"
#![allow(dead_code)]
use std::{ffi::c_int,sync::atomic::{AtomicU32,AtomicU64,Ordering}};
extern crate self as mochios_posix_client;
pub mod signal_context{pub struct SigInfo;}
pub mod wait{
 pub struct Request{pub selector:i64,pub options:u32}
 pub fn request(_:i32,id:u32,options:i32)->Result<Request,i32>{Ok(Request{selector:id as i64,options:options as u32})}
 pub fn origin(_:super::Info)->Result<(),i32>{Ok(())}
}
mod posix_protocol{pub const STATUS_EINTR:i32=4;pub const SIGNAL_CHLD:u32=17;}
const EINVAL:i32=22;const EFAULT:i32=14;const EAGAIN:i32=11;const EINTR:i32=4;
const WNOHANG:i32=1;const WUNTRACED:i32=2;const WCONTINUED:i32=8;
struct Control{nonrestart_signal_generation:AtomicU64}
static CONTROL:Control=Control{nonrestart_signal_generation:AtomicU64::new(0)};
static PENDING:AtomicU32=AtomicU32::new(0);static ENABLED:AtomicU32=AtomicU32::new(1);
static PHASE:AtomicU32=AtomicU32::new(0);static CALLS:AtomicU32=AtomicU32::new(0);
static EVENT:AtomicU32=AtomicU32::new(1);static COPIES:AtomicU32=AtomicU32::new(0);
static ERRNO:AtomicU32=AtomicU32::new(123);
fn pthread_testcancel(){
 if PENDING.load(Ordering::Acquire)!=0&&ENABLED.load(Ordering::Acquire)!=0{
  let phase=PHASE.load(Ordering::Acquire);assert!(phase<=2,"committed child event was hidden");
  assert_eq!(EVENT.load(Ordering::Acquire),1);assert_eq!(COPIES.load(Ordering::Acquire),0);
  assert_eq!(CALLS.load(Ordering::Acquire),if phase==2{1}else{0});
  assert_eq!(ERRNO.load(Ordering::Acquire),123);std::process::exit(0);
 }
}
fn register_current_thread()->Option<(usize,&'static Control)>{Some((1,&CONTROL))}
enum PosixClientError{Remote(i32)}
fn map_posix_client_error(error:PosixClientError)->i32{match error{PosixClientError::Remote(e)=>e}}
fn result_with_errno<T>(result:Result<T,i32>,failure:T)->T{match result{Ok(value)=>value,Err(error)=>{ERRNO.store(error as u32,Ordering::Release);failure}}}
fn drain_pending_signals()->Result<(),i32>{Ok(())}
#[derive(Clone,Copy)]pub struct Event{process_id:u64,status:u32}
#[derive(Clone,Copy)]pub struct Info{result:Event}
struct Client;
fn posix_client()->Result<&'static Client,PosixClientError>{Ok(&Client)}
impl Client{
 fn thread_signal_epoch(&self)->Result<u64,PosixClientError>{if PHASE.load(Ordering::Acquire)==1{PENDING.store(1,Ordering::Release)}Ok(7)}
 fn receive(&self)->Result<Info,PosixClientError>{
  let call=CALLS.fetch_add(1,Ordering::AcqRel)+1;
  let phase=PHASE.load(Ordering::Acquire);
  if phase==2{assert_eq!(call,1,"cancelled wait was retried");PENDING.store(1,Ordering::Release);return Err(PosixClientError::Remote(EINTR))}
  assert_eq!(EVENT.swap(0,Ordering::AcqRel),1);
  if phase==3{PENDING.store(1,Ordering::Release)}
  Ok(Info{result:Event{process_id:42,status:37<<8}})
 }
 fn wait_child(&self,_:i64,_:u32)->Result<Event,PosixClientError>{self.receive().map(|info|info.result)}
 fn wait_child_since(&self,_:i64,_:u32,_:u64)->Result<Event,PosixClientError>{self.receive().map(|info|info.result)}
 fn wait_child_info_since(&self,_:i64,_:u32,_:u64)->Result<Info,PosixClientError>{self.receive()}
}
mod wait_output{pub fn publish(pid:u64,status:u32,output:*mut i32)->Result<i32,i32>{
 assert_eq!((pid,status),(42,37<<8));unsafe{output.write(status as i32)};
 super::COPIES.fetch_add(1,super::Ordering::AcqRel);Ok(pid as i32)
}}
mod signal_memory{pub fn write_info(_: *mut super::signal_context::SigInfo,_:u32,_:())->Result<(),i32>{super::COPIES.fetch_add(1,super::Ordering::AcqRel);Ok(())}}
mod user_copy{pub fn write(_: *mut u8,_:&[u8])->Result<(),i32>{panic!("ready child required")}}
"#,
    );
    program.push_str(probe::between(
        runtime,
        "pub extern \"C\" fn _waitpid(",
        "#[unsafe(no_mangle)]\npub extern \"C\" fn waitpid(",
    ));
    program.push_str("mod wait_id {\n");
    program.push_str(
        &include_str!("../../../user/crates/newlib-runtime/src/wait_id.rs")
            .replace("#[unsafe(no_mangle)]", ""),
    );
    program.push_str(r#"
}
fn main(){
 let args:Vec<_>=std::env::args().collect();
 if args.len()==3{
  let api:u32=args[1].parse().unwrap();let phase:u32=args[2].parse().unwrap();PHASE.store(phase,Ordering::Release);
  if phase==0||phase==4{PENDING.store(1,Ordering::Release)}
  if phase==4{ENABLED.store(0,Ordering::Release)}
  let mut status=0;
  if api==1{let mut info=signal_context::SigInfo;assert_eq!(wait_id::waitid(1,42,&mut info,4),0)}
  else{assert_eq!(_waitpid(42,&mut status,if api==2{WNOHANG}else{0}),42);assert_eq!(status,37<<8)}
  assert!(phase==3||phase==4,"pending cancellation returned");
  assert_eq!(EVENT.load(Ordering::Acquire),0);assert_eq!(COPIES.load(Ordering::Acquire),1);assert_eq!(ERRNO.load(Ordering::Acquire),123);return;
 }
 for api in 0..3{for phase in 0..5{
  if api==2&&(phase==1||phase==2){continue}
  let child=std::process::Command::new(std::env::current_exe().unwrap()).args([api.to_string(),phase.to_string()]).output().unwrap();
  assert!(child.status.success(),"api={api},phase={phase}: {}",String::from_utf8_lossy(&child.stderr));
 }}
}
"#);
    probe::run(&program);
}
