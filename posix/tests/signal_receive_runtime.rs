//! Execute the unchanged runtime receive loops with controlled endpoint,
//! local-value-adapter and copy outcomes. Actual registry/checked-copy behavior
//! is covered by process_timer_runtime and signal_memory_runtime respectively.
#[allow(dead_code)]
#[path = "support/native_error_probe.rs"]
mod probe;

#[test]
fn actual_signal_receive_loops_discard_retired_metadata_without_extending_deadlines() {
    let runtime = include_str!("../../../user/crates/newlib-runtime/src/lib.rs");
    let mut program = String::from(
        r#"
#![allow(dead_code)]
use std::{ffi::c_int,collections::VecDeque,sync::{Mutex,atomic::{AtomicU32,Ordering}}};
const EFAULT:i32=14;const EAGAIN:i32=11;const EINTR:i32=4;const EIO:i32=5;
extern crate self as mochios_posix_client;
pub mod signal_context{pub struct SigInfo;}
mod posix_protocol{pub const STATUS_EINTR:i32=4;}
enum PosixClientError{Remote(i32)}
#[derive(Clone,Copy)]struct Accepted{signal:u32,origin:u32}
static QUEUE:Mutex<VecDeque<Result<Accepted,i32>>>=Mutex::new(VecDeque::new());
static CALLS:Mutex<Vec<(u64,Option<u64>,u64)>>=Mutex::new(Vec::new());
static COPIES:Mutex<Vec<u32>>=Mutex::new(Vec::new());
static EPOCH:AtomicU32=AtomicU32::new(0);
static DRAINS:AtomicU32=AtomicU32::new(0);
static READ_ERROR:AtomicU32=AtomicU32::new(0);
static WRITE_ERROR:AtomicU32=AtomicU32::new(0);
static CANCEL_PENDING:AtomicU32=AtomicU32::new(0);
static CANCEL_ENABLED:AtomicU32=AtomicU32::new(1);
static CANCEL_PHASE:AtomicU32=AtomicU32::new(u32::MAX);
fn pthread_testcancel(){
 if CANCEL_PENDING.load(Ordering::Acquire)!=0&&CANCEL_ENABLED.load(Ordering::Acquire)!=0{
  let phase=CANCEL_PHASE.load(Ordering::Acquire);
  assert!(phase<=2,"a committed signal must remain visible");
  assert_eq!(CALLS.lock().unwrap().len(),if phase==2{1}else{0});
  assert!(COPIES.lock().unwrap().is_empty());
  assert_eq!(QUEUE.lock().unwrap().len(),1,"cancellation must not accept the queued signal");
  std::process::exit(0);
 }
}
fn register_current_thread()->Option<(u32,())>{Some((1,()))}
fn map_posix_client_error(error:PosixClientError)->i32{match error{PosixClientError::Remote(e)=>e}}
fn drain_pending_signals()->Result<(),i32>{DRAINS.fetch_add(1,Ordering::Relaxed);Ok(())}
struct Client;
fn posix_client()->Result<&'static Client,PosixClientError>{Ok(&Client)}
impl Client {
 fn thread_signal_epoch(&self)->Result<u64,PosixClientError>{
  if CANCEL_PHASE.load(Ordering::Acquire)==1{CANCEL_PENDING.store(1,Ordering::Release)}
  Ok(EPOCH.fetch_add(1,Ordering::Relaxed) as u64+1)
 }
 fn wait_thread_signal_info_until(&self,mask:u64,epoch:u64,deadline:u64)->Result<Accepted,PosixClientError>{self.receive(mask,epoch,Some(deadline))}
 fn wait_thread_signal_info_since(&self,mask:u64,epoch:u64)->Result<Accepted,PosixClientError>{self.receive(mask,epoch,None)}
 fn receive(&self,mask:u64,epoch:u64,deadline:Option<u64>)->Result<Accepted,PosixClientError>{
  CALLS.lock().unwrap().push((epoch,deadline,mask));
  let phase=CANCEL_PHASE.load(Ordering::Acquire);
  if phase==2{
   assert_eq!(CALLS.lock().unwrap().len(),1,"cancelled wait was retried");
   CANCEL_PENDING.store(1,Ordering::Release);return Err(PosixClientError::Remote(EINTR))
  }
  let result=QUEUE.lock().unwrap().pop_front().expect("unexpected retry").map_err(PosixClientError::Remote);
  if phase==3{CANCEL_PENDING.store(1,Ordering::Release)}
  result
 }
}
mod signal_info {
 use super::*;
 pub struct Prepared(u32);
 impl Prepared{pub fn into_info(self)->Result<signal_context::SigInfo,i32>{if self.0==3{Err(EIO)}else{Ok(signal_context::SigInfo)}}}
 pub fn prepare(_:u32,origin:u32)->Result<Option<Prepared>,i32>{
  match origin{0|3=>Ok(Some(Prepared(origin))),1=>Ok(None),_=>Err(EIO)}
 }
}
mod signal_memory {
 use super::*;
 pub fn read_set(_: *const u64)->Result<u64,i32>{
  if READ_ERROR.load(Ordering::Relaxed)!=0{Err(EFAULT)}else{Ok(0x200)}
 }
 pub fn write_resolved_info(_: *mut signal_context::SigInfo,_:signal_context::SigInfo)->Result<(),i32>{
  if WRITE_ERROR.load(Ordering::Relaxed)!=0{return Err(EFAULT)}
  COPIES.lock().unwrap().push(0);Ok(())
 }
 pub fn write_selected(_: *mut i32,signal:i32)->Result<(),i32>{
  if WRITE_ERROR.load(Ordering::Relaxed)!=0{return Err(EFAULT)}
  COPIES.lock().unwrap().push(signal as u32);Ok(())
 }
}
fn reset(queue:Vec<Result<Accepted,i32>>){
 *QUEUE.lock().unwrap()=queue.into();CALLS.lock().unwrap().clear();COPIES.lock().unwrap().clear();
 for counter in [&EPOCH,&DRAINS,&READ_ERROR,&WRITE_ERROR]{counter.store(0,Ordering::Relaxed)}
 CANCEL_PENDING.store(0,Ordering::Release);CANCEL_ENABLED.store(1,Ordering::Release);CANCEL_PHASE.store(u32::MAX,Ordering::Release);
}
fn accepted(origin:u32)->Result<Accepted,i32>{Ok(Accepted{signal:10,origin})}
fn calls(deadline:Option<u64>,count:usize){
 assert_eq!(*CALLS.lock().unwrap(),(1..=count).map(|i|(i as u64,deadline,0x200)).collect::<Vec<_>>());
}
"#,
    );
    program.push_str(probe::between(
        runtime,
        "fn wait_signal_info(",
        "#[unsafe(no_mangle)]\npub unsafe extern \"C\" fn _signal_r(",
    ));
    program.push_str(probe::between(
        runtime,
        "pub unsafe extern \"C\" fn sigwait(",
        "#[unsafe(no_mangle)]\npub unsafe extern \"C\" fn sigwaitinfo(",
    ));
    program.push_str(
        r#"
fn main(){
 let mask=0x200u64;let mut selected=0;
 let args:Vec<_>=std::env::args().collect();
 if args.len()==3{
  let mode:u32=args[1].parse().unwrap();let phase:u32=args[2].parse().unwrap();
  reset(vec![accepted(0)]);CANCEL_PHASE.store(phase,Ordering::Release);
  if phase==0||phase==4{CANCEL_PENDING.store(1,Ordering::Release)}
  if phase==4{CANCEL_ENABLED.store(0,Ordering::Release)}
  if mode==0{assert_eq!(unsafe{sigwait(&mask,&mut selected)},0);assert_eq!(*COPIES.lock().unwrap(),[10])}
  else{assert_eq!(wait_signal_info(&mask,std::ptr::null_mut(),(mode==2).then_some(123)),Ok(10));}
  assert!(phase==3||phase==4,"pending cancellation returned from the API");
  assert_eq!(COPIES.lock().unwrap().len(),1);assert!(QUEUE.lock().unwrap().is_empty());return;
 }
 for mode in 0..3{for phase in 0..5{
  let result=std::process::Command::new(std::env::current_exe().unwrap()).args([mode.to_string(),phase.to_string()]).output().unwrap();
  assert!(result.status.success(),"mode={mode},phase={phase}: {}",String::from_utf8_lossy(&result.stderr));
 }}
 reset(vec![accepted(1),accepted(1),accepted(0)]);
 assert_eq!(wait_signal_info(&mask,std::ptr::null_mut(),Some(123)),Ok(10));
 calls(Some(123),3);assert_eq!(*COPIES.lock().unwrap(),[0]);
 assert_eq!(DRAINS.load(Ordering::Relaxed),0);

 reset(vec![accepted(1),Err(EAGAIN)]);
 assert_eq!(wait_signal_info(&mask,std::ptr::null_mut(),Some(123)),Err(EAGAIN));
 calls(Some(123),2);assert!(COPIES.lock().unwrap().is_empty());

 reset(vec![accepted(1),Err(EINTR)]);
 assert_eq!(wait_signal_info(&mask,std::ptr::null_mut(),Some(123)),Err(EINTR));
 calls(Some(123),2);assert_eq!(DRAINS.load(Ordering::Relaxed),1);
 assert!(COPIES.lock().unwrap().is_empty());

 reset(vec![accepted(1),accepted(0)]);
 assert_eq!(wait_signal_info(&mask,std::ptr::null_mut(),None),Ok(10));
 calls(None,2);

 reset(vec![accepted(2)]);
 assert_eq!(wait_signal_info(&mask,std::ptr::null_mut(),None),Err(EIO));
 calls(None,1);assert!(COPIES.lock().unwrap().is_empty());

 reset(vec![accepted(3)]);
 assert_eq!(wait_signal_info(&mask,std::ptr::null_mut(),None),Err(EIO));
 calls(None,1);assert!(COPIES.lock().unwrap().is_empty());

 reset(vec![accepted(0)]);WRITE_ERROR.store(1,Ordering::Relaxed);
 assert_eq!(wait_signal_info(&mask,std::ptr::null_mut(),None),Err(EFAULT));
 calls(None,1);assert!(COPIES.lock().unwrap().is_empty());

 reset(vec![accepted(0)]);READ_ERROR.store(1,Ordering::Relaxed);
 assert_eq!(wait_signal_info(&mask,std::ptr::null_mut(),None),Err(EFAULT));
 calls(None,0);

 reset(vec![accepted(1),Err(EINTR),accepted(3)]);
 // sigwait does not request siginfo's narrower C identity representation.
 assert_eq!(unsafe{sigwait(&mask,&mut selected)},0);
 calls(None,3);assert_eq!(DRAINS.load(Ordering::Relaxed),1);
 assert_eq!(*COPIES.lock().unwrap(),[10]);

 reset(vec![accepted(2)]);
 assert_eq!(unsafe{sigwait(&mask,&mut selected)},EIO);
 calls(None,1);assert!(COPIES.lock().unwrap().is_empty());

 reset(vec![accepted(1),accepted(0)]);WRITE_ERROR.store(1,Ordering::Relaxed);
 assert_eq!(unsafe{sigwait(&mask,&mut selected)},EFAULT);
 calls(None,2);assert!(COPIES.lock().unwrap().is_empty());
}
"#,
    );
    probe::run(&program);
}
