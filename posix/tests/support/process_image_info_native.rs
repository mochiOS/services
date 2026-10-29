#![allow(dead_code)]
extern crate alloc;
extern crate self as mnu_abi;
#[path = ABI_SOURCE]
mod abi;
pub use abi::*;
use std::sync::{Arc, LazyLock, Mutex, atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering}, mpsc};
use status::Error;
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Id(u64);
impl Id { fn as_u64(self) -> u64 { self.0 } }
struct Object { id: Id, live: AtomicBool, revision: AtomicU64 }
impl Object {
 fn id(&self)->Id{self.id}
 fn accepts_threads(&self)->bool{self.live.load(Ordering::Acquire)}
 fn image_revision(&self)->u64{self.revision.load(Ordering::Acquire)}
}
fn object(id:u64)->Arc<Object>{Arc::new(Object{id:Id(id),live:AtomicBool::new(true),revision:AtomicU64::new(0)})}
static TARGET:LazyLock<Arc<Object>>=LazyLock::new(||object(17));
static FOREIGN:LazyLock<Arc<Object>>=LazyLock::new(||object(17));
static CALLER:AtomicBool=AtomicBool::new(true);
static PRESENT:AtomicBool=AtomicBool::new(true);
static REUSED:AtomicBool=AtomicBool::new(false);
static QUERIES:AtomicUsize=AtomicUsize::new(0);
static COPIES:AtomicUsize=AtomicUsize::new(0);
static COPY_FAILURE:Mutex<Option<Error>>=Mutex::new(None);
static DIGEST:Mutex<Option<[u8;32]>>=Mutex::new(Some([3;32]));
static ATTEMPT:Mutex<Option<mpsc::Sender<()>>>=Mutex::new(None);
struct Process { object: Arc<Object>, digest: Option<[u8;32]> }
impl Process {
 fn process_object(&self)->Arc<Object>{self.object.clone()}
 fn image_digest(&self)->Option<[u8;32]>{self.digest}
}
mod task {
 use super::*;
 pub fn with_process<R>(id:Id,f:impl FnOnce(&Process)->R)->Option<R>{
  assert_eq!(id,Id(17));QUERIES.fetch_add(1,Ordering::Relaxed);
  if let Some(tx)=ATTEMPT.lock().unwrap().as_ref(){tx.send(()).unwrap();}
  let digest=DIGEST.lock().unwrap();
  PRESENT.load(Ordering::Acquire).then(||f(&Process{object:if REUSED.load(Ordering::Acquire){FOREIGN.clone()}else{TARGET.clone()},digest:*digest}))
 }
}
mod syscall {
 use super::*;
 pub mod security {pub fn current_process_id()->Option<Id>{CALLER.load(Ordering::Acquire).then_some(Id(17))} use super::*;}
 pub fn copy_to_user_native(out:u64,bytes:&[u8])->Result<(),Error>{
  COPIES.fetch_add(1,Ordering::Relaxed);
  if let Some(error)=*COPY_FAILURE.lock().unwrap(){return Err(error);}
  if out<4096{return Err(Error::InvalidAddress);}
  unsafe{std::ptr::copy_nonoverlapping(bytes.as_ptr(),out as *mut u8,bytes.len());}Ok(())
 }
}
mod handles {
 use super::*;
 #[derive(Debug,PartialEq)]pub struct HandleRights;
 impl HandleRights{pub const WAIT:Self=Self;}
 pub enum KernelObject{Process(Arc<Object>),Other}
 pub fn object_native(raw:u64,right:HandleRights)->Result<KernelObject,Error>{
  assert_eq!(right,HandleRights::WAIT);
  match raw{42=>Ok(KernelObject::Process(TARGET.clone())),43=>Err(Error::AccessDenied),44=>Ok(KernelObject::Other),_=>Err(Error::InvalidArgument)}
 }
 #[path = READER_SOURCE]
 pub mod reader;
}
fn main(){
 let mut info=ProcessImageInfo::default();let out=(&mut info as *mut ProcessImageInfo)as u64;
 for h in [0,42]{assert_eq!(handles::reader::read(h,out,56),0);assert_eq!(info,ProcessImageInfo{process_id:17,digest_kind:1,digest:[3;32],..Default::default()});}
 for (raw,error) in [(43,Error::AccessDenied),(44,Error::InvalidArgument),(u64::MAX,Error::InvalidArgument)]{
  let q=QUERIES.load(Ordering::Relaxed);let c=COPIES.load(Ordering::Relaxed);let old=info;
  assert_eq!(handles::reader::read(raw,out,56),error.into_raw());assert_eq!(info,old);assert_eq!(QUERIES.load(Ordering::Relaxed),q);assert_eq!(COPIES.load(Ordering::Relaxed),c);
 }
 for length in [0,55,57,u64::MAX]{let q=QUERIES.load(Ordering::Relaxed);assert_eq!(handles::reader::read(0,out,length),Error::InvalidArgument.into_raw());assert_eq!(QUERIES.load(Ordering::Relaxed),q);}
 assert_eq!(handles::reader::read(42,0,56),Error::InvalidAddress.into_raw());
 for error in [Error::ResourceUnavailable,Error::BackingFailure]{*COPY_FAILURE.lock().unwrap()=Some(error);assert_eq!(handles::reader::read(42,out,56),error.into_raw());}*COPY_FAILURE.lock().unwrap()=None;
 CALLER.store(false,Ordering::Release);assert_eq!(handles::reader::read(0,out,56),Error::NotReady.into_raw());CALLER.store(true,Ordering::Release);
 for state in 0..3{
  if state==0{PRESENT.store(false,Ordering::Release);}else if state==1{TARGET.live.store(false,Ordering::Release);}else{REUSED.store(true,Ordering::Release);}
  assert_eq!(handles::reader::read(42,out,56),Error::NotFound.into_raw());
  PRESENT.store(true,Ordering::Release);TARGET.live.store(true,Ordering::Release);REUSED.store(false,Ordering::Release);
 }
 *DIGEST.lock().unwrap()=None;assert_eq!(handles::reader::read(0,out,56),0);assert_eq!(info.digest_kind,0);assert_eq!(info.digest,[0;32]);
 *DIGEST.lock().unwrap()=Some([0;32]);assert_eq!(handles::reader::read(0,out,56),0);assert_eq!(info.digest_kind,1);
 // Writer has published new bytes but not the final revision, under the same
 // commit lock. An observer awakened in this interval must wait for both.
 let (ready_tx,ready_rx)=mpsc::channel();let (attempt_tx,attempt_rx)=mpsc::channel();
 *ATTEMPT.lock().unwrap()=Some(attempt_tx);
 let writer=std::thread::spawn(move||{
  let mut digest=DIGEST.lock().unwrap();*digest=Some([9;32]);ready_tx.send(()).unwrap();
  attempt_rx.recv_timeout(std::time::Duration::from_secs(2)).unwrap();
  TARGET.revision.store(7,Ordering::Release);
 });
 ready_rx.recv_timeout(std::time::Duration::from_secs(2)).unwrap();
 assert_eq!(handles::reader::read(42,out,56),0);writer.join().unwrap();
 assert_eq!(info.image_revision,7);assert_eq!(info.digest,[9;32]);
}
