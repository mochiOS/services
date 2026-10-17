use std::io::Write;
use std::process::{Command, Stdio};

#[test]
fn production_retirement_releases_only_exact_destinations_and_rejects_late_sends() {
    let source = include_str!("../../../core/src/syscall/ipc.rs");
    let types = source
        .find("#[derive(Debug)]\nstruct ObjectHandleAttachments")
        .unwrap();
    let mailbox = source
        .find("#[derive(Clone, Copy, Debug, PartialEq, Eq)]\nstruct ReplyTarget")
        .unwrap();
    let constructor_end = source[mailbox..].find("    fn add_reply_target(").unwrap() + mailbox;
    let slots = source.find("    fn reserve_slot(").unwrap();
    let slots_end = source[slots..].find("    fn push_message(").unwrap() + slots;
    let waiter = source.find("    fn take_waiter(").unwrap();
    let waiter_end = source[waiter..].find("\n    }\n").unwrap() + waiter + 7;
    let cache = source.find("struct MessageCache {").unwrap();
    let cache_end = source[cache..].find("static MESSAGE_CACHE:").unwrap() + cache;
    let retire = source.find("pub(crate) fn retire_endpoint(").unwrap();
    let retire_end = source[retire..].find("\n}\n").unwrap() + retire + 3;
    let send = source
        .find("fn send_to_thread_id_with_attachments(")
        .unwrap();
    let send_end = source[send..].find("\n}\n").unwrap() + send + 3;
    let mut program = String::from(
        r#"
use std::{alloc::{alloc as system_alloc,Layout},collections::BTreeMap,sync::{Arc,Mutex,atomic::{AtomicU64,AtomicUsize,AtomicBool,Ordering}}};
static NEXT_MESSAGE_ID:AtomicU64=AtomicU64::new(1);
use status::Error;
const MAX_OBJECT_HANDLES:usize=4;const MAX_MSG_SIZE:usize=256;const MAX_THREADS:usize=2;
const MAILBOX_CAP:usize=4;const MESSAGE_CACHE_CAP:usize=4;
static COPY_RACE:AtomicBool=AtomicBool::new(false);
static FAIL_ALLOC:AtomicBool=AtomicBool::new(false);
static COPY_ERROR:AtomicUsize=AtomicUsize::new(0);
unsafe fn alloc(layout:Layout)->*mut u8{
 if FAIL_ALLOC.swap(false,Ordering::SeqCst){return std::ptr::null_mut();}
 unsafe{system_alloc(layout)}
}
static DROPPED:AtomicUsize=AtomicUsize::new(0);static RETIRED:AtomicUsize=AtomicUsize::new(0);
#[derive(Clone,Copy,Debug,PartialEq,Eq)]struct IpcEndpoint{thread_id:u64,slot:u16,generation:u64}
#[derive(Debug)]struct Resource;
impl Drop for Resource{fn drop(&mut self){assert!(MAILBOXES.0.try_lock().is_ok(),"resource destructor ran under mailbox lock");DROPPED.fetch_add(1,Ordering::SeqCst);}}
#[derive(Debug)]struct ObjectHandleEntry(Arc<Resource>);
struct Lock<T>(Mutex<T>);impl<T>Lock<T>{const fn new(v:T)->Self{Self(Mutex::new(v))}fn lock(&self)->std::sync::MutexGuard<'_,T>{self.0.lock().unwrap()}}
mod audit{pub enum AuditEventKind{Quarantine}pub fn log(_:AuditEventKind,reason:&str){panic!("unexpected quarantine: {}",reason);}}
mod performance{pub enum CounterMetric{IpcSendAllocations}pub fn increment(_:CounterMetric,_:u64){}}
#[macro_export]macro_rules! debug{($($arg:tt)*)=>{()}}
fn record_ipc_copy(_:usize){}
fn ipc_max_msg_size()->usize{MAX_MSG_SIZE}fn ipc_mailbox_cap()->usize{MAILBOX_CAP}
static OWNERS:Mutex<BTreeMap<u64,(usize,u64)>>=Mutex::new(BTreeMap::new());
mod task{
 pub fn thread_slot_index_and_generation_by_u64(id:u64)->Option<(usize,u64)>{crate::OWNERS.lock().unwrap().get(&id).copied()}
 pub struct ThreadId;impl ThreadId{pub fn from_u64(_:u64)->Self{Self}}
 pub fn wake_registered_waiter(_:ThreadId){}
}
mod syscall{
 pub fn copy_from_user_native(input:u64,output:&mut[u8])->Result<(),crate::Error>{
  assert!(crate::MAILBOXES.0.try_lock().is_ok(),"user copy ran under mailbox lock");
  match crate::COPY_ERROR.swap(0,crate::Ordering::SeqCst){
   0=>{},1=>return Err(crate::Error::InvalidAddress),
   2=>return Err(crate::Error::ResourceUnavailable),_=>return Err(crate::Error::BackingFailure),
  }
  if crate::COPY_RACE.swap(false,crate::Ordering::SeqCst){
    crate::OWNERS.lock().unwrap().remove(&7);
    crate::retire_endpoint(crate::IpcEndpoint{thread_id:7,slot:0,generation:1});
  }
  unsafe{output.copy_from_slice(std::slice::from_raw_parts(input as*const u8,output.len()));}Ok(())
 }
}
mod lifetime{pub fn retire(_:crate::IpcEndpoint){assert!(crate::MAILBOXES.0.try_lock().is_ok());crate::RETIRED.fetch_add(1,crate::Ordering::SeqCst);}}
fn endpoint_is_valid(endpoint:IpcEndpoint)->bool{OWNERS.lock().unwrap().get(&endpoint.thread_id)==Some(&(endpoint.slot as usize,endpoint.generation))}
"#,
    );
    let status = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../core/crates/abi/src/status.rs")
        .canonicalize()
        .unwrap();
    program.insert_str(
        0,
        &format!("extern crate self as mnu_abi;\n#[path={status:?}] mod status;\n"),
    );
    program.push_str(&source[types..mailbox]);
    program.push_str(&source[mailbox..constructor_end]);
    program.push_str(&source[slots..slots_end]);
    program.push_str(&source[waiter..waiter_end]);
    program.push_str("\n}\n");
    program.push_str(&source[cache..cache_end]);
    program.push_str(
        r#"
static MESSAGE_CACHE:Lock<MessageCache>=Lock::new(MessageCache::new());
static MAILBOXES:Lock<[Mailbox;MAX_THREADS]>=Lock::new([const{Mailbox::new()};MAX_THREADS]);
fn lock_mailboxes()->std::sync::MutexGuard<'static,[Mailbox;MAX_THREADS]>{MAILBOXES.lock()}
"#,
    );
    program.push_str(&source[retire..retire_end]);
    program.push_str(&source[send..send_end]);
    program.push_str(r#"
fn make_message(to:u64,generation:u64,slot:u16,tag:u64)->(Box<Message>,std::sync::Weak<Resource>){
 let resource=Arc::new(Resource);let weak=Arc::downgrade(&resource);
 let mut message=Box::new(Message::empty());message.to=to;message.to_generation=generation;message.to_slot=slot;message.call_id=tag;message.is_reply=true;
 message.object_handles.count=1;message.object_handles.handles[0]=Some(ObjectHandleEntry(resource));(message,weak)
}
fn enqueue(slot:usize,message:Box<Message>){MAILBOXES.lock()[slot].enqueue_message(message).unwrap();}
fn drain(slot:usize)->Vec<Box<Message>>{
 let mut boxes=MAILBOXES.lock();let mailbox=&mut boxes[slot];let mut result=Vec::new();
 while let Some(index)=mailbox.dequeue_slot(){result.push(mailbox.take_slot(index).unwrap());}result
}
fn main(){
 let old=IpcEndpoint{thread_id:7,slot:0,generation:1};
 let mut weak=Vec::new();
 for(to,generation,tag)in[(7,1,101),(8,2,202),(7,1,103),(7,2,204)]{
   let(message,reference)=make_message(to,generation,0,tag);enqueue(0,message);weak.push(reference);
 }
 let(unrelated,other)=make_message(9,3,1,300);enqueue(1,unrelated);
 {let mut boxes=MAILBOXES.lock();boxes[0].reply_owner=Some((8,2));boxes[0].reply_targets.push(ReplyTarget{endpoint:42,call_id:202});boxes[0].waiter=8;}
 OWNERS.lock().unwrap().insert(8,(0,2));
 retire_endpoint(old);
 assert_eq!(DROPPED.load(Ordering::SeqCst),2);
 assert!(weak[0].upgrade().is_none()&&weak[2].upgrade().is_none());
 assert!(weak[1].upgrade().is_some()&&weak[3].upgrade().is_some()&&other.upgrade().is_some());
 {let boxes=MAILBOXES.lock();assert_eq!(boxes[0].count,2);assert_eq!(boxes[0].free_count,2);assert_eq!(boxes[0].waiter,8);assert_eq!(boxes[0].reply_owner,Some((8,2)));assert_eq!(boxes[0].reply_targets.len(),1);assert_eq!(boxes[1].count,1);}
 retire_endpoint(old);assert_eq!(DROPPED.load(Ordering::SeqCst),2);
 let remaining=drain(0);assert_eq!(remaining.iter().map(|m|m.call_id).collect::<Vec<_>>(),[202,204]);
 for message in remaining{release_message(message);}for message in drain(1){release_message(message);}
 assert_eq!(DROPPED.load(Ordering::SeqCst),5);

 // Delayed cleanup must not clear a same-ID newer-generation wait record.
 OWNERS.lock().unwrap().insert(7,(0,2));
 {let mut boxes=MAILBOXES.lock();boxes[0].waiter=7;boxes[0].reply_owner=Some((7,2));boxes[0].reply_targets.push(ReplyTarget{endpoint:42,call_id:204});}
 retire_endpoint(old);
 {let boxes=MAILBOXES.lock();assert_eq!(boxes[0].waiter,7);assert_eq!(boxes[0].reply_owner,Some((7,2)));}
 OWNERS.lock().unwrap().remove(&7);
 {let mut boxes=MAILBOXES.lock();boxes[0].reply_owner=Some((7,1));}
 retire_endpoint(old);
 {let boxes=MAILBOXES.lock();assert_eq!(boxes[0].waiter,0);assert_eq!(boxes[0].reply_owner,None);assert!(boxes[0].reply_targets.is_empty());}

 // Full-capacity retirement, freelist reuse, ring wraparound and repeated
 // retirement must neither lose entries nor release the same reference twice.
 for round in 0..50{
   for tag in 0..MAILBOX_CAP{let(message,_)=make_message(7,1,0,tag as u64);enqueue(0,message);}
   retire_endpoint(old);
   let boxes=MAILBOXES.lock();let mb=&boxes[0];assert_eq!((mb.count,mb.free_count),(0,MAILBOX_CAP));
   let mut free=mb.free[..mb.free_count].to_vec();free.sort();assert_eq!(free,[0,1,2,3]);
   assert_eq!(DROPPED.load(Ordering::SeqCst),5+(round+1)*MAILBOX_CAP);
 }

 // Execute the real send implementation. Killing its destination during the
 // user-buffer copy reproduces publication racing with completed retirement.
 OWNERS.lock().unwrap().insert(7,(0,1));
 let(message,reference)=make_message(7,1,0,1);
 let attachments=message.object_handles;COPY_RACE.store(true,Ordering::SeqCst);
 let result=send_to_thread_id_with_attachments(7,99,1,b"x".as_ptr()as u64,1,false,true,attachments);
 assert_eq!(result,Error::NotFound.into_raw());assert!(reference.upgrade().is_none());
 assert_eq!(MAILBOXES.lock()[0].count,0);

 // A live destination still accepts normal messages without dropping their
 // delegated resource until a receiver takes it or the endpoint retires.
 OWNERS.lock().unwrap().insert(7,(0,1));
 let(message,reference)=make_message(7,1,0,2);
 let result=send_to_thread_id_with_attachments(7,99,2,b"y".as_ptr()as u64,1,false,false,message.object_handles);
 assert_eq!(result,0);assert!(reference.upgrade().is_some());
 OWNERS.lock().unwrap().remove(&7);retire_endpoint(old);assert!(reference.upgrade().is_none());
 assert!(RETIRED.load(Ordering::SeqCst)>=55);

 // Queue saturation must return the rejected message to the sender. Its
 // resource destructor asserts that MAILBOXES is unlocked when it runs.
 OWNERS.lock().unwrap().insert(7,(0,1));
 let mut queued=Vec::new();
 for tag in 0..MAILBOX_CAP-1{
   let(mut message,reference)=make_message(7,1,0,500+tag as u64);
   message.is_reply=false;enqueue(0,message);queued.push(reference);
 }
 let(message,rejected)=make_message(7,1,0,600);
 let result=send_to_thread_id_with_attachments(7,99,600,b"z".as_ptr()as u64,1,false,false,message.object_handles);
 assert_eq!(result,Error::NotReady.into_raw());assert!(rejected.upgrade().is_none());
 {let boxes=MAILBOXES.lock();assert_eq!((boxes[0].count,boxes[0].free_count),(MAILBOX_CAP-1,1));}
 assert!(queued.iter().all(|reference|reference.upgrade().is_some()));

 // An ordinary message cannot consume the final reply reservation. A reply
 // can, but a fully occupied queue must reject both kinds without lock-held
 // destruction or disturbing any already enqueued authority.
 let(message,reply)=make_message(7,1,0,601);
 assert_eq!(send_to_thread_id_with_attachments(7,99,601,b"r".as_ptr()as u64,1,true,false,message.object_handles),0);
 assert!(reply.upgrade().is_some());
 for is_reply in [false,true]{
   let(message,rejected)=make_message(7,1,0,602);
   assert_eq!(send_to_thread_id_with_attachments(7,99,602,b"f".as_ptr()as u64,1,is_reply,false,message.object_handles),Error::NotReady.into_raw());
   assert!(rejected.upgrade().is_none());
   let boxes=MAILBOXES.lock();assert_eq!((boxes[0].count,boxes[0].free_count),(MAILBOX_CAP,0));
 }
 assert!(queued.iter().all(|reference|reference.upgrade().is_some()));
 OWNERS.lock().unwrap().remove(&7);retire_endpoint(old);
 assert!(queued.iter().all(|reference|reference.upgrade().is_none()));assert!(reply.upgrade().is_none());
 {let boxes=MAILBOXES.lock();assert_eq!((boxes[0].count,boxes[0].free_count),(0,MAILBOX_CAP));}

 // Admission and copy failures preserve native categories and consume no
 // queue entries. Even failure before message allocation releases authority.
 OWNERS.lock().unwrap().insert(7,(0,1));
 OWNERS.lock().unwrap().insert(8,(MAX_THREADS,1));
 for(to,pointer,length,error)in[
   (0,0,0,Error::InvalidArgument),
   (7,0,MAX_MSG_SIZE as u64+1,Error::LimitExceeded),
   (7,0,u64::MAX,Error::LimitExceeded),
   (7,0,1,Error::InvalidAddress),
   (99,0,0,Error::NotFound),
   (8,0,0,Error::BackingFailure),
 ]{
   let(message,reference)=make_message(to,1,0,700);
   assert_eq!(send_to_thread_id_with_attachments(to,99,700,pointer,length,false,false,message.object_handles),error.into_raw());
   assert!(reference.upgrade().is_none());assert_eq!(MAILBOXES.lock()[0].count,0);
 }
 for(code,error)in[(1,Error::InvalidAddress),(2,Error::ResourceUnavailable),(3,Error::BackingFailure)]{
   COPY_ERROR.store(code,Ordering::SeqCst);
   let(message,reference)=make_message(7,1,0,701);
   assert_eq!(send_to_thread_id_with_attachments(7,99,701,b"x".as_ptr()as u64,1,false,false,message.object_handles),error.into_raw());
   assert!(reference.upgrade().is_none());assert_eq!(MAILBOXES.lock()[0].count,0);
 }
 while let Some(message)=MESSAGE_CACHE.lock().take(){drop(message);}
 FAIL_ALLOC.store(true,Ordering::SeqCst);
 let(message,reference)=make_message(7,1,0,702);
 assert_eq!(send_to_thread_id_with_attachments(7,99,702,0,0,false,false,message.object_handles),Error::ResourceUnavailable.into_raw());
 assert!(!FAIL_ALLOC.load(Ordering::SeqCst));assert!(reference.upgrade().is_none());
 assert_eq!(MAILBOXES.lock()[0].count,0);
 // A zero-length message accepts a null data pointer and publishes normally.
 assert_eq!(send_to_thread_id_with_attachments(7,99,703,0,0,false,false,ObjectHandleAttachments::empty()),0);
 OWNERS.lock().unwrap().remove(&7);retire_endpoint(old);
}
"#);
    let directory = std::env::temp_dir().join(format!(
        "mochios-endpoint-queue-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&directory).unwrap();
    let binary = directory.join("probe");
    let mut compiler = Command::new("rustc")
        .args(["--edition=2024", "-Awarnings", "-"])
        .arg("-o")
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
    let executed = Command::new(&binary).output().unwrap();
    std::fs::remove_dir_all(directory).unwrap();
    assert!(
        executed.status.success(),
        "{}",
        String::from_utf8_lossy(&executed.stderr)
    );
}
