use std::io::Write;
use std::process::{Command, Stdio};

#[test]
fn production_message_wiping_releases_owned_attachments_before_cache_reuse() {
    let source = include_str!("../../../core/src/syscall/ipc.rs");
    let start = source
        .find("#[derive(Debug)]\nstruct ObjectHandleAttachments")
        .unwrap();
    let end = source[start..]
        .find("#[derive(Clone, Copy, Debug, PartialEq, Eq)]")
        .unwrap()
        + start;
    let cache = source.find("struct MessageCache {").unwrap();
    let cache_end = source[cache..].find("fn allocate_message(").unwrap() + cache;
    let mut program = String::from(
        r#"
use std::sync::{Arc,Mutex,atomic::{AtomicUsize,Ordering}};
const MAX_OBJECT_HANDLES:usize=4;
const MAX_MSG_SIZE:usize=256;
const MESSAGE_CACHE_CAP:usize=2;
static DROPPED:AtomicUsize=AtomicUsize::new(0);
static AUDITS:AtomicUsize=AtomicUsize::new(0);
#[derive(Debug)]struct Resource;
impl Drop for Resource {fn drop(&mut self){DROPPED.fetch_add(1,Ordering::SeqCst);}}
#[derive(Debug)]struct ObjectHandleEntry(Arc<Resource>);
mod audit {
 pub enum AuditEventKind{Quarantine}
 pub fn log(_:AuditEventKind,_:&str){crate::AUDITS.fetch_add(1,crate::Ordering::SeqCst);}
}
struct Lock<T>(Mutex<T>);
impl<T>Lock<T>{const fn new(value:T)->Self{Self(Mutex::new(value))}fn lock(&self)->std::sync::MutexGuard<'_,T>{self.0.lock().unwrap()}}
"#,
    );
    program.push_str(&source[start..end]);
    program.push_str(&source[cache..cache_end]);
    program.push_str(r#"
static MESSAGE_CACHE:Lock<MessageCache>=Lock::new(MessageCache::new());
fn owned()->Box<Message>{
 let mut message=Box::new(Message::empty());
 message.from=11;message.to=22;message.to_slot=3;message.to_generation=4;
 message.is_reply=true;message.expects_reply=true;message.call_id=5;
 message.len=MAX_MSG_SIZE;message.data.fill(0x55);
 message.object_handles.count=MAX_OBJECT_HANDLES;
 message.object_handles.delivery_flags=3;
 for slot in &mut message.object_handles.handles{*slot=Some(ObjectHandleEntry(Arc::new(Resource)));}
 message
}
fn empty(message:&Message){
 assert_eq!((message.from,message.to,message.to_slot,message.to_generation,message.call_id,message.len),(0,0,0,0,0,0));
 assert!(!message.is_reply&&!message.expects_reply);
 assert!(message.data.iter().all(|byte|*byte==0));
 assert_eq!((message.object_handles.count,message.object_handles.delivery_flags),(0,0));
 assert!(message.object_handles.handles.iter().all(Option::is_none));
}
fn main(){
 let message=owned();let pointer=message.as_ref() as *const Message;
 let wiped=wipe_message(message);
 assert_eq!(DROPPED.load(Ordering::SeqCst),4,"overwriting owned handles must run their destructors");
 assert_eq!(wiped.as_ref() as *const Message,pointer);empty(&wiped);
 drop(wiped);assert_eq!(DROPPED.load(Ordering::SeqCst),4);

 // A normal receive has moved authority out before freeing its queue slot.
 let mut message=owned();
 let transferred=std::mem::replace(&mut message.object_handles,ObjectHandleAttachments::empty());
 let wiped=wipe_message(message);empty(&wiped);
 assert_eq!(DROPPED.load(Ordering::SeqCst),4,"transferred attachments are owned by the receiver");
 drop(wiped);drop(transferred);
 assert_eq!(DROPPED.load(Ordering::SeqCst),8);

 // The ordinary discard path must release before a cached allocation is taken.
 for expected in [12,16]{
   release_message(owned());
   assert_eq!(DROPPED.load(Ordering::SeqCst),expected);
   let cached=MESSAGE_CACHE.lock().take().unwrap();empty(&cached);drop(cached);
   assert_eq!(DROPPED.load(Ordering::SeqCst),expected);
 }
 // A full cache returns the extra allocation to the allocator, also wiped.
 release_message(owned());release_message(owned());release_message(owned());
 assert_eq!(DROPPED.load(Ordering::SeqCst),28);
 while let Some(message)=MESSAGE_CACHE.lock().take(){empty(&message);drop(message);}
 assert_eq!(DROPPED.load(Ordering::SeqCst),28);

 // Quarantine can encounter owned references even in inconsistent metadata.
 let mut cache=MessageCache::new();
 cache.slots[0]=Some(owned());cache.slots[1]=Some(owned());cache.count=2;
 cache.quarantine("test");
 assert_eq!(DROPPED.load(Ordering::SeqCst),36);
 assert_eq!(cache.count,0);assert!(cache.slots.iter().all(Option::is_none));
 assert_eq!(AUDITS.load(Ordering::SeqCst),1);

 // Multiple attachments can refer to one object; only its final reference dies.
 let resource=Arc::new(Resource);let weak=Arc::downgrade(&resource);
 let mut message=Box::new(Message::empty());
 message.object_handles.count=2;
 message.object_handles.handles[0]=Some(ObjectHandleEntry(resource.clone()));
 message.object_handles.handles[1]=Some(ObjectHandleEntry(resource.clone()));
 drop(resource);drop(wipe_message(message));
 assert!(weak.upgrade().is_none());assert_eq!(DROPPED.load(Ordering::SeqCst),37);
 // Corrupt count metadata cannot hide owned array entries from destruction.
 for (count,expected) in [(0,41),(usize::MAX,45)] {
   let mut message=owned();message.object_handles.count=count;
   drop(wipe_message(message));assert_eq!(DROPPED.load(Ordering::SeqCst),expected);
 }
}
"#);
    let directory = std::env::temp_dir().join(format!(
        "mochios-message-release-{}-{}",
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
