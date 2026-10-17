#[allow(dead_code)]
#[path = "support/native_error_probe.rs"]
mod probe;

#[test]
fn snapshot_usercopy_runs_unlocked_and_commit_rejects_retirement_and_slot_reuse() {
    let source = include_str!("../../../core/src/syscall/ipc.rs");
    let mut program = probe::program();
    program.push_str(r#"
use std::{cell::{Cell,RefCell},sync::{Arc,Weak,Mutex,atomic::{AtomicU64,Ordering}}};
use mnu_abi::status::Error;
const MAX_OBJECT_HANDLES:usize=4;const MAX_MSG_SIZE:usize=32;const MAILBOX_CAP:usize=4;const MAX_THREADS:usize=2;
static NEXT_MESSAGE_ID:AtomicU64=AtomicU64::new(1);
thread_local!{
    static VALID:Cell<bool>=const{Cell::new(true)};
    static FAIL_ALLOC:Cell<bool>=const{Cell::new(false)};
    static COPY_ERROR:Cell<Option<Error>>=const{Cell::new(None)};
    static RACE:Cell<u8>=const{Cell::new(0)};
    static COPIES:Cell<usize>=const{Cell::new(0)};
    static REPLACEMENT:RefCell<Option<Weak<Resource>>>=const{RefCell::new(None)};
}
#[derive(Debug)]struct Resource;
impl Drop for Resource{fn drop(&mut self){assert!(MAILBOXES.try_lock().is_ok(),"resource destructor held mailbox lock");}}
#[derive(Debug)]struct ObjectHandleEntry(Arc<Resource>);
#[derive(Clone,Copy)]struct IpcEndpoint{thread_id:u64,slot:u16,generation:u64}
fn endpoint()->IpcEndpoint{IpcEndpoint{thread_id:7,slot:0,generation:3}}
fn endpoint_is_valid(e:IpcEndpoint)->bool{VALID.get()&&e.thread_id==7&&e.slot==0&&e.generation==3}
mod task{pub fn thread_slot_index_and_generation_by_u64(id:u64)->Option<(usize,u64)>{assert_eq!(id,7);Some((0,3))}}
mod audit{pub enum AuditEventKind{Quarantine}pub fn log(_:AuditEventKind,reason:&str){panic!("unexpected quarantine: {reason}");}}
fn ipc_mailbox_cap()->usize{MAILBOX_CAP}
fn record_ipc_copy(_:usize){}
"#);
    program.push_str(probe::between(
        source,
        "#[derive(Debug)]\nstruct ObjectHandleAttachments",
        "    fn push_message(",
    ));
    program.push_str(r#"
}
static MAILBOXES:Mutex<[Mailbox;MAX_THREADS]>=Mutex::new([const{Mailbox::new()};MAX_THREADS]);
fn lock_mailboxes()->std::sync::MutexGuard<'static,[Mailbox;MAX_THREADS]>{MAILBOXES.lock().unwrap()}
fn allocate_message()->Option<Box<Message>>{if FAIL_ALLOC.replace(false){None}else{Some(Box::new(Message::empty()))}}
fn release_message(message:Box<Message>){assert!(MAILBOXES.try_lock().is_ok());drop(message);}
fn make_message()->(Box<Message>,Weak<Resource>){
    let mut message=Box::new(Message::empty());message.from=41;message.to=7;message.to_generation=3;message.call_id=55;
    message.len=3;message.data[..3].copy_from_slice(b"abc");message.expects_reply=true;
    let resource=Arc::new(Resource);let weak=Arc::downgrade(&resource);message.object_handles.count=1;
    message.object_handles.delivery_flags=2;message.object_handles.handles[0]=Some(ObjectHandleEntry(resource));(message,weak)
}
fn retire(){
    let messages=lock_mailboxes()[0].retire_destination(endpoint());
    for message in messages.into_iter().flatten(){release_message(message);}
}
mod syscall{
    pub fn copy_to_user_native(pointer:u64,bytes:&[u8])->Result<(),crate::Error>{
        assert!(crate::MAILBOXES.try_lock().is_ok(),"usercopy held mailbox lock");
        crate::COPIES.set(crate::COPIES.get()+1);
        {let boxes=crate::lock_mailboxes();let mailbox=&boxes[0];
         for offset in 0..mailbox.count{
            let slot=mailbox.queue[(mailbox.head+offset)%crate::MAILBOX_CAP]as usize;
            if let Some(message)=&mailbox.slots[slot]{
                if let Some(entry)=&message.object_handles.handles[0]{assert_eq!(crate::Arc::strong_count(&entry.0),1,"snapshot cloned authority");}
            }
         }
        }
        if let Some(error)=crate::COPY_ERROR.take(){return Err(error);}
        match crate::RACE.replace(0){
            1=>{crate::VALID.set(false);crate::retire();},
            2=>{crate::retire();let(message,weak)=crate::make_message();crate::lock_mailboxes()[0].enqueue_message(message).unwrap();crate::REPLACEMENT.set(Some(weak));},
            3=>{let(mut message,weak)=crate::make_message();message.call_id=56;message.expects_reply=false;
                crate::lock_mailboxes()[0].enqueue_message(message).unwrap();crate::REPLACEMENT.set(Some(weak));},
            _=>{},
        }
        if bytes.is_empty(){return Ok(());}
        if pointer==0{return Err(crate::Error::InvalidAddress);}
        unsafe{std::ptr::copy_nonoverlapping(bytes.as_ptr(),pointer as *mut u8,bytes.len());}Ok(())
    }
}
mod receive{
use crate::mnu_abi;
"#);
    // Load the complete production module, including its actual commit path.
    program.push_str(
        include_str!("../../../core/src/syscall/ipc/receive.rs")
            .lines()
            .filter(|line| !line.starts_with("//!"))
            .collect::<Vec<_>>()
            .join("\n")
            .as_str(),
    );
    program.push_str(r#"
}
fn reset()->Weak<Resource>{
    retire();VALID.set(true);FAIL_ALLOC.set(false);COPY_ERROR.set(None);RACE.set(0);COPIES.set(0);REPLACEMENT.set(None);
    let(message,weak)=make_message();lock_mailboxes()[0].enqueue_message(message).unwrap();weak
}
fn copy(output:&mut[u8;3])->Result<Option<UserReceive>,u64>{receive::copy_message(endpoint(),7,output.as_mut_ptr()as u64,3,true)}
fn main(){
    let mut output=[0u8;3];
    for error in [Error::InvalidAddress,Error::ResourceUnavailable,Error::BackingFailure]{
        let weak=reset();COPY_ERROR.set(Some(error));let id=lock_mailboxes()[0].slots[3].as_ref().unwrap().message_id;
        assert!(matches!(copy(&mut output),Err(status)if status==error.into_raw()));assert!(weak.upgrade().is_some());
        {let boxes=lock_mailboxes();assert_eq!((boxes[0].count,boxes[0].free_count),(1,3));assert_eq!(boxes[0].slots[3].as_ref().unwrap().message_id,id);assert!(boxes[0].reply_targets.is_empty());}
        let received=copy(&mut output).unwrap().unwrap();assert_eq!(output,*b"abc");assert_eq!((received.from,received.copy_len,received.call_id),(41,3,55));
        assert_eq!((received.object_handles.count,received.object_handles.delivery_flags),(1,2));assert!(weak.upgrade().is_some());
        assert_eq!(lock_mailboxes()[0].reply_target(41,(7,3)).unwrap().call_id,55);drop(received);assert!(weak.upgrade().is_none());
    }
    let weak=reset();FAIL_ALLOC.set(true);assert!(matches!(copy(&mut output),Err(status)if status==Error::ResourceUnavailable.into_raw()));
    assert_eq!(COPIES.get(),0);assert!(weak.upgrade().is_some());assert_eq!(lock_mailboxes()[0].count,1);
    let weak=reset();assert!(matches!(receive::copy_message(endpoint(),7,0,3,false),Err(status)if status==Error::LimitExceeded.into_raw()));
    assert_eq!(COPIES.get(),0);assert!(weak.upgrade().is_some());
    for race in [1,2]{
        let weak=reset();RACE.set(race);assert!(matches!(copy(&mut output),Err(status)if status==Error::NotFound.into_raw()));
        assert!(weak.upgrade().is_none());assert!(lock_mailboxes()[0].reply_targets.is_empty());
        if race==2{assert!(REPLACEMENT.with_borrow(|w|w.as_ref().unwrap().upgrade().is_some()));assert_eq!(lock_mailboxes()[0].count,1);}
    }
    let weak=reset();RACE.set(3);drop(copy(&mut output).unwrap().unwrap());assert!(weak.upgrade().is_none());
    assert_eq!(lock_mailboxes()[0].count,1);assert!(REPLACEMENT.with_borrow(|w|w.as_ref().unwrap().upgrade().is_some()));
    let weak=reset();assert!(matches!(receive::copy_message(endpoint(),7,0,3,true),Err(status)if status==Error::InvalidAddress.into_raw()));assert!(weak.upgrade().is_some());
    drop(receive::copy_message(endpoint(),7,0,0,true).unwrap().unwrap());assert!(weak.upgrade().is_none());
    assert!(receive::copy_message(endpoint(),7,0,3,true).unwrap().is_none());
    // Exhaustion cannot wrap identities and turn a delayed commit into ABA.
    NEXT_MESSAGE_ID.store(u64::MAX,Ordering::Relaxed);let(message,weak)=make_message();
    let rejected=lock_mailboxes()[0].enqueue_message(message).unwrap_err().unwrap();release_message(rejected);
    assert!(weak.upgrade().is_none());{let boxes=lock_mailboxes();assert_eq!((boxes[0].count,boxes[0].free_count),(0,4));}
}
"#);
    probe::run(&program);
}
