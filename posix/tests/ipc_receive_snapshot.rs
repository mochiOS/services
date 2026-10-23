#[allow(dead_code)]
#[path = "support/native_error_probe.rs"]
mod probe;

#[test]
fn snapshot_usercopy_runs_unlocked_and_commit_rejects_retirement_and_slot_reuse() {
    let source = include_str!("../../../core/src/syscall/ipc.rs");
    let mut program = probe::program();
    program.push_str(r#"
use std::{cell::{Cell,RefCell},collections::VecDeque,ops::{Deref,DerefMut},sync::{Arc,Weak,Mutex,atomic::{AtomicU64,Ordering}}};
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
    static PEER_VALID:Cell<bool>=const{Cell::new(true)};
    static INJECT_ON_UNLOCK:Cell<bool>=const{Cell::new(false)};
    static SLEEP_ACTIONS:RefCell<VecDeque<(bool,u8)>>=const{RefCell::new(VecDeque::new())};
    static SLEEPS:Cell<usize>=const{Cell::new(0)};
    static YIELDS:Cell<usize>=const{Cell::new(0)};
    static REPLY:Cell<bool>=const{Cell::new(false)};
}
#[derive(Debug)]struct Resource;
impl Drop for Resource{fn drop(&mut self){assert!(MAILBOXES.try_lock().is_ok(),"resource destructor held mailbox lock");}}
#[derive(Debug)]struct ObjectHandleEntry(Arc<Resource>);
#[derive(Clone,Copy)]struct IpcEndpoint{thread_id:u64,slot:u16,generation:u64}
fn endpoint()->IpcEndpoint{IpcEndpoint{thread_id:7,slot:0,generation:3}}
fn endpoint_is_valid(e:IpcEndpoint)->bool{
    if e.thread_id==19{return PEER_VALID.get()&&e.slot==1&&e.generation==4;}
    VALID.get()&&e.thread_id==7&&e.slot==0&&e.generation==3
}
mod task{
    pub struct ThreadId(u64);impl ThreadId{pub fn from_u64(id:u64)->Self{Self(id)}}
    pub fn ipc_slot_index_and_generation_by_u64(id:u64)->Option<(usize,u64)>{assert_eq!(id,7);Some((0,3))}
    pub fn yield_now(){assert!(crate::MAILBOXES.try_lock().is_ok());crate::YIELDS.set(crate::YIELDS.get()+1);}
    pub fn sleep_thread_unless_woken(thread:ThreadId)->bool{
        assert_eq!(thread.0,7);assert!(crate::MAILBOXES.try_lock().is_ok(),"park held mailbox lock");
        assert_eq!(crate::lock_mailboxes()[0].waiter,7);crate::SLEEPS.set(crate::SLEEPS.get()+1);
        let(result,action)=crate::SLEEP_ACTIONS.with_borrow_mut(|q|q.pop_front().expect("unexpected park"));
        match action{1=>crate::arrive(false),2=>crate::PEER_VALID.set(false),3=>crate::arrive(true),_=>{}}
        result
    }
}
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
struct Guard(Option<std::sync::MutexGuard<'static,[Mailbox;MAX_THREADS]>>);
impl Deref for Guard{type Target=[Mailbox;MAX_THREADS];fn deref(&self)->&Self::Target{self.0.as_ref().unwrap()}}
impl DerefMut for Guard{fn deref_mut(&mut self)->&mut Self::Target{self.0.as_mut().unwrap()}}
impl Drop for Guard{fn drop(&mut self){
    let inject=INJECT_ON_UNLOCK.get()&&self[0].waiter==7;drop(self.0.take());
    if inject{INJECT_ON_UNLOCK.set(false);arrive(false);}
}}
fn lock_mailboxes()->Guard{Guard(Some(MAILBOXES.lock().unwrap()))}
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
fn arrive(unrelated:bool){
    let(mut message,weak)=make_message();message.is_reply=REPLY.get();
    if unrelated{message.from=42;message.is_reply=false;message.call_id=56;}
    MAILBOXES.lock().unwrap()[0].enqueue_message(message).unwrap();REPLACEMENT.set(Some(weak));
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
            4=>{crate::VALID.set(false);crate::retire();crate::lock_mailboxes()[0].waiter=99;},
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
    INJECT_ON_UNLOCK.set(false);let discarded={let mut boxes=lock_mailboxes();std::mem::replace(&mut boxes[0],Mailbox::new())};drop(discarded);
    VALID.set(true);FAIL_ALLOC.set(false);COPY_ERROR.set(None);RACE.set(0);COPIES.set(0);REPLACEMENT.set(None);
    PEER_VALID.set(true);INJECT_ON_UNLOCK.set(false);SLEEP_ACTIONS.with_borrow_mut(|q|q.clear());SLEEPS.set(0);YIELDS.set(0);REPLY.set(false);lock_mailboxes()[0].waiter=0;
    let(message,weak)=make_message();lock_mailboxes()[0].enqueue_message(message).unwrap();weak
}
fn copy(output:&mut[u8;3])->Result<Option<UserReceive>,u64>{receive::copy_message(endpoint(),7,output.as_mut_ptr()as u64,3,true)}
fn wait(output:&mut[u8;3],reply:bool)->Result<UserReceive,u64>{
    receive::wait_message(endpoint(),7,output.as_mut_ptr()as u64,3,true,
        reply.then_some((41,55,IpcEndpoint{thread_id:19,slot:1,generation:4})))
}
fn main(){
    let mut output=[0u8;3];
    for error in [Error::InvalidAddress,Error::ResourceUnavailable,Error::BackingFailure]{
        let weak=reset();COPY_ERROR.set(Some(error));let id=lock_mailboxes()[0].slots[3].as_ref().unwrap().message_id;
        assert!(matches!(copy(&mut output),Err(status)if status==error.into_raw()));assert!(weak.upgrade().is_some());
        {let boxes=lock_mailboxes();assert_eq!((boxes[0].count,boxes[0].free_count),(1,3));assert_eq!(boxes[0].slots[3].as_ref().unwrap().message_id,id);assert!(boxes[0].reply_targets.is_empty());}
        let received=copy(&mut output).unwrap().unwrap();assert_eq!(output,*b"abc");assert_eq!((received.from,received.copy_len),(41,3));
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

    for reply in [false,true]{
        // Arrival after waiter publication but before the second queue check
        // must complete without parking, and copies remain outside the lock.
        reset();retire();REPLY.set(reply);INJECT_ON_UNLOCK.set(true);
        drop(wait(&mut output,reply).unwrap());assert_eq!((SLEEPS.get(),YIELDS.get()),(0,0));assert_eq!(lock_mailboxes()[0].waiter,0);
        // A latched wake declines the sleep transition. The opposite branch
        // parks then yields; both must retry rather than return an empty result.
        for parked in [false,true]{
            reset();retire();REPLY.set(reply);SLEEP_ACTIONS.with_borrow_mut(|q|q.push_back((parked,1)));
            drop(wait(&mut output,reply).unwrap());assert_eq!((SLEEPS.get(),YIELDS.get()),(1,usize::from(parked)));
            assert_eq!(lock_mailboxes()[0].waiter,0);
        }
        for error in [Error::InvalidAddress,Error::ResourceUnavailable,Error::BackingFailure]{
            let weak=reset();REPLY.set(reply);{let mut boxes=lock_mailboxes();for message in boxes[0].slots.iter_mut().flatten(){message.is_reply=reply;}}
            COPY_ERROR.set(Some(error));lock_mailboxes()[0].waiter=7;
            assert!(matches!(wait(&mut output,reply),Err(e)if e==error.into_raw()));assert!(weak.upgrade().is_some());assert_eq!(lock_mailboxes()[0].waiter,0);
        }
    }
    // Unrelated ordinary messages and wakeups cannot abort a delivered RPC.
    reset();retire();REPLY.set(true);SLEEP_ACTIONS.with_borrow_mut(|q|q.extend([(false,3),(true,1)]));
    let received=wait(&mut output,true).unwrap();assert!(!received.expects_reply);drop(received);
    assert_eq!((SLEEPS.get(),YIELDS.get()),(2,1));assert_eq!(lock_mailboxes()[0].count,1);assert!(lock_mailboxes()[0].reply_targets.is_empty());
    reset();retire();REPLY.set(true);SLEEP_ACTIONS.with_borrow_mut(|q|q.push_back((false,2)));
    assert!(matches!(wait(&mut output,true),Err(e)if e==Error::NotFound.into_raw()));assert_eq!(lock_mailboxes()[0].waiter,0);
    // Sender, call ID, destination generation and reply marker all matter.
    reset();retire();
    for selector in 0..3{let(mut message,_)=make_message();message.is_reply=true;
        match selector{0=>message.from=42,1=>message.call_id=56,_=>message.to_generation=4};lock_mailboxes()[0].enqueue_message(message).unwrap();}
    let(mut message,_)=make_message();message.is_reply=true;lock_mailboxes()[0].enqueue_message(message).unwrap();
    drop(wait(&mut output,true).unwrap());assert_eq!(lock_mailboxes()[0].count,3);assert_eq!(SLEEPS.get(),0);
    for (sender,call_id) in [(42,55),(41,56)]{
        drop(receive::wait_message(endpoint(),7,output.as_mut_ptr()as u64,3,true,Some((sender,call_id,IpcEndpoint{thread_id:19,slot:1,generation:4}))).unwrap());
    }
    assert_eq!(lock_mailboxes()[0].count,1);
    let weak=reset();{let mut boxes=lock_mailboxes();for message in boxes[0].slots.iter_mut().flatten(){message.is_reply=true;message.len=0;}}
    let selection=Some((41,55,IpcEndpoint{thread_id:19,slot:1,generation:4}));
    assert!(matches!(receive::wait_message(endpoint(),7,0,0,false,selection),Err(e)if e==Error::LimitExceeded.into_raw()));
    assert!(weak.upgrade().is_some());assert_eq!(lock_mailboxes()[0].count,1);assert_eq!(lock_mailboxes()[0].waiter,0);
    let received=receive::wait_message(endpoint(),7,0,0,true,selection).unwrap();assert_eq!((received.copy_len,received.object_handles.count),(0,1));drop(received);assert!(weak.upgrade().is_none());
    // A delayed waiter cleanup must not clear a new owner's waiter.
    reset();RACE.set(4);assert!(matches!(wait(&mut output,false),Err(e)if e==Error::NotFound.into_raw()));assert_eq!(lock_mailboxes()[0].waiter,99);
    reset();retire();
    // Exhaustion cannot wrap identities and turn a delayed commit into ABA.
    NEXT_MESSAGE_ID.store(u64::MAX,Ordering::Relaxed);let(message,weak)=make_message();
    let rejected=lock_mailboxes()[0].enqueue_message(message).unwrap_err().unwrap();release_message(rejected);
    assert!(weak.upgrade().is_none());{let boxes=lock_mailboxes();assert_eq!((boxes[0].count,boxes[0].free_count),(0,4));}
}
"#);
    probe::run(&program);
}
