#[allow(dead_code)]
#[path = "support/native_error_probe.rs"]
mod probe;

#[test]
fn kernel_call_errors_retries_and_waiter_cleanup_keep_native_contracts() {
    let mut program = String::from(
        r#"
#![allow(dead_code)]
extern crate self as mnu_abi;
use std::{cell::Cell,sync::{Arc,Mutex,atomic::{AtomicU64,Ordering}},ops::{Deref,DerefMut}};
mod status {
"#,
    );
    program.push_str(include_str!("../../../core/crates/abi/src/status.rs"));
    program.push_str(r#"
}
use status::Error;
#[derive(Clone,Copy,Debug)]struct IpcEndpoint{thread_id:u64,slot:u16,generation:u64}
struct ObjectHandleAttachments{resource:Option<Arc<u64>>}
impl ObjectHandleAttachments{fn empty()->Self{Self{resource:None}}}
struct Message{from:u64,to:u64,to_slot:u16,to_generation:u64,is_reply:bool,expects_reply:bool,call_id:u64,len:usize,data:[u8;32],object_handles:ObjectHandleAttachments}
impl Message{fn new()->Self{Self{from:0,to:0,to_slot:0,to_generation:0,is_reply:false,expects_reply:false,call_id:0,len:0,data:[0;32],object_handles:ObjectHandleAttachments::empty()}}}
struct Mailbox{slots:[Option<Box<Message>>;1],waiter:u64}
impl Mailbox{
    fn new()->Self{Self{slots:[None],waiter:77}}
    fn alloc_slot(&mut self)->Option<usize>{
        ALLOCS.set(ALLOCS.get()+1);
        if QUEUE.get()==1&&ALLOCS.get()==1{return None;}
        if QUEUE.get()!=2{self.slots[0]=Some(Box::new(Message::new()));}Some(0)
    }
    fn quarantine(&mut self,_:&str){self.slots[0]=None;QUARANTINES.set(QUARANTINES.get()+1);}
    fn enqueue_slot(&mut self,slot:usize)->Result<(),()>{
        assert!(LOCKED.get());assert_eq!(slot,0);let message=self.slots[0].as_ref().unwrap();
        assert_eq!((message.from,message.to,message.to_slot,message.to_generation),(555,2,1,12));
        assert!(!message.is_reply);assert!(message.expects_reply);assert_eq!(&message.data[..message.len],b"request");
        assert_eq!(message.call_id,NEXT_CALL_ID.load(Ordering::Relaxed)-1);
        assert_eq!(Arc::strong_count(message.object_handles.resource.as_ref().unwrap()),2);
        ATTEMPTS.set(ATTEMPTS.get()+1);
        if QUEUE.get()==3&&ATTEMPTS.get()==1{return Err(());}
        if QUEUE.get()==4{self.slots[0]=None;return Err(());}
        ENQUEUED.set(ENQUEUED.get()+1);Ok(())
    }
    fn free_slot(&mut self,slot:usize){self.slots[slot]=None;}
    fn take_waiter(&mut self)->u64{let waiter=self.waiter;self.waiter=0;waiter}
    fn pop_reply_copy(&mut self,sender:u64,id:u64,receiver:u64,slot:u16,generation:u64,out:&mut[u8])->Option<(u64,usize)>{
        assert!(LOCKED.get());assert_eq!((sender,receiver,slot,generation),(999,1,0,11));
        assert_eq!(id,NEXT_CALL_ID.load(Ordering::Relaxed)-1);assert_eq!(OBSERVERS.get(),1);
        POLLS.set(POLLS.get()+1);
        if POLLS.get()<READY_AT.get(){return None;}
        if SLEEPS.get()>0&&!SLEEP_RESULT.get(){assert_eq!(self.waiter,0);}
        out[..3].copy_from_slice(b"yes");Some((sender,3))
    }
}
thread_local!{
    static CONTEXT:Cell<bool>=const{Cell::new(true)};
    static SENDER:Cell<bool>=const{Cell::new(true)};
    static TARGET:Cell<u8>=const{Cell::new(0)};
    static CALLER:Cell<bool>=const{Cell::new(true)};
    static VALID:Cell<bool>=const{Cell::new(true)};
    static VALID_CALLS:Cell<usize>=const{Cell::new(0)};
    static DIE_AT:Cell<usize>=const{Cell::new(0)};
    static DIE_ON_LOCK:Cell<bool>=const{Cell::new(false)};
    static LOCKED:Cell<bool>=const{Cell::new(false)};
    static QUEUE:Cell<u8>=const{Cell::new(0)};
    static ALLOCS:Cell<usize>=const{Cell::new(0)};
    static ATTEMPTS:Cell<usize>=const{Cell::new(0)};
    static ENQUEUED:Cell<usize>=const{Cell::new(0)};
    static QUARANTINES:Cell<usize>=const{Cell::new(0)};
    static POLLS:Cell<usize>=const{Cell::new(0)};
    static READY_AT:Cell<usize>=const{Cell::new(1)};
    static SLEEPS:Cell<usize>=const{Cell::new(0)};
    static SLEEP_RESULT:Cell<bool>=const{Cell::new(false)};
    static YIELDS:Cell<usize>=const{Cell::new(0)};
    static WAKES:Cell<usize>=const{Cell::new(0)};
    static OBSERVERS:Cell<usize>=const{Cell::new(0)};
    static OBSERVE_ERROR:Cell<Option<Error>>=const{Cell::new(None)};
}
static MAILBOXES:Mutex<Vec<Mailbox>>=Mutex::new(Vec::new());
static NEXT_CALL_ID:AtomicU64=AtomicU64::new(10);
struct Guard(std::sync::MutexGuard<'static,Vec<Mailbox>>);
impl Deref for Guard{type Target=Vec<Mailbox>;fn deref(&self)->&Self::Target{&self.0}}
impl DerefMut for Guard{fn deref_mut(&mut self)->&mut Self::Target{&mut self.0}}
impl Drop for Guard{fn drop(&mut self){assert!(LOCKED.replace(false));}}
fn lock_mailboxes()->Guard{
    assert!(!LOCKED.replace(true));if DIE_ON_LOCK.replace(false){VALID.set(false);}
    Guard(MAILBOXES.lock().unwrap())
}
fn ipc_max_msg_size()->usize{32}
fn record_ipc_copy(length:usize){assert_eq!(length,7);}
fn ensure_endpoint_for_thread(id:u64)->Option<u64>{assert_eq!(id,1);SENDER.get().then_some(555)}
fn endpoint_is_valid(endpoint:IpcEndpoint)->bool{
    assert_eq!((endpoint.thread_id,endpoint.slot,endpoint.generation),(2,1,12));
    VALID_CALLS.set(VALID_CALLS.get()+1);
    VALID.get()&&(DIE_AT.get()==0||VALID_CALLS.get()<DIE_AT.get())
}
mod task{
    #[derive(Clone,Copy)]pub struct ThreadId(u64);
    impl ThreadId{pub fn as_u64(self)->u64{self.0}pub fn from_u64(value:u64)->Self{Self(value)}}
    pub fn current_thread_id()->Option<ThreadId>{crate::CONTEXT.get().then_some(ThreadId(1))}
    pub fn thread_slot_index_and_generation_by_u64(id:u64)->Option<(usize,u64)>{
        if id==1{return crate::CALLER.get().then_some((0,11));}
        assert_eq!(id,2);match crate::TARGET.get(){0=>Some((1,12)),1=>None,2=>Some((1,13)),_=>Some((2,12))}
    }
    pub fn wake_registered_waiter(id:ThreadId){assert_eq!(id.0,77);assert!(!crate::LOCKED.get());crate::WAKES.set(crate::WAKES.get()+1);}
    pub fn yield_now(){assert!(!crate::LOCKED.get());crate::YIELDS.set(crate::YIELDS.get()+1);assert!(crate::YIELDS.get()<4);}
    pub fn sleep_thread_unless_woken(id:ThreadId)->bool{
        assert_eq!(id.0,1);assert!(!crate::LOCKED.get());assert_eq!(crate::MAILBOXES.lock().unwrap()[0].waiter,1);
        crate::SLEEPS.set(crate::SLEEPS.get()+1);crate::SLEEP_RESULT.get()
    }
}
mod lifetime{
    pub struct Observation;
    impl Drop for Observation{fn drop(&mut self){assert_eq!(crate::OBSERVERS.replace(0),1);}}
    pub fn observe(_:crate::IpcEndpoint,_:crate::task::ThreadId)->Result<Observation,u64>{
        if let Some(error)=crate::OBSERVE_ERROR.get(){return Err(error.into_raw());}
        assert_eq!(crate::OBSERVERS.replace(1),0);Ok(Observation)
    }
}
"#);
    program.push_str(probe::between(
        include_str!("../../../core/src/syscall/ipc.rs"),
        "fn call_endpoint_with_attachments_from_kernel(",
        "fn send_to_endpoint(",
    ));
    program.push_str(r#"
fn reset(){
    CONTEXT.set(true);SENDER.set(true);TARGET.set(0);CALLER.set(true);VALID.set(true);
    VALID_CALLS.set(0);DIE_AT.set(0);DIE_ON_LOCK.set(false);QUEUE.set(0);ALLOCS.set(0);
    ATTEMPTS.set(0);ENQUEUED.set(0);QUARANTINES.set(0);POLLS.set(0);READY_AT.set(1);
    SLEEPS.set(0);SLEEP_RESULT.set(false);YIELDS.set(0);WAKES.set(0);OBSERVE_ERROR.set(None);
    assert_eq!(OBSERVERS.get(),0);assert!(!LOCKED.get());
    *MAILBOXES.lock().unwrap()=vec![Mailbox::new(),Mailbox::new()];
}
fn invoke(request:&[u8],reply:&mut[u8])->Result<usize,u64>{
    let resource=Arc::new(42);
    let result=call_endpoint_with_attachments_from_kernel(
        IpcEndpoint{thread_id:2,slot:1,generation:12},999,request,reply,
        ObjectHandleAttachments{resource:Some(resource.clone())}
    );
    assert_eq!(OBSERVERS.get(),0);assert!(!LOCKED.get());
    MAILBOXES.lock().unwrap().clear();assert_eq!(Arc::strong_count(&resource),1);
    result
}
fn main(){
    let mut reply=[0u8;16];
    for mode in 0..10{
        reset();
        let expected=match mode{
            0=>{CONTEXT.set(false);Error::NotReady},
            1=>{SENDER.set(false);Error::NotReady},
            2=>{CALLER.set(false);Error::NotReady},
            3..=5=>{TARGET.set(mode-2);Error::NotFound},
            6=>{VALID.set(false);Error::NotFound},
            7=>{DIE_ON_LOCK.set(true);Error::NotFound},
            8=>{MAILBOXES.lock().unwrap().clear();Error::BackingFailure},
            _=>{QUEUE.set(2);Error::BackingFailure},
        };
        assert_eq!(invoke(b"request",&mut reply),Err(expected.into_raw()));assert_eq!(ENQUEUED.get(),0);
    }
    reset();assert_eq!(invoke(&[0;33],&mut reply),Err(Error::LimitExceeded.into_raw()));
    reset();assert_eq!(invoke(b"request",&mut [0;33]),Err(Error::LimitExceeded.into_raw()));
    for error in [Error::NotReady,Error::NotFound,Error::ResourceUnavailable]{
        reset();OBSERVE_ERROR.set(Some(error));assert_eq!(invoke(b"request",&mut reply),Err(error.into_raw()));
        assert_eq!(ENQUEUED.get(),0);
    }
    for mode in [0,1,3]{
        reset();QUEUE.set(mode);assert_eq!(invoke(b"request",&mut reply),Ok(3));assert_eq!(&reply[..3],b"yes");
        assert_eq!(ENQUEUED.get(),1);assert_eq!(WAKES.get(),1);
        assert_eq!(YIELDS.get(),usize::from(mode!=0));
    }
    reset();QUEUE.set(4);assert_eq!(invoke(b"request",&mut reply),Err(Error::BackingFailure.into_raw()));
    for sleep_result in [false,true]{
        reset();READY_AT.set(2);SLEEP_RESULT.set(sleep_result);
        assert_eq!(invoke(b"request",&mut reply),Ok(3));assert_eq!(SLEEPS.get(),1);
        assert_eq!(YIELDS.get(),usize::from(sleep_result));
    }
    reset();READY_AT.set(2);DIE_AT.set(3);
    // Check waiter cleanup before the fixture drops its mailbox storage.
    let resource=Arc::new(42);
    assert_eq!(call_endpoint_with_attachments_from_kernel(
        IpcEndpoint{thread_id:2,slot:1,generation:12},999,b"request",&mut reply,
        ObjectHandleAttachments{resource:Some(resource.clone())}),Err(Error::NotFound.into_raw()));
    assert_eq!(MAILBOXES.lock().unwrap()[0].waiter,0);assert_eq!(OBSERVERS.get(),0);
    MAILBOXES.lock().unwrap().clear();assert_eq!(Arc::strong_count(&resource),1);
}
"#);
    probe::run(&program);
}
