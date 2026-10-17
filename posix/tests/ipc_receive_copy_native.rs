#[allow(dead_code)]
#[path = "support/native_error_probe.rs"]
mod probe;

#[test]
fn receive_copy_failures_keep_messages_and_attenuated_authority_retryable() {
    let source = include_str!("../../../core/src/syscall/ipc.rs");
    let mut program = probe::program();
    program.push_str(r#"
use std::{cell::Cell,sync::{Arc,atomic::{AtomicU64,AtomicUsize,Ordering}}};
static NEXT_MESSAGE_ID:AtomicU64=AtomicU64::new(1);
use mnu_abi::status::Error;
const MAX_OBJECT_HANDLES:usize=4;const MAX_MSG_SIZE:usize=32;const MAILBOX_CAP:usize=4;
static DROPPED:AtomicUsize=AtomicUsize::new(0);
thread_local!{static COPY_ERROR:Cell<Option<Error>>=const{Cell::new(None)};static COPIES:Cell<usize>=const{Cell::new(0)};}
#[derive(Debug)]struct Resource;
impl Drop for Resource{fn drop(&mut self){DROPPED.fetch_add(1,Ordering::SeqCst);}}
#[derive(Debug)]struct ObjectHandleEntry(Arc<Resource>);
#[derive(Clone,Copy)]struct IpcEndpoint{thread_id:u64,slot:u16,generation:u64}
mod audit{pub enum AuditEventKind{Quarantine}pub fn log(_:AuditEventKind,reason:&str){panic!("unexpected quarantine: {reason}");}}
mod syscall{
    pub fn copy_to_user_native(pointer:u64,bytes:&[u8])->Result<(),crate::Error>{
        crate::COPIES.set(crate::COPIES.get()+1);
        if pointer==0{return Err(crate::Error::InvalidAddress);}
        if let Some(error)=crate::COPY_ERROR.take(){return Err(error);}
        unsafe{std::ptr::copy_nonoverlapping(bytes.as_ptr(),pointer as *mut u8,bytes.len());}Ok(())
    }
}
fn ipc_mailbox_cap()->usize{MAILBOX_CAP}
fn record_ipc_copy(_:usize){}
"#);
    program.push_str(probe::between(
        source,
        "#[derive(Debug)]\nstruct ObjectHandleAttachments",
        "    fn add_reply_target(",
    ));
    program.push_str(probe::between(
        source,
        "    fn reserve_slot(",
        "    fn push_message(",
    ));
    program.push_str(probe::between(
        source,
        "    fn pop_valid_for_receiver_to_user(",
        "    /// 指定送信元からの有効メッセージ",
    ));
    program.push_str(probe::between(
        source,
        "    fn pop_reply_to_user(",
        "    fn pop_reply_copy(",
    ));
    program.push_str(r#"
}
fn allocate_message()->Option<Box<Message>>{Some(Box::new(Message::empty()))}
fn release_message(message:Box<Message>){drop(message);}
fn make_message(reply:bool,attached:bool)->(Box<Message>,Option<std::sync::Weak<Resource>>){
    let mut message=Box::new(Message::empty());message.from=41;message.to=7;message.to_slot=0;message.to_generation=3;
    message.is_reply=reply;message.call_id=55;message.len=3;message.data[..3].copy_from_slice(b"abc");
    let weak=if attached{let resource=Arc::new(Resource);let weak=Arc::downgrade(&resource);
        message.object_handles.count=1;message.object_handles.delivery_flags=2;message.object_handles.handles[0]=Some(ObjectHandleEntry(resource));Some(weak)
    }else{None};(message,weak)
}
fn receive(mailbox:&mut Mailbox,reply:bool,pointer:u64,accept:bool)->Result<Option<UserReceive>,u64>{
    if reply{mailbox.pop_reply_to_user(41,55,7,0,3,pointer,3,accept)}
    else{mailbox.pop_valid_for_receiver_to_user(7,0,3,pointer,3,accept)}
}
fn main(){
    for reply in [false,true]{
        for error in [Error::InvalidAddress,Error::ResourceUnavailable,Error::BackingFailure]{
            let mut mailbox=Mailbox::new();let(message,weak)=make_message(reply,true);let weak=weak.unwrap();
            mailbox.enqueue_message(message).unwrap();let mut output=[0u8;3];
            COPY_ERROR.set(Some(error));assert!(matches!(receive(&mut mailbox,reply,output.as_mut_ptr()as u64,true),Err(status)if status==error.into_raw()));
            assert_eq!((mailbox.count,mailbox.free_count),(1,3));assert!(weak.upgrade().is_some());assert_eq!(output,[0;3]);
            let received=receive(&mut mailbox,reply,output.as_mut_ptr()as u64,true).unwrap().unwrap();
            assert_eq!(output,*b"abc");assert_eq!((received.from,received.copy_len,received.call_id),(41,3,55));
            assert_eq!((received.object_handles.count,received.object_handles.delivery_flags),(1,2));
            assert_eq!((mailbox.count,mailbox.free_count),(0,4));assert!(weak.upgrade().is_some());
            drop(received);assert!(weak.upgrade().is_none());
        }
        // NULL is not a request to silently discard a nonempty payload.
        let mut mailbox=Mailbox::new();let(message,_)=make_message(reply,false);mailbox.enqueue_message(message).unwrap();
        assert!(matches!(receive(&mut mailbox,reply,0,true),Err(status)if status==Error::InvalidAddress.into_raw()));
        assert_eq!(mailbox.count,1);let mut output=[0u8;3];
        assert!(receive(&mut mailbox,reply,output.as_mut_ptr()as u64,true).unwrap().is_some());assert_eq!(output,*b"abc");

        // A byte-only receiver cannot consume or destroy delegated authority.
        let mut mailbox=Mailbox::new();let(message,weak)=make_message(reply,true);let weak=weak.unwrap();mailbox.enqueue_message(message).unwrap();
        COPIES.set(0);assert!(matches!(receive(&mut mailbox,reply,0,false),Err(status)if status==Error::LimitExceeded.into_raw()));
        assert_eq!((mailbox.count,mailbox.free_count,COPIES.get()),(1,3,0));assert!(weak.upgrade().is_some());
        drop(receive(&mut mailbox,reply,output.as_mut_ptr()as u64,true).unwrap().unwrap());assert!(weak.upgrade().is_none());

        // Empty payloads require no user memory, including a NULL pointer.
        let mut mailbox=Mailbox::new();let(mut message,_)=make_message(reply,false);message.len=0;mailbox.enqueue_message(message).unwrap();
        COPIES.set(0);assert_eq!(receive(&mut mailbox,reply,0,true).unwrap().unwrap().copy_len,0);assert_eq!(COPIES.get(),0);
    }
    // Reply filtering still ignores wrong senders, call IDs and generations.
    let mut mailbox=Mailbox::new();
    for selector in 0..3{let(mut message,_)=make_message(true,false);match selector{0=>message.from=42,1=>message.call_id=56,_=>message.to_generation=4};mailbox.enqueue_message(message).unwrap();}
    assert!(receive(&mut mailbox,true,0,true).unwrap().is_none());assert_eq!(mailbox.count,3);
    assert_eq!(DROPPED.load(Ordering::SeqCst),8);
}
"#);
    probe::run(&program);
}
