#[allow(dead_code)]
#[path = "support/native_error_probe.rs"]
mod probe;

#[test]
fn replies_preserve_generation_scoped_authority_until_success_and_release_failed_attachments() {
    let source = include_str!("../../../core/src/syscall/ipc.rs");
    let mut program = probe::program();
    program.push_str(r#"
use std::{cell::Cell,sync::{Arc,Mutex}};
use mnu_abi::status::Error;
const MAX_THREADS:usize=2;
thread_local!{
    static CONTEXT:Cell<bool>=const{Cell::new(true)};
    static REGISTER:Cell<bool>=const{Cell::new(true)};
    static SLOT:Cell<Option<(usize,u64)>>=const{Cell::new(Some((0,1)))};
    static TARGET:Cell<bool>=const{Cell::new(true)};
    static RESULT:Cell<u64>=const{Cell::new(0)};
    static SENDS:Cell<usize>=const{Cell::new(0)};
    static DECODE_ERROR:Cell<u64>=const{Cell::new(0)};
    static DROPPED:Cell<usize>=const{Cell::new(0)};
}
struct Resource;
impl Drop for Resource{fn drop(&mut self){assert!(MAILBOXES.try_lock().is_ok(),"attachment released under mailbox lock");DROPPED.set(DROPPED.get()+1);}}
struct ObjectHandleAttachments{resource:Option<Arc<Resource>>}
impl ObjectHandleAttachments{fn empty()->Self{Self{resource:None}}}
fn owned()->ObjectHandleAttachments{ObjectHandleAttachments{resource:Some(Arc::new(Resource))}}
mod task{
    pub struct ThreadId;impl ThreadId{pub fn as_u64(&self)->u64{7}}
    pub fn current_thread_id()->Option<ThreadId>{crate::CONTEXT.get().then_some(ThreadId)}
    pub fn thread_slot_index_and_generation_by_u64(id:u64)->Option<(usize,u64)>{assert_eq!(id,7);crate::SLOT.get()}
}
fn ensure_endpoint_for_thread(id:u64)->Option<u64>{assert_eq!(id,7);REGISTER.get().then_some(6001)}
fn resolve_endpoint_handle(handle:u64)->Option<u64>{assert_eq!(handle,5001);TARGET.get().then_some(19)}
fn decode_outgoing_object_handles(pointer:u64)->Result<ObjectHandleAttachments,u64>{
    assert_eq!(pointer,99);let error=DECODE_ERROR.get();if error!=0{return Err(error);}Ok(owned())
}
"#);
    program.push_str(probe::between(
        source,
        "#[derive(Clone, Copy, Debug, PartialEq, Eq)]\nstruct ReplyTarget",
        "#[derive(Debug)]\nstruct Mailbox",
    ));
    program.push_str(
        r#"
struct Mailbox{reply_targets:Vec<ReplyTarget>,reply_owner:Option<(u64,u64)>}
impl Mailbox{
    const fn new()->Self{Self{reply_targets:Vec::new(),reply_owner:None}}
"#,
    );
    program.push_str(probe::between(
        source,
        "    fn add_reply_target(",
        "    fn reserve_slot(",
    ));
    program.push_str(r#"
}
static MAILBOXES:Mutex<[Mailbox;MAX_THREADS]>=Mutex::new([const{Mailbox::new()};MAX_THREADS]);
fn lock_mailboxes()->std::sync::MutexGuard<'static,[Mailbox;MAX_THREADS]>{MAILBOXES.lock().unwrap()}
fn send_to_thread_id_with_attachments(dest:u64,sender:u64,id:u64,pointer:u64,length:u64,reply:bool,expects:bool,_attachments:ObjectHandleAttachments)->u64{
    assert!(MAILBOXES.try_lock().is_ok(),"delivery ran under mailbox lock");
    assert_eq!((dest,sender,id,pointer,length),(19,6001,42,11,3));assert!(reply&&!expects);
    SENDS.set(SENDS.get()+1);RESULT.get()
}
"#);
    program.push_str(probe::between(
        source,
        "pub fn reply(dest_thread_id:",
        "\nfn recv_blocking_reply_for_thread(",
    ));
    program.push_str(r#"
fn reset(){
    CONTEXT.set(true);REGISTER.set(true);SLOT.set(Some((0,1)));TARGET.set(true);RESULT.set(0);SENDS.set(0);DECODE_ERROR.set(0);DROPPED.set(0);
    let mut boxes=lock_mailboxes();boxes[0]=Mailbox::new();boxes[1]=Mailbox::new();boxes[0].add_reply_target(5001,42,(7,1));
}
fn retained()->bool{lock_mailboxes()[0].reply_target(5001,(7,1)).is_some()}
fn main(){
    for stage in 0..7{
        reset();let expected=match stage{
            0=>{CONTEXT.set(false);Error::NotReady},
            1=>{REGISTER.set(false);Error::ResourceUnavailable},
            2=>{SLOT.set(None);Error::NotReady},
            3=>{SLOT.set(Some((MAX_THREADS,1)));Error::BackingFailure},
            4=>{SLOT.set(Some((0,2)));Error::AccessDenied},
            5=>{TARGET.set(false);Error::NotFound},
            _=>{lock_mailboxes()[0].reply_targets.clear();Error::AccessDenied},
        };
        assert_eq!(reply_with_attachments(5001,11,3,owned()),expected.into_raw());
        assert_eq!((SENDS.get(),DROPPED.get()),(0,1));if stage!=6{assert!(retained());}
    }
    // A malformed internal target is a backing failure, not caller errno.
    reset();lock_mailboxes()[0].reply_targets.push(ReplyTarget{endpoint:0,call_id:43});
    assert_eq!(reply_with_attachments(0,11,3,owned()),Error::BackingFailure.into_raw());
    assert_eq!((SENDS.get(),DROPPED.get()),(0,1));assert!(retained());
    for error in [Error::LimitExceeded,Error::InvalidAddress,Error::ResourceUnavailable,Error::BackingFailure,Error::InvalidArgument,Error::AccessDenied,Error::NotReady,Error::AlreadyExists,Error::NotFound,Error::PeerClosed]{
        reset();RESULT.set(error.into_raw());assert_eq!(reply_object_handles(5001,11,3,99),error.into_raw());
        assert_eq!((SENDS.get(),DROPPED.get()),(1,1));assert!(retained());
        RESULT.set(0);assert_eq!(reply_object_handles(5001,11,3,99),0);
        assert_eq!((SENDS.get(),DROPPED.get()),(2,2));assert!(!retained());
        assert_eq!(reply(5001,11,3),Error::AccessDenied.into_raw());assert_eq!(SENDS.get(),2);
    }
    reset();DECODE_ERROR.set(Error::AccessDenied.into_raw());
    assert_eq!(reply_object_handles(5001,11,3,99),Error::AccessDenied.into_raw());
    assert_eq!((SENDS.get(),DROPPED.get()),(0,0));assert!(retained());
    reset();assert_eq!(reply(5001,11,3),0);assert_eq!(SENDS.get(),1);assert!(!retained());
}
"#);
    probe::run(&program);
}
