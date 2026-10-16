#[allow(dead_code)]
#[path = "support/native_error_probe.rs"]
mod probe;

#[test]
fn public_send_admission_fails_closed_and_preserves_native_delivery_errors() {
    let ipc = include_str!("../../../core/src/syscall/ipc.rs");
    let mut program = probe::program();
    program.push_str("\nuse std::cell::Cell;\nuse mnu_abi::status::Error;\n");
    program.push_str(probe::between(
        ipc,
        "#[derive(Debug, Clone, Copy, PartialEq, Eq)]\npub struct EndpointRights",
        "#[derive(Clone, Copy, Debug)]\nstruct EndpointRecord",
    ));
    program.push_str(r#"
thread_local!{
    static CONTEXT:Cell<bool>=const{Cell::new(true)};
    static REGISTER:Cell<bool>=const{Cell::new(true)};
    static SENDER:Cell<bool>=const{Cell::new(true)};
    static DESTINATION:Cell<bool>=const{Cell::new(true)};
    static SEND_RIGHTS:Cell<EndpointRights>=const{Cell::new(EndpointRights::SEND)};
    static DEST_RIGHTS:Cell<EndpointRights>=const{Cell::new(EndpointRights::RECV)};
    static CAPABILITIES:Cell<u8>=const{Cell::new(1)};
    static RESOLVE_ERROR:Cell<u64>=const{Cell::new(0)};
    static DECODE_ERROR:Cell<u64>=const{Cell::new(0)};
    static RESULT:Cell<u64>=const{Cell::new(0)};
    static SENDS:Cell<usize>=const{Cell::new(0)};
    static DECODES:Cell<usize>=const{Cell::new(0)};
    static ATTACHED:Cell<bool>=const{Cell::new(false)};
    static EXPECTED_FLAGS:Cell<u32>=const{Cell::new(0)};
}
struct EndpointRecord{thread_id:u64,rights:EndpointRights}
fn endpoint_record_from_handle(handle:u64)->Option<EndpointRecord>{
    match handle{
        5001=>DESTINATION.get().then(||EndpointRecord{thread_id:19,rights:DEST_RIGHTS.get()}),
        6001=>SENDER.get().then(||EndpointRecord{thread_id:7,rights:SEND_RIGHTS.get()}),
        _=>None,
    }
}
mod task{
    pub struct ThreadId;impl ThreadId{pub fn as_u64(&self)->u64{7}}
    pub fn current_thread_id()->Option<ThreadId>{crate::CONTEXT.get().then_some(ThreadId)}
}
fn ensure_endpoint_for_thread(thread:u64)->Option<u64>{assert_eq!(thread,7);REGISTER.get().then_some(6001)}
mod capability{pub enum Capability{IpcClient,IpcServer}}
mod syscall{pub mod security{
    pub fn caller_has_any_capability(requested:&[crate::capability::Capability])->bool{
        use crate::capability::Capability;
        assert_eq!(requested.len(),2);
        requested.iter().any(|c|crate::CAPABILITIES.get()&match c{Capability::IpcClient=>1,Capability::IpcServer=>2}!=0)
    }
}}
struct ObjectHandleAttachments{delivery_flags:u32}
fn resolve_call_destination(handle:u64)->Result<(u64,u64,u32),u64>{
    let error=RESOLVE_ERROR.get();if error!=0{return Err(error);}
    match handle{7=>Ok((19,5001,2)),5001=>Ok((19,5001,0)),_=>Err(Error::NotFound.into_raw())}
}
fn decode_outgoing_object_handles(pointer:u64)->Result<ObjectHandleAttachments,u64>{
    assert_eq!(pointer,99);DECODES.set(DECODES.get()+1);
    let error=DECODE_ERROR.get();if error!=0{return Err(error);}
    Ok(ObjectHandleAttachments{delivery_flags:0})
}
fn deliver(dest:u64,sender:u64,pointer:u64,length:u64)->u64{
    assert_eq!((dest,sender,pointer,length),(19,6001,11,3));SENDS.set(SENDS.get()+1);RESULT.get()
}
fn send_to_thread_id(dest:u64,sender:u64,pointer:u64,length:u64)->u64{
    assert!(!ATTACHED.get());deliver(dest,sender,pointer,length)
}
fn send_to_thread_id_with_attachments(dest:u64,sender:u64,id:u64,pointer:u64,length:u64,reply:bool,expects:bool,attachments:ObjectHandleAttachments)->u64{
    assert!(ATTACHED.get());assert_eq!(id,0);assert!(!reply&&!expects);
    assert_eq!(attachments.delivery_flags,EXPECTED_FLAGS.get());deliver(dest,sender,pointer,length)
}
"#);
    program.push_str(probe::between(
        ipc,
        "pub fn send(dest_endpoint_handle:",
        "\nfn finish_user_receive(",
    ));
    program.push_str(r#"
fn reset(attached:bool){
    CONTEXT.set(true);REGISTER.set(true);SENDER.set(true);DESTINATION.set(true);
    SEND_RIGHTS.set(EndpointRights::SEND);DEST_RIGHTS.set(EndpointRights::RECV);CAPABILITIES.set(1);
    RESOLVE_ERROR.set(0);DECODE_ERROR.set(0);RESULT.set(0);SENDS.set(0);DECODES.set(0);
    ATTACHED.set(attached);EXPECTED_FLAGS.set(0);
}
fn run(attached:bool)->u64{
    if attached{send_object_handles(5001,11,3,99)}else{send(5001,11,3)}
}
fn denied(attached:bool,error:Error){
    assert_eq!(run(attached),error.into_raw());assert_eq!((SENDS.get(),DECODES.get()),(0,0));
}
fn main(){
    for attached in [false,true]{
        for caps in [1,2,3]{reset(attached);CAPABILITIES.set(caps);assert_eq!(run(attached),0);assert_eq!(SENDS.get(),1);}
        reset(attached);CAPABILITIES.set(0);denied(attached,Error::AccessDenied);
        reset(attached);CONTEXT.set(false);denied(attached,Error::NotReady);
        reset(attached);REGISTER.set(false);denied(attached,Error::ResourceUnavailable);
        for error in [Error::LimitExceeded,Error::InvalidAddress,Error::ResourceUnavailable,Error::BackingFailure,Error::InvalidArgument,Error::AccessDenied,Error::NotReady,Error::AlreadyExists,Error::NotFound,Error::PeerClosed]{
            reset(attached);RESULT.set(error.into_raw());assert_eq!(run(attached),error.into_raw());assert_eq!(SENDS.get(),1);
        }
    }
    reset(false);DESTINATION.set(false);denied(false,Error::NotFound);
    reset(false);DEST_RIGHTS.set(EndpointRights::SEND);denied(false,Error::AccessDenied);
    reset(false);SEND_RIGHTS.set(EndpointRights::RECV);denied(false,Error::AccessDenied);
    // Registration can disappear after ensure returned. Missing evidence of
    // SEND authority must not be treated as permission to publish a message.
    reset(false);SENDER.set(false);denied(false,Error::NotReady);
    for error in [Error::InvalidArgument,Error::AccessDenied,Error::NotFound,Error::NotReady]{
        reset(true);RESOLVE_ERROR.set(error.into_raw());denied(true,error);
        reset(true);DECODE_ERROR.set(error.into_raw());assert_eq!(run(true),error.into_raw());assert_eq!((SENDS.get(),DECODES.get()),(0,1));
    }
    // Caller-local endpoint delivery keeps the endpoint-handle origin flag;
    // global endpoint delivery above leaves it clear. Both resolve explicitly.
    reset(true);EXPECTED_FLAGS.set(2);assert_eq!(send_object_handles(7,11,3,99),0);
    assert_eq!((SENDS.get(),DECODES.get()),(1,1));
}
"#);
    probe::run(&program);
}
