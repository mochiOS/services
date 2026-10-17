#[allow(dead_code)]
#[path = "support/native_error_probe.rs"]
mod probe;

#[test]
fn receive_admission_is_native_and_missing_endpoint_authority_fails_closed() {
    let source = include_str!("../../../core/src/syscall/ipc.rs");
    let mut program = probe::program();
    program.push_str(r#"
use std::cell::Cell;
use mnu_abi::status::Error;
const MAX_THREADS:usize=2;
#[macro_export]macro_rules! debug{($($arg:tt)*)=>{()}}
thread_local!{
    static CONTEXT:Cell<bool>=const{Cell::new(true)};
    static REGISTER:Cell<bool>=const{Cell::new(true)};
    static RECORD:Cell<bool>=const{Cell::new(true)};
    static RIGHTS:Cell<bool>=const{Cell::new(true)};
    static RESOLVE:Cell<bool>=const{Cell::new(true)};
    static SLOT:Cell<Option<(usize,u64)>>=const{Cell::new(Some((0,9)))};
    static STAGE:Cell<u8>=const{Cell::new(1)};
    static ERROR:Cell<u64>=const{Cell::new(0)};
    static FINISH_ERROR:Cell<u64>=const{Cell::new(0)};
    static CALLS:Cell<usize>=const{Cell::new(0)};
    static REGISTRATIONS:Cell<usize>=const{Cell::new(0)};
    static WITH_HANDLES:Cell<bool>=const{Cell::new(false)};
}
mod task{
    pub struct ThreadId;impl ThreadId{pub fn as_u64(&self)->u64{7}}
    pub fn current_thread_id()->Option<ThreadId>{crate::CONTEXT.get().then_some(ThreadId)}
    pub fn thread_slot_index_and_generation_by_u64(id:u64)->Option<(usize,u64)>{assert_eq!(id,7);crate::SLOT.get()}
}
fn ensure_endpoint_for_thread(id:u64)->Option<u64>{assert_eq!(id,7);REGISTRATIONS.set(REGISTRATIONS.get()+1);REGISTER.get().then_some(5001)}
"#);
    program.push_str(probe::between(
        source,
        "#[derive(Debug, Clone, Copy, PartialEq, Eq)]\npub struct EndpointRights",
        "#[derive(Clone, Copy, Debug)]\nstruct EndpointRecord",
    ));
    program.push_str(r#"
struct EndpointRecord{rights:EndpointRights}
fn endpoint_record_from_handle(handle:u64)->Option<EndpointRecord>{
    assert_eq!(handle,5001);RECORD.get().then(||EndpointRecord{rights:if RIGHTS.get(){EndpointRights::RECV}else{EndpointRights::SEND}})
}
fn resolve_receive_thread(raw:u64,current:u64)->Result<u64,u64>{
    assert_eq!((raw,current),(5002,7));if RESOLVE.get(){Ok(7)}else{Err(Error::AccessDenied.into_raw())}
}
#[derive(Clone,Copy)]struct IpcEndpoint{thread_id:u64,slot:u16,generation:u64}
struct UserReceive{from:u64,copy_len:usize}
fn ipc_max_msg_size()->usize{32}
mod receive{
    use super::*;
    pub fn copy_message(endpoint:IpcEndpoint,caller:u64,pointer:u64,length:usize,handles:bool)->Result<Option<UserReceive>,u64>{
        assert_eq!((endpoint.thread_id,endpoint.slot,endpoint.generation,caller,pointer,length,handles),(7,0,9,7,11,32,WITH_HANDLES.get()));
        CALLS.set(CALLS.get()+1);
        let error=ERROR.get();if error!=0{return Err(error);}
        if STAGE.get()==0{Ok(None)}else{Ok(Some(UserReceive{from:41,copy_len:3}))}
    }
    pub fn wait_message(endpoint:IpcEndpoint,caller:u64,pointer:u64,length:usize,handles:bool,reply:Option<(u64,u64,IpcEndpoint)>)->Result<UserReceive,u64>{
        assert!(reply.is_none());copy_message(endpoint,caller,pointer,length,handles)?.ok_or(Error::BackingFailure.into_raw())
    }
}
fn finish_user_receive(receiver:u64,message:UserReceive,handles:Option<u64>)->Result<(u64,usize,bool),u64>{
    assert_eq!(receiver,7);assert_eq!(handles,WITH_HANDLES.get().then_some(99));
    let error=FINISH_ERROR.get();if error!=0{return Err(error);}Ok((message.from,message.copy_len,false))
}
"#);
    program.push_str(probe::between(
        source,
        "fn current_receiver(",
        "pub fn send_to_endpoint(",
    ));
    program.push_str(&source[source.find("fn recv_from_thread_nonblocking(").unwrap()..]);
    program.push_str(r#"
fn reset(mode:u8){
    CONTEXT.set(true);REGISTER.set(true);RECORD.set(true);RIGHTS.set(true);RESOLVE.set(true);SLOT.set(Some((0,9)));
    STAGE.set(1);ERROR.set(0);FINISH_ERROR.set(0);CALLS.set(0);REGISTRATIONS.set(0);WITH_HANDLES.set(mode>=4);
}
fn run(mode:u8)->u64{match mode{
    0=>recv(11,64),1=>recv_blocking(11,64),2=>wait(11,64,0),3=>wait(11,64,5002),
    4=>recv_object_handles(11,64,99,0),_=>recv_object_handles(11,64,99,5002),
}}
fn main(){
    for mode in 0..6{
        reset(mode);assert_eq!(run(mode),(41u64<<32)|3);assert_eq!((CALLS.get(),REGISTRATIONS.get()),(1,1));
        for stage in 0..5{
            reset(mode);let expected=match stage{
                0=>{CONTEXT.set(false);Error::NotReady},
                1=>{REGISTER.set(false);Error::ResourceUnavailable},
                2=>{RECORD.set(false);Error::NotReady},
                3=>{SLOT.set(None);Error::NotReady},
                _=>{SLOT.set(Some((MAX_THREADS,9)));Error::BackingFailure},
            };
            assert_eq!(run(mode),expected.into_raw());assert_eq!(CALLS.get(),0);
        }
        reset(mode);RIGHTS.set(false);
        // Keep the existing distinction: legacy receive requires RECV;
        // waiting on the caller's own queue does not require server authority.
        if mode<2{assert_eq!(run(mode),Error::AccessDenied.into_raw());assert_eq!(CALLS.get(),0);}
        else{assert_eq!(run(mode),(41u64<<32)|3);assert_eq!(CALLS.get(),1);}
        for error in [Error::InvalidAddress,Error::AccessDenied,Error::ResourceUnavailable,Error::BackingFailure,Error::LimitExceeded,Error::NotFound]{
            reset(mode);ERROR.set(error.into_raw());assert_eq!(run(mode),error.into_raw());assert_eq!(CALLS.get(),1);
            reset(mode);FINISH_ERROR.set(error.into_raw());assert_eq!(run(mode),error.into_raw());assert_eq!(CALLS.get(),1);
        }
    }
    for mode in [3,5]{reset(mode);RESOLVE.set(false);assert_eq!(run(mode),Error::AccessDenied.into_raw());assert_eq!(CALLS.get(),0);}
    for mode in [0,2,4]{reset(mode);STAGE.set(0);assert_eq!(run(mode),Error::NotReady.into_raw());assert_eq!(CALLS.get(),1);}
    reset(4);assert_eq!(recv_object_handles(11,64,0,0),Error::InvalidAddress.into_raw());assert_eq!((CALLS.get(),REGISTRATIONS.get()),(0,0));
}
"#);
    probe::run(&program);
}
