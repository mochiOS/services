#[allow(dead_code)]
#[path = "support/native_error_probe.rs"]
mod probe;

#[test]
fn bootstrap_notifications_retry_only_native_queue_pressure() {
    let mut program = probe::program();
    program.push_str(r#"
use std::{cell::RefCell,collections::VecDeque};
struct State{replies:VecDeque<SysResult<u64>>,calls:usize,yields:usize}
thread_local!{static STATE:RefCell<State>=RefCell::new(State{replies:VecDeque::new(),calls:0,yields:0});}
mod syscall{pub use crate::mochi_user_syscall::*;}
mod ipc{
    #[derive(Default)]pub struct IpcObjectHandles;
    pub fn send(endpoint:u64,message:&[u8])->crate::SysResult<u64>{
        assert_eq!(endpoint,55);assert_eq!(message,b"ready");
        crate::STATE.with_borrow_mut(|s|{s.calls+=1;s.replies.pop_front().expect("unexpected send")})
    }
    pub fn send_object_handles(endpoint:u64,message:&[u8],_:&IpcObjectHandles)->crate::SysResult<u64>{send(endpoint,message)}
}
mod thread{pub fn yield_now(){crate::STATE.with_borrow_mut(|s|s.yields+=1);}}
mod ready{
"#);
    let source = include_str!("../../../user/crates/platform/src/service_ready.rs");
    program.push_str(
        probe::between(source, "fn send_when_ready(", "\n#[cfg(test)]")
            .replace("#[cfg(not(test))]", "")
            .as_str(),
    );
    program.push_str(r#"
    pub fn run(handles:bool)->super::SysResult<u64>{
        if handles{send_handles_when_ready(55,b"ready",&super::ipc::IpcObjectHandles)}
        else{send_when_ready(55,b"ready")}
    }
}
fn main(){
    for handles in [false,true]{
        STATE.set(State{replies:vec![Err(SysError::from(NativeError::NotReady.into_raw())),Ok(17)].into(),calls:0,yields:0});
        assert_eq!(ready::run(handles),Ok(17));
        STATE.with_borrow(|s|{assert_eq!((s.calls,s.yields),(2,1));assert!(s.replies.is_empty());});
        for status in [EAGAIN,EACCES,NativeError::ResourceUnavailable.into_raw(),NativeError::NotFound.into_raw(),NativeError::InvalidAddress.into_raw()]{
            STATE.set(State{replies:vec![Err(SysError::from(status))].into(),calls:0,yields:0});
            assert_eq!(ready::run(handles),Err(SysError::from(status)));
            STATE.with_borrow(|s|{assert_eq!((s.calls,s.yields),(1,0));assert!(s.replies.is_empty());});
        }
    }
}
"#);
    probe::run(&program);
}

#[test]
fn synchronous_calls_retry_queue_pressure_but_propagate_allocation_failure() {
    let mut program = probe::program();
    program.push_str(r#"
use std::{cell::{Cell,RefCell},collections::VecDeque,sync::atomic::{AtomicU64,Ordering}};
thread_local!{
    static CAPS:Cell<bool>=const{Cell::new(true)};
    static CONTEXT:Cell<bool>=const{Cell::new(true)};
    static REGISTER:Cell<bool>=const{Cell::new(true)};
    static TARGET:Cell<bool>=const{Cell::new(true)};
    static VALID:Cell<bool>=const{Cell::new(true)};
    static DIE_ON_YIELD:Cell<bool>=const{Cell::new(false)};
    static OBSERVE_ERROR:Cell<u64>=const{Cell::new(0)};
    static DECODE_ERROR:Cell<u64>=const{Cell::new(0)};
    static OBSERVERS:Cell<usize>=const{Cell::new(0)};
}
struct State{replies:VecDeque<u64>,calls:usize,yields:usize,receives:usize,decodes:usize}
thread_local!{static STATE:RefCell<State>=RefCell::new(State{replies:VecDeque::new(),calls:0,yields:0,receives:0,decodes:0});}
static NEXT_CALL_ID:AtomicU64=AtomicU64::new(1);
#[derive(Clone,Copy)]struct IpcEndpoint;
struct ObjectHandleAttachments{delivery_flags:u32}
mod capability{pub enum Capability{IpcClient,IpcServer}}
mod syscall{pub mod security{pub fn caller_has_any_capability(_:&[crate::capability::Capability])->bool{crate::CAPS.get()}}}
mod task{
    pub struct ThreadId(u64);impl ThreadId{pub fn as_u64(&self)->u64{self.0}pub fn from_u64(id:u64)->Self{Self(id)}}
    pub fn current_thread_id()->Option<ThreadId>{crate::CONTEXT.get().then_some(ThreadId(7))}
    pub fn yield_now(){crate::STATE.with_borrow_mut(|s|s.yields+=1);if crate::DIE_ON_YIELD.get(){crate::VALID.set(false);}}
}
mod lifetime{
    pub struct Observation;
    impl Drop for Observation{fn drop(&mut self){crate::OBSERVERS.set(crate::OBSERVERS.get()-1);}}
    pub fn observe(_:crate::IpcEndpoint,_:crate::task::ThreadId)->Result<Observation,u64>{
        let error=crate::OBSERVE_ERROR.get();if error!=0{return Err(error);}
        crate::OBSERVERS.set(crate::OBSERVERS.get()+1);Ok(Observation)
    }
}
fn resolve_call_destination(_:u64)->Result<(u64,u64,u32),u64>{Ok((8,88,2))}
fn ensure_endpoint_for_thread(_:u64)->Option<u64>{REGISTER.get().then_some(77)}
fn endpoint_for_thread(_:u64)->Option<IpcEndpoint>{TARGET.get().then_some(IpcEndpoint)}
fn endpoint_is_valid(_:IpcEndpoint)->bool{VALID.get()}
fn decode_outgoing_object_handles(pointer:u64)->Result<ObjectHandleAttachments,u64>{
    assert_eq!(pointer,99);STATE.with_borrow_mut(|s|s.decodes+=1);
    let error=DECODE_ERROR.get();if error!=0{return Err(error);}Ok(ObjectHandleAttachments{delivery_flags:0})
}
fn send_call_to_thread_id(dest:u64,sender:u64,id:u64,pointer:u64,length:u64,flags:u32)->u64{
    assert_eq!((dest,sender,pointer,length,flags),(8,77,11,3,2));assert!(id>0);
    STATE.with_borrow_mut(|s|{s.calls+=1;s.replies.pop_front().expect("unexpected send")})
}
fn send_to_thread_id_with_attachments(dest:u64,sender:u64,id:u64,pointer:u64,length:u64,reply:bool,expects:bool,attachments:ObjectHandleAttachments)->u64{
    assert!(!reply&&expects);send_call_to_thread_id(dest,sender,id,pointer,length,attachments.delivery_flags)
}
fn recv_blocking_reply_for_thread(caller:u64,receiver:u64,sender:u64,id:u64,pointer:u64,length:u64,handles:Option<u64>,_:IpcEndpoint)->u64{
    assert_eq!((caller,receiver,sender,pointer,length),(7,7,88,22,4));assert!(id>0);assert!(handles.is_none()||handles==Some(99));
    STATE.with_borrow_mut(|s|s.receives+=1);123
}
mod production{
use super::*;
"#);
    program.push_str(probe::between(
        include_str!("../../../core/src/syscall/ipc.rs"),
        "pub fn call(",
        "\npub fn reply(",
    ));
    program.push_str(r#"
}
fn run(handles:bool)->u64{
    if handles{production::call_object_handles(8,11,3,22,4,99)}
    else{production::call(8,11,3,22,4)}
}
fn reset(){
    CAPS.set(true);CONTEXT.set(true);REGISTER.set(true);TARGET.set(true);VALID.set(true);DIE_ON_YIELD.set(false);OBSERVE_ERROR.set(0);DECODE_ERROR.set(0);
    assert_eq!(OBSERVERS.get(),0);
    STATE.set(State{replies:VecDeque::new(),calls:0,yields:0,receives:0,decodes:0});
}
fn main(){
    for handles in [false,true]{
        STATE.set(State{replies:vec![NativeError::NotReady.into_raw(),0].into(),calls:0,yields:0,receives:0,decodes:0});
        assert_eq!(run(handles),123);
        STATE.with_borrow(|s|{assert_eq!((s.calls,s.yields,s.receives),(2,1,1));assert_eq!(s.decodes,if handles{2}else{0});assert!(s.replies.is_empty());});
        for status in [EAGAIN,NativeError::ResourceUnavailable.into_raw(),NativeError::NotFound.into_raw(),NativeError::InvalidAddress.into_raw()]{
            STATE.set(State{replies:vec![status].into(),calls:0,yields:0,receives:0,decodes:0});
            assert_eq!(run(handles),status);
            STATE.with_borrow(|s|{assert_eq!((s.calls,s.yields,s.receives),(1,0,0));assert_eq!(s.decodes,usize::from(handles));assert!(s.replies.is_empty());});
        }
    }
    for handles in [false,true]{
        for stage in 0..6{
            reset();let expected=match stage{
                0=>{CAPS.set(false);NativeError::AccessDenied},
                1=>{CONTEXT.set(false);NativeError::NotReady},
                2=>{REGISTER.set(false);NativeError::ResourceUnavailable},
                3=>{TARGET.set(false);NativeError::NotFound},
                4=>{VALID.set(false);NativeError::NotFound},
                _=>{OBSERVE_ERROR.set(NativeError::ResourceUnavailable.into_raw());NativeError::ResourceUnavailable},
            };
            assert_eq!(run(handles),expected.into_raw());assert_eq!(OBSERVERS.get(),0);
            STATE.with_borrow(|s|assert_eq!((s.calls,s.yields,s.receives,s.decodes),(0,0,0,0)));
        }
        reset();DIE_ON_YIELD.set(true);
        STATE.with_borrow_mut(|s|s.replies.push_back(NativeError::NotReady.into_raw()));
        assert_eq!(run(handles),NativeError::NotFound.into_raw());assert_eq!(OBSERVERS.get(),0);
        STATE.with_borrow(|s|assert_eq!((s.calls,s.yields,s.receives),(1,1,0)));
    }
    reset();assert_eq!(production::call_object_handles(8,11,3,22,4,0),NativeError::InvalidAddress.into_raw());
    reset();DECODE_ERROR.set(NativeError::AccessDenied.into_raw());
    assert_eq!(run(true),NativeError::AccessDenied.into_raw());assert_eq!(OBSERVERS.get(),0);
    STATE.with_borrow(|s|assert_eq!((s.calls,s.receives,s.decodes),(0,0,1)));
}
"#);
    probe::run(&program);
}
