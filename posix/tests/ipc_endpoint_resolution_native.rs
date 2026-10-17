#[allow(dead_code)]
#[path = "support/native_error_probe.rs"]
mod probe;

#[test]
fn endpoint_resolution_uses_native_handle_checks_and_preserves_receive_ownership() {
    let mut program = String::from(
        r#"
#![allow(dead_code)]
extern crate self as mnu_abi;
use std::cell::Cell;
mod status {
"#,
    );
    program.push_str(include_str!("../../../core/crates/abi/src/status.rs"));
    program.push_str(
        r#"
}
use status::Error;
"#,
    );
    probe::constants(
        &mut program,
        include_str!("../../../core/crates/abi/src/lib.rs"),
        &["IPC_DELIVERY_ENDPOINT_HANDLE", "PROCESS_MAX_OBJECT_HANDLES"],
    );
    program.push_str(probe::between(
        include_str!("../../../core/src/task/handle_table.rs"),
        "#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]",
        "/// Kernel object identity",
    ));
    program.push_str(r#"
thread_local!{
    static CONTEXT:Cell<bool>=const{Cell::new(true)};
    static PROCESS:Cell<bool>=const{Cell::new(true)};
    static HANDLE:Cell<bool>=const{Cell::new(true)};
    static RIGHTS:Cell<u64>=const{Cell::new(12)};
    static KIND:Cell<bool>=const{Cell::new(true)};
    static VALID:Cell<bool>=const{Cell::new(true)};
    static SENDER:Cell<bool>=const{Cell::new(true)};
    static LOCKED:Cell<bool>=const{Cell::new(false)};
}
#[derive(Clone,Debug)]enum KernelObject{IpcEndpoint{thread_id:u64,slot:u16,generation:u64},Other}
struct Entry{rights:HandleRights,object:KernelObject}
impl Entry{fn rights(&self)->HandleRights{self.rights}fn object(&self)->&KernelObject{&self.object}}
struct Table;
impl Table{fn get(&self,handle:ObjectHandle)->Option<Entry>{
    assert!(LOCKED.get());if handle.raw()!=7||!HANDLE.get(){return None;}
    Some(Entry{rights:HandleRights::from_bits(RIGHTS.get()).unwrap(),
        object:if KIND.get(){KernelObject::IpcEndpoint{thread_id:19,slot:3,generation:7}}else{KernelObject::Other}})
}}
mod task{
    pub(crate) use crate::{ObjectHandle,HandleRights,KernelObject,PROCESS_MAX_OBJECT_HANDLES};
    pub struct Process;
    impl Process{pub fn object_handles(&self)->&crate::Table{&crate::Table}}
    pub fn with_process<T>(pid:u64,body:impl FnOnce(&Process)->T)->Option<T>{
        assert_eq!(pid,42);if !crate::PROCESS.get(){return None;}
        assert!(!crate::LOCKED.replace(true));let result=body(&Process);crate::LOCKED.set(false);Some(result)
    }
}
mod syscall{
    pub mod security{pub fn current_process_id()->Option<u64>{crate::CONTEXT.get().then_some(42)}}
    pub mod handle{
        use crate::{mnu_abi,KernelObject,HandleRights,ObjectHandle};
"#);
    program.push_str(probe::between(
        include_str!("../../../core/src/syscall/handle.rs"),
        "pub(crate) fn object_native(",
        "pub fn read(",
    ));
    program.push_str(r#"
}}
#[derive(Clone,Copy,Debug,PartialEq,Eq)]struct IpcEndpoint{thread_id:u64,slot:u16,generation:u64}
fn endpoint_is_valid(endpoint:IpcEndpoint)->bool{
    assert_eq!(endpoint,IpcEndpoint{thread_id:19,slot:3,generation:7});VALID.get()
}
fn ensure_endpoint_for_thread(id:u64)->Option<u64>{assert_eq!(id,19);SENDER.get().then_some(5001)}
struct EndpointRights(u8);
impl EndpointRights{const RECV:Self=Self(1);fn contains(&self,required:Self)->bool{self.0&required.0==required.0}}
struct Record{thread_id:u64,rights:EndpointRights}
fn endpoint_record_from_handle(raw:u64)->Option<Record>{
    match raw{5001=>Some(Record{thread_id:19,rights:EndpointRights(1)}),
        5002=>Some(Record{thread_id:20,rights:EndpointRights(0)}),_=>None}
}
"#);
    let ipc = include_str!("../../../core/src/syscall/ipc.rs");
    program.push_str(probe::between(
        ipc,
        "fn process_local_endpoint(",
        "pub(crate) fn resolve_provider_endpoint_native(",
    ));
    program.push_str(probe::between(
        ipc,
        "fn resolve_call_destination(",
        "pub fn call(",
    ));
    program.push_str(r#"
fn reset(){
    CONTEXT.set(true);PROCESS.set(true);HANDLE.set(true);RIGHTS.set(12);KIND.set(true);VALID.set(true);SENDER.set(true);
    assert!(!LOCKED.get());
}
fn main(){
    for required in [HandleRights::SEND,HandleRights::RECEIVE]{
        reset();assert_eq!(process_local_endpoint(7,required),Ok(IpcEndpoint{thread_id:19,slot:3,generation:7}));
        for raw in [0,8,4096,u64::MAX]{
            assert_eq!(process_local_endpoint(raw,required),Err(Error::InvalidArgument.into_raw()));
        }
        for absent_process in [false,true]{
            reset();CONTEXT.set(absent_process);PROCESS.set(!absent_process);
            assert_eq!(process_local_endpoint(7,required),Err(Error::NotReady.into_raw()));
        }
        reset();HANDLE.set(false);assert_eq!(process_local_endpoint(7,required),Err(Error::InvalidArgument.into_raw()));
        reset();RIGHTS.set(0);assert_eq!(process_local_endpoint(7,required),Err(Error::AccessDenied.into_raw()));
        reset();KIND.set(false);assert_eq!(process_local_endpoint(7,required),Err(Error::InvalidArgument.into_raw()));
        reset();VALID.set(false);assert_eq!(process_local_endpoint(7,required),Err(Error::NotFound.into_raw()));
    }
    reset();assert_eq!(resolve_call_destination(7),Ok((19,5001,2)));
    SENDER.set(false);assert_eq!(resolve_call_destination(7),Err(Error::NotReady.into_raw()));
    reset();RIGHTS.set(HandleRights::RECEIVE.bits());
    assert_eq!(resolve_call_destination(7),Err(Error::AccessDenied.into_raw()));
    reset();assert_eq!(resolve_call_destination(5001),Ok((19,5001,0)));
    assert_eq!(resolve_call_destination(5002),Err(Error::AccessDenied.into_raw()));
    assert_eq!(resolve_call_destination(6000),Err(Error::NotFound.into_raw()));
    assert_eq!(resolve_receive_thread(7,19),Ok(19));
    assert_eq!(resolve_receive_thread(7,20),Err(Error::AccessDenied.into_raw()));
    RIGHTS.set(HandleRights::SEND.bits());
    assert_eq!(resolve_receive_thread(7,19),Err(Error::AccessDenied.into_raw()));
    assert_eq!(resolve_receive_thread(5001,19),Ok(19));
    assert_eq!(resolve_receive_thread(5001,20),Err(Error::AccessDenied.into_raw()));
    assert_eq!(resolve_receive_thread(5002,20),Err(Error::AccessDenied.into_raw()));
    assert_eq!(resolve_receive_thread(6000,19),Err(Error::NotFound.into_raw()));
    assert!(!LOCKED.get());
}
"#);
    probe::run(&program);
}
