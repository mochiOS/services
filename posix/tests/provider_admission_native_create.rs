//! Execute native endpoint validation and admission creation, including Arc OOM.
#[allow(dead_code)]
#[path = "support/native_error_probe.rs"]
mod probe;

#[test]
fn invalid_authority_and_creation_failures_publish_no_queue_owner() {
    let mut program = String::from(
        r#"
#![feature(allocator_api)]
#![allow(dead_code)]
extern crate alloc;
use alloc::sync::Arc;
use std::{cell::{Cell,RefCell},sync::atomic::{AtomicBool,Ordering}};
use mnu_abi::status::Error;
static FAIL:AtomicBool=AtomicBool::new(false);
struct Allocator;
unsafe impl std::alloc::GlobalAlloc for Allocator {
    unsafe fn alloc(&self,l:std::alloc::Layout)->*mut u8 {
        if FAIL.swap(false,Ordering::Relaxed){return std::ptr::null_mut();}
        unsafe {std::alloc::System.alloc(l)}
    }
    unsafe fn dealloc(&self,p:*mut u8,l:std::alloc::Layout){unsafe {std::alloc::System.dealloc(p,l)}}
}
#[global_allocator]static ALLOCATOR:Allocator=Allocator;
thread_local! {
    static MODE:Cell<u8>=const {Cell::new(0)};
    static LOOKUPS:Cell<usize>=const {Cell::new(0)};
    static CREATED:Cell<usize>=const {Cell::new(0)};
    static INSERTS:Cell<usize>=const {Cell::new(0)};
    static LIVE:Cell<usize>=const {Cell::new(0)};
    static PROCESS:RefCell<task::Process>=const {RefCell::new(task::Process(task::Table(None)))};
}
#[derive(Clone,Copy,Debug,PartialEq)]struct HandleRights(u64);
impl HandleRights {
    const RECEIVE:Self=Self(8);const WAIT:Self=Self(16);const TRANSFER:Self=Self(1<<63);
    fn union(self,other:Self)->Self{Self(self.0|other.0)}
}
enum KernelObject {IpcEndpoint{thread_id:u64,slot:u16,generation:u64},MemoryAdmission(Arc<ProviderAdmission>),Other}
struct ObjectHandleEntry(KernelObject,HandleRights);
impl ObjectHandleEntry {fn new(object:KernelObject,rights:HandleRights)->Self{Self(object,rights)}}
enum ObjectKey {Provider{endpoint_thread_id:u64,endpoint_slot:u16,endpoint_generation:u64,identity:u64}}
struct ProviderAdmission;
impl ProviderAdmission {fn new(key:ObjectKey)->Result<Self,Error>{
    let ObjectKey::Provider{endpoint_thread_id,endpoint_slot,endpoint_generation,identity}=key;
    assert_eq!((endpoint_thread_id,endpoint_slot,endpoint_generation,identity),(119,2,8,77));
    CREATED.set(CREATED.get()+1);
    if MODE.get()==6{return Err(Error::ResourceUnavailable);}
    LIVE.set(LIVE.get()+1);
    if MODE.get()==7{FAIL.store(true,Ordering::Relaxed);}
    Ok(Self)
}}
impl Drop for ProviderAdmission {fn drop(&mut self){LIVE.set(LIVE.get()-1);}}
mod task {
    pub struct Handle;impl Handle{pub fn raw(&self)->u32{31}}
    pub struct Table(pub Option<crate::ObjectHandleEntry>);
    impl Table{pub fn insert(&mut self,entry:crate::ObjectHandleEntry)->Option<Handle>{
        crate::INSERTS.set(crate::INSERTS.get()+1);
        assert_eq!(entry.1,crate::HandleRights::WAIT.union(crate::HandleRights::TRANSFER));
        assert!(self.0.is_none());
        if crate::MODE.get()==8{return None;}
        self.0=Some(entry);Some(Handle)
    }}
    pub struct Process(pub Table);
    impl Process{pub fn object_handles_mut(&mut self)->&mut Table{&mut self.0}}
    pub fn with_process_mut<T>(id:u64,body:impl FnOnce(&mut Process)->T)->Option<T>{
        assert_eq!(id,7);
        (crate::MODE.get()!=9).then(||crate::PROCESS.with_borrow_mut(body))
    }
}
mod syscall {
    pub mod security{pub fn current_process_id()->Option<u64>{(crate::MODE.get()!=1).then_some(7)}}
    pub mod handle{pub fn object_native(raw:u64,rights:crate::HandleRights)->Result<crate::KernelObject,crate::Error>{
        assert_eq!(rights,crate::HandleRights::RECEIVE);
        crate::LOOKUPS.set(crate::LOOKUPS.get()+1);
        match crate::MODE.get(){
            2=>return Err(crate::Error::AccessDenied),
            3=>return Err(crate::Error::InvalidArgument),
            4=>return Ok(crate::KernelObject::Other),
            10=>return Err(crate::Error::BackingFailure),
            _=>{}
        }
        if raw!=7{return Err(crate::Error::InvalidArgument);}
        Ok(crate::KernelObject::IpcEndpoint{thread_id:119,slot:2,generation:8})
    }}
    pub mod ipc {
        use crate::{mnu_abi,HandleRights,KernelObject};
        struct IpcEndpoint{thread_id:u64,slot:u16,generation:u64}
        fn endpoint_is_valid(e:IpcEndpoint)->bool{
            assert_eq!((e.thread_id,e.slot,e.generation),(119,2,8));
            crate::MODE.get()!=5
        }
"#,
    );
    program.push_str(probe::between(
        include_str!("../../../core/src/syscall/ipc.rs"),
        "pub(crate) fn resolve_provider_endpoint_native(",
        "fn resolve_call_destination(",
    ));
    program.push_str("\n}}\nmod production {use crate::{mnu_abi,ObjectKey,ProviderAdmission,Arc,Error,HandleRights,KernelObject,ObjectHandleEntry};\n");
    program.push_str(probe::between(
        include_str!("../../../core/src/syscall/handle/memory_update.rs"),
        "fn provider_key(",
        "pub fn create(endpoint:",
    ));
    program.push_str(
        r#"
}
fn main(){
    for (mode,error,created,inserts) in [
        (1,Error::NotReady,0,0),(2,Error::AccessDenied,0,0),
        (3,Error::InvalidArgument,0,0),(4,Error::InvalidArgument,0,0),
        (5,Error::InvalidArgument,0,0),(6,Error::ResourceUnavailable,1,0),
        (7,Error::ResourceUnavailable,1,0),(8,Error::ResourceUnavailable,1,1),
        (9,Error::NotReady,1,0),(10,Error::BackingFailure,0,0),
    ]{
        MODE.set(mode);CREATED.set(0);INSERTS.set(0);
        assert_eq!(production::create_admission(7,77),error.into_raw());
        assert_eq!(CREATED.get(),created);assert_eq!(INSERTS.get(),inserts);
        assert_eq!(LIVE.get(),0);assert!(!FAIL.load(Ordering::Relaxed));
        PROCESS.with_borrow(|p|assert!(p.0.0.is_none()));
    }
    MODE.set(0);LOOKUPS.set(0);
    assert_eq!(production::create_admission(7,0),Error::InvalidArgument.into_raw());
    assert_eq!(LOOKUPS.get(),0,"invalid identity must not inspect or reserve a resource");
    for raw in [0,u64::MAX] {
        assert_eq!(production::create_admission(raw,77),Error::InvalidArgument.into_raw());
    }
    assert_eq!(LIVE.get(),0);
    assert_eq!(production::create_admission(7,77),31);
    assert_eq!(LIVE.get(),1);
    PROCESS.with_borrow_mut(|p|p.0.0=None);
    assert_eq!(LIVE.get(),0);
}
"#,
    );
    program.push_str("\nmod mnu_abi{pub mod status{\n");
    program.push_str(include_str!("../../../core/crates/abi/src/status.rs"));
    program.push_str("\n}}\n");
    probe::run_with_toolchain(&program, "nightly-2026-07-16");
}
