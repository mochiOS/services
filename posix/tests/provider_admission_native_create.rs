//! Execute shared native authority checks and both object/admission creators.
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
const EINVAL:u64=(-22i64) as u64;const ENOMEM:u64=(-12i64) as u64;
const EEXIST:u64=(-17i64) as u64;const ENOSPC:u64=(-28i64) as u64;
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
    fn from_bits(bits:u64)->Option<Self>{(bits&!3==0).then_some(Self(bits))}
}
enum KernelObject {IpcEndpoint{thread_id:u64,slot:u16,generation:u64},MemoryAdmission(Arc<ProviderAdmission>),Provider(Arc<ProviderObject>),Other}
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
struct ProviderObject;
impl ProviderObject {fn new(thread:u64,slot:u16,generation:u64,identity:u64)->Result<Self,u64>{
    assert_eq!((thread,slot,generation,identity),(119,2,8,77));
    CREATED.set(CREATED.get()+1);
    if MODE.get()==6{return Err(ENOMEM);}
    LIVE.set(LIVE.get()+1);
    if MODE.get()==7{FAIL.store(true,Ordering::Relaxed);}
    Ok(Self)
}}
impl Drop for ProviderObject {fn drop(&mut self){LIVE.set(LIVE.get()-1);}}
mod task {
    pub mod handle_table {
        pub fn register_provider_object(_: &crate::Arc<crate::ProviderObject>)->bool{crate::MODE.get()!=12}
    }
    pub struct Handle;impl Handle{pub fn raw(&self)->u32{31}}
    pub struct Table(pub Option<crate::ObjectHandleEntry>);
    impl Table{pub fn insert(&mut self,entry:crate::ObjectHandleEntry)->Option<Handle>{
        crate::INSERTS.set(crate::INSERTS.get()+1);
        if matches!(&entry.0,crate::KernelObject::MemoryAdmission(_)){
            assert_eq!(entry.1,crate::HandleRights::WAIT.union(crate::HandleRights::TRANSFER));
        }else{assert_eq!(entry.1.0,1);}
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
    program.push_str("\n}}\nmod production {use crate::{mnu_abi,ObjectKey,ProviderAdmission,ProviderObject,Arc,Error,HandleRights,KernelObject,ObjectHandleEntry,EINVAL,EEXIST,ENOSPC};\nfn current_process()->Result<u64,u64>{crate::syscall::security::current_process_id().ok_or(EINVAL)}\n");
    program.push_str(probe::between(
        include_str!("../../../core/src/syscall/handle/memory_update.rs"),
        "fn provider_key(",
        "pub fn create(endpoint:",
    ));
    program.push_str(probe::between(
        include_str!("../../../core/src/syscall/handle.rs"),
        "pub fn provider_object_create(",
        "/// Returns the opaque identifier",
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
    // Only endpoint validation is migrated here; preserve other creation
    // errors until their native contracts are migrated separately.
    for (mode,error,created,inserts) in [
        (1,EINVAL,0,0),(2,Error::AccessDenied.into_raw(),0,0),
        (3,Error::InvalidArgument.into_raw(),0,0),(4,Error::InvalidArgument.into_raw(),0,0),
        (5,Error::InvalidArgument.into_raw(),0,0),(6,ENOMEM,1,0),(7,ENOMEM,1,0),
        (8,ENOSPC,1,1),(9,EINVAL,1,0),(10,Error::BackingFailure.into_raw(),0,0),
        (12,EEXIST,1,0),
    ]{
        MODE.set(mode);CREATED.set(0);INSERTS.set(0);
        assert_eq!(production::provider_object_create(7,77,1),error);
        assert_eq!(CREATED.get(),created);assert_eq!(INSERTS.get(),inserts);
        assert_eq!(LIVE.get(),0);assert!(!FAIL.load(Ordering::Relaxed));
        PROCESS.with_borrow(|p|assert!(p.0.0.is_none()));
    }
    MODE.set(0);LOOKUPS.set(0);
    assert_eq!(production::provider_object_create(7,u64::MAX,1),EINVAL);
    assert_eq!(production::provider_object_create(7,77,u64::MAX),EINVAL);
    assert_eq!(LOOKUPS.get(),0);
    assert_eq!(production::provider_object_create(7,77,1),31);
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
