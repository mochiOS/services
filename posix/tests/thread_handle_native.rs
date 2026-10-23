//! Execute the production thread Handle syscalls, native lookup, real Handle
//! storage and upcall queue. Thread-table/scheduler access and usercopy are
//! controlled host boundaries; no context switch is claimed by this test.
#[allow(dead_code)]
#[path = "support/native_error_probe.rs"]
mod probe;

#[test]
fn thread_handles_preserve_authority_queue_limits_and_native_copy_failures() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap();
    let table = include_str!("../../../core/src/task/handle_table.rs");
    let thread = include_str!("../../../core/src/task/thread.rs");
    let context = include_str!("../../../core/src/task/context.rs");
    let upcall = include_str!("../../../core/src/syscall/upcall.rs");
    let mut program = String::from(
        r#"
#![allow(dead_code)]
extern crate alloc;
extern crate self as mnu_abi;
use std::{cell::{Cell,RefCell},sync::atomic::{AtomicBool,Ordering}};
static FAIL_NEXT:AtomicBool=AtomicBool::new(false);
struct Allocator;
unsafe impl std::alloc::GlobalAlloc for Allocator {
    unsafe fn alloc(&self,layout:std::alloc::Layout)->*mut u8 {
        if FAIL_NEXT.swap(false,Ordering::Relaxed){return std::ptr::null_mut();}
        unsafe{std::alloc::System.alloc(layout)}
    }
    unsafe fn realloc(&self,p:*mut u8,layout:std::alloc::Layout,size:usize)->*mut u8 {
        if FAIL_NEXT.swap(false,Ordering::Relaxed){return std::ptr::null_mut();}
        unsafe{std::alloc::System.realloc(p,layout,size)}
    }
    unsafe fn dealloc(&self,p:*mut u8,layout:std::alloc::Layout){unsafe{std::alloc::System.dealloc(p,layout)}}
}
#[global_allocator]static ALLOCATOR:Allocator=Allocator;
thread_local! {
    static CURRENT:Cell<bool>=const{Cell::new(true)};
    static PRESENT:Cell<bool>=const{Cell::new(true)};
    static PROCESS_PRESENT:Cell<bool>=const{Cell::new(true)};
    static LOCKED:Cell<bool>=const{Cell::new(false)};
    static WAKES:Cell<usize>=const{Cell::new(0)};
    static COPIES:Cell<usize>=const{Cell::new(0)};
    static COPY_ERROR:Cell<Option<status::Error>>=const{Cell::new(None)};
    static OUTPUT:RefCell<[u8;32]>=const{RefCell::new([0xcc;32])};
    static PROCESS:RefCell<Option<task::Process>>=const{RefCell::new(None)};
    static THREAD:RefCell<task::Thread>=RefCell::new(task::Thread::new());
}
"#,
    );
    program.push_str(&format!(
        "#[path={:?}]mod abi;pub use abi::*;\n",
        root.join("core/crates/abi/src/lib.rs")
    ));
    program.push_str("mod task {pub mod context {\n");
    program.push_str(probe::between(
        context,
        "const FXSAVE_AREA_SIZE:",
        "/// CPU コンテキスト",
    ));
    program.push_str("}\nmod queue {\n");
    program.push_str(probe::between(
        thread,
        "const THREAD_UPCALL_QUEUE_CAPACITY:",
        "// L4 風",
    ));
    program.push_str(r#"
pub struct Queue(ThreadUpcallState);
impl Queue {
    pub fn new()->Self{Self(ThreadUpcallState::new())}
    pub fn enqueue(&mut self,value:u64)->Result<(),ThreadUpcallError>{self.0.enqueue(value)}
    pub fn values(&self)->Vec<u64>{(0..self.0.pending_len).map(|index|self.0.pending[(self.0.pending_head+index)%THREAD_UPCALL_QUEUE_CAPACITY]).collect()}
}
}
pub use queue::ThreadUpcallError;
"#);
    program.push_str(&format!(
        "#[path={:?}]mod ids;pub use ids::{{ThreadId,ProcessId,ThreadState}};\n",
        root.join("core/src/task/ids.rs")
    ));
    program.push_str(r#"
pub mod handle_snapshot {
    pub struct HandleSnapshot;
    impl HandleSnapshot {
        pub fn capture(_:impl IntoIterator<Item=(super::handle_table::ObjectHandle,super::handle_table::ObjectHandleEntry)>)->Result<Self,()>{Ok(Self)}
    }
}
pub mod handle_table {
    use alloc::{boxed::Box,vec::Vec};
    const PROCESS_MAX_OBJECT_HANDLES:usize=crate::PROCESS_MAX_OBJECT_HANDLES;
    #[derive(Clone,Debug)]pub enum KernelObject{Thread(super::ThreadId),Other}
"#);
    program.push_str(probe::between(
        table,
        "#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]",
        "/// Kernel object identity",
    ));
    program.push_str(probe::between(
        table,
        "#[derive(Clone, Debug)]\npub struct ObjectHandleEntry",
        "#[cfg(test)]",
    ));
    program.push_str(r#"
}
pub use handle_table::*;
pub struct Thread {pub state:ThreadState,pub queue:queue::Queue}
impl Thread {
    pub fn new()->Self{Self{state:ThreadState::Running,queue:queue::Queue::new()}}
    pub fn id(&self)->ThreadId{ThreadId::from_u64(23)}
    pub fn process_id(&self)->ProcessId{ProcessId::from_u64(19)}
    pub fn state(&self)->ThreadState{self.state}
    pub fn enqueue_upcall(&mut self,payload:u64)->Result<(),ThreadUpcallError>{self.queue.enqueue(payload)}
}
pub struct Process(pub Box<ObjectHandleTable>);
impl Process {
    pub fn object_handles(&self)->&ObjectHandleTable{&self.0}
    pub fn object_handles_mut(&mut self)->&mut ObjectHandleTable{&mut self.0}
}
pub fn current_thread_id()->Option<ThreadId>{crate::CURRENT.get().then_some(ThreadId::from_u64(23))}
pub fn with_thread<T>(id:ThreadId,body:impl FnOnce(&Thread)->T)->Option<T>{with_thread_mut(id,|thread|body(thread))}
pub fn with_thread_mut<T>(id:ThreadId,body:impl FnOnce(&mut Thread)->T)->Option<T>{
    assert_eq!(id.as_u64(),23);if !crate::PRESENT.get(){return None;}
    assert!(!crate::LOCKED.replace(true));let result=crate::THREAD.with_borrow_mut(body);
    assert!(crate::LOCKED.replace(false));Some(result)
}
pub fn with_process<T>(id:ProcessId,body:impl FnOnce(&Process)->T)->Option<T>{with_process_mut(id,|process|body(process))}
pub fn with_process_mut<T>(id:ProcessId,body:impl FnOnce(&mut Process)->T)->Option<T>{
    assert_eq!(id.as_u64(),19);if !crate::PROCESS_PRESENT.get(){return None;}
    assert!(!crate::LOCKED.replace(true));let result=crate::PROCESS.with_borrow_mut(|process|body(process.as_mut().unwrap()));
    assert!(crate::LOCKED.replace(false));Some(result)
}
pub fn wake_registered_waiter(id:ThreadId){assert_eq!(id.as_u64(),23);assert!(!crate::LOCKED.get());crate::WAKES.set(crate::WAKES.get()+1)}
}
use task::{HandleRights,KernelObject,ObjectHandle,ObjectHandleEntry,ThreadUpcallError};
mod syscall {
    pub mod security {
        pub fn current_process_id()->Option<crate::task::ProcessId>{crate::CURRENT.get().then_some(crate::task::ProcessId::from_u64(19))}
    }
    pub fn copy_to_user_native(pointer:u64,bytes:&[u8])->Result<(),crate::status::Error>{
        assert_eq!(pointer,42);assert_eq!(bytes.len(),24);assert!(!crate::LOCKED.get());
        crate::COPIES.set(crate::COPIES.get()+1);
        if let Some(error)=crate::COPY_ERROR.get(){return Err(error);}
        crate::OUTPUT.with_borrow_mut(|output|output[..24].copy_from_slice(bytes));Ok(())
    }
    pub mod handle {use crate::{HandleRights,KernelObject,ObjectHandle};
"#);
    program.push_str(probe::between(
        include_str!("../../../core/src/syscall/handle.rs"),
        "pub(crate) fn object_native(",
        "pub fn read(",
    ));
    program.push_str("}\nmod upcall {use crate::{HandleRights,KernelObject,ObjectHandleEntry,ThreadUpcallError,SUCCESS};\n");
    program.push_str(probe::between(
        upcall,
        "const THREAD_HANDLE_RIGHTS:",
        "pub fn install(",
    ));
    program.push_str(probe::between(
        upcall,
        "pub fn create_thread_handle()",
        "/// Sample a caller-owned thread object",
    ));
    program.push_str("}\npub use upcall::*;}\n");
    program.push_str(r#"
fn add(table:&mut task::ObjectHandleTable,raw:u32,object:KernelObject,rights:HandleRights){
    assert!(table.insert_at(ObjectHandle::from_raw(raw).unwrap(),ObjectHandleEntry::new(object,rights)));
}
fn main(){
    use status::Error;
    let mut table=task::ObjectHandleTable::new_boxed();
    let target=KernelObject::Thread(task::ThreadId::from_u64(23));
    add(&mut table,1,KernelObject::Other,HandleRights::WAIT.union(HandleRights::SIGNAL));
    add(&mut table,2,target.clone(),HandleRights::SIGNAL);
    add(&mut table,3,target.clone(),HandleRights::WAIT);
    add(&mut table,4,target,HandleRights::empty());
    PROCESS.set(Some(task::Process(table)));
    let owned=syscall::create_thread_handle();assert!(owned>0&&owned<=PROCESS_MAX_OBJECT_HANDLES as u64);
    let entry=PROCESS.with_borrow(|process|process.as_ref().unwrap().0.get(ObjectHandle::from_raw(owned as u32).unwrap()).unwrap());
    assert_eq!(entry.rights(),HandleRights::WAIT.union(HandleRights::SIGNAL).union(HandleRights::DUPLICATE).union(HandleRights::TRANSFER));
    for raw in [0,999,1u64<<32,u64::MAX,1]{
        assert_eq!(syscall::interrupt(raw,7),Error::InvalidArgument.into_raw());
        assert_eq!(syscall::thread_status(raw,42),Error::InvalidArgument.into_raw());
    }
    for raw in [3,4]{assert_eq!(syscall::interrupt(raw,7),Error::AccessDenied.into_raw());}
    for raw in [2,4]{assert_eq!(syscall::thread_status(raw,42),Error::AccessDenied.into_raw());}
    assert_eq!(syscall::thread_status(owned,0),Error::InvalidAddress.into_raw());
    assert_eq!(COPIES.get(),0);assert_eq!(WAKES.get(),0);
    for (state,code) in [(task::ThreadState::Ready,THREAD_STATE_READY),(task::ThreadState::Running,THREAD_STATE_RUNNING),
        (task::ThreadState::Blocked,THREAD_STATE_BLOCKED),(task::ThreadState::Sleeping,THREAD_STATE_SLEEPING),
        (task::ThreadState::Terminated,THREAD_STATE_TERMINATED)]{
        THREAD.with_borrow_mut(|thread|thread.state=state);OUTPUT.set([0xcc;32]);
        assert_eq!(syscall::thread_status(owned,42),0);
        OUTPUT.with_borrow(|bytes|{
            assert_eq!(u64::from_ne_bytes(bytes[..8].try_into().unwrap()),23);
            assert_eq!(u64::from_ne_bytes(bytes[8..16].try_into().unwrap()),19);
            assert_eq!(u32::from_ne_bytes(bytes[16..20].try_into().unwrap()),code);
            assert_eq!(u32::from_ne_bytes(bytes[20..24].try_into().unwrap()),0);
            assert_eq!(&bytes[24..],&[0xcc;8]);
        });
    }
    for error in [Error::InvalidAddress,Error::ResourceUnavailable,Error::BackingFailure]{
        OUTPUT.set([0xcc;32]);COPY_ERROR.set(Some(error));
        assert_eq!(syscall::thread_status(owned,42),error.into_raw());assert_eq!(OUTPUT.take(),[0xcc;32]);
    }
    COPY_ERROR.set(None);
    let payloads:Vec<u64>=(0..16).map(|index|if index==0{0}else{u64::MAX-index+1}).collect();
    for &payload in &payloads{assert_eq!(syscall::interrupt(owned,payload),0);}
    assert_eq!(WAKES.get(),16);
    assert_eq!(syscall::interrupt(owned,999),Error::ResourceUnavailable.into_raw());assert_eq!(WAKES.get(),16);
    assert_eq!(THREAD.with_borrow(|thread|thread.queue.values()),payloads);
    PRESENT.set(false);let copied=COPIES.get();
    assert_eq!(syscall::interrupt(owned,999),Error::NotFound.into_raw());
    assert_eq!(syscall::thread_status(owned,42),Error::NotFound.into_raw());assert_eq!(COPIES.get(),copied);
    assert_eq!(syscall::create_thread_handle(),Error::NotReady.into_raw());PRESENT.set(true);
    for process_missing in [false,true]{
        if process_missing{PROCESS_PRESENT.set(false)}else{CURRENT.set(false)}
        assert_eq!(syscall::create_thread_handle(),Error::NotReady.into_raw());
        assert_eq!(syscall::interrupt(owned,999),Error::NotReady.into_raw());
        assert_eq!(syscall::thread_status(owned,42),Error::NotReady.into_raw());
        PROCESS_PRESENT.set(true);CURRENT.set(true);
    }
    PROCESS.with_borrow_mut(|process|{
        let table=&mut process.as_mut().unwrap().0;
        let mut raw=100;
        while table.describe().len()<8{add(table,raw,KernelObject::Other,HandleRights::empty());raw+=1;}
    });
    // Capacity is now eight: the next insertion must reserve before publishing.
    FAIL_NEXT.store(true,Ordering::Relaxed);
    assert_eq!(syscall::create_thread_handle(),Error::ResourceUnavailable.into_raw());
    assert!(!FAIL_NEXT.load(Ordering::Relaxed));
    assert_eq!(PROCESS.with_borrow(|process|process.as_ref().unwrap().0.describe().len()),8);
    PROCESS.with_borrow_mut(|process|{
        let table=&mut process.as_mut().unwrap().0;
        while table.insert(ObjectHandleEntry::new(KernelObject::Other,HandleRights::empty())).is_some(){}
        assert_eq!(table.describe().len(),PROCESS_MAX_OBJECT_HANDLES);
    });
    assert_eq!(syscall::create_thread_handle(),Error::ResourceUnavailable.into_raw());
}
"#);
    probe::run(&program);
}
