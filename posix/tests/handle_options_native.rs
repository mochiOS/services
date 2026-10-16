//! Execute real selector/rights/table lookup, shared stream options and syscall
//! entry points. Provider option access uses its production atomic methods;
//! provider transport and the scheduler are not involved in these operations.
#[allow(dead_code)]
#[path = "support/native_error_probe.rs"]
mod probe;

#[test]
fn shared_options_require_local_control_authority_and_return_native_errors() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap();
    let table = include_str!("../../../core/src/task/handle_table.rs");
    let syscall = include_str!("../../../core/src/syscall/handle.rs");
    let mut program = String::from(
        r#"
#![feature(allocator_api)]
#![allow(dead_code)]
extern crate alloc;
extern crate self as mnu_abi;
use std::{cell::{Cell,RefCell},sync::{Arc,atomic::{AtomicBool,AtomicU64,Ordering}}};
static DENY:AtomicBool=AtomicBool::new(false);
struct Allocator;
unsafe impl std::alloc::GlobalAlloc for Allocator {
    unsafe fn alloc(&self,layout:std::alloc::Layout)->*mut u8 {
        if DENY.load(Ordering::Relaxed){return std::ptr::null_mut();}
        unsafe{std::alloc::System.alloc(layout)}
    }
    unsafe fn dealloc(&self,pointer:*mut u8,layout:std::alloc::Layout){unsafe{std::alloc::System.dealloc(pointer,layout)}}
}
#[global_allocator]static ALLOCATOR:Allocator=Allocator;
pub mod status {
"#,
    );
    program.push_str(include_str!("../../../core/crates/abi/src/status.rs"));
    program.push_str("}\nuse status::Error;\nconst SUCCESS:u64=0;\n");
    probe::constants(
        &mut program,
        include_str!("../../../core/crates/abi/src/lib.rs"),
        &[
            "PROCESS_MAX_OBJECT_HANDLES",
            "HANDLE_OPTION_NONBLOCKING",
            "HANDLE_OPTIONS_ALL",
        ],
    );
    program.push_str(r#"
#[derive(Debug)]pub struct HandleInfo {pub handle:u32,pub reserved:u32,pub rights:u64}
thread_local! {
    static CURRENT:Cell<Option<u64>>=const{Cell::new(Some(19))};
    static PRESENT:Cell<bool>=const{Cell::new(true)};
    static LOCKED:Cell<bool>=const{Cell::new(false)};
    static FIRST:RefCell<Option<task::Process>>=const{RefCell::new(None)};
    static SECOND:RefCell<Option<task::Process>>=const{RefCell::new(None)};
}
mod interrupt {pub mod spinlock {
    pub struct SpinLock<T>(std::sync::Mutex<T>);
    impl<T> SpinLock<T> {
        pub const fn new(value:T)->Self{Self(std::sync::Mutex::new(value))}
        pub fn lock(&self)->std::sync::MutexGuard<'_,T>{
            assert!(!crate::LOCKED.get(),"process table held across object access");self.0.lock().unwrap()
        }
    }
}}
#[derive(Debug)]pub struct ProviderObject {io_options:AtomicU64}
impl ProviderObject {
"#);
    program.push_str(probe::between(
        table,
        "    pub(crate) fn io_options(",
        "    pub(crate) fn memory_identity(",
    ));
    program.push_str("}\nmod task {\n");
    program.push_str(&format!(
        "#[path={:?}]pub mod fd_table;\n",
        root.join("core/src/task/fd_table.rs")
    ));
    program.push_str(r#"
    pub mod handle_snapshot {
        pub struct HandleSnapshot;
        impl HandleSnapshot {
            pub fn capture(_:impl IntoIterator<Item=(super::handle_table::ObjectHandle,super::handle_table::ObjectHandleEntry)>)->Result<Self,()>{Ok(Self)}
        }
    }
    pub mod handle_table {
        use alloc::{boxed::Box,vec::Vec};use crate::*;
        #[derive(Clone)]pub enum KernelObject {File(Arc<super::fd_table::FileHandle>),Provider(Arc<ProviderObject>),Other}
        impl std::fmt::Debug for KernelObject {
            fn fmt(&self,f:&mut std::fmt::Formatter<'_>)->std::fmt::Result{f.write_str("object")}
        }
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
    pub struct Process(pub Box<ObjectHandleTable>);
    impl Process {pub fn object_handles(&self)->&ObjectHandleTable{assert!(crate::LOCKED.get());&self.0}}
    pub fn with_process<T>(id:u64,body:impl FnOnce(&Process)->T)->Option<T>{
        if !crate::PRESENT.get(){return None;}
        assert!(!crate::LOCKED.replace(true));
        let result=match id {
            19=>crate::FIRST.with_borrow(|process|process.as_ref().map(body)),
            20=>crate::SECOND.with_borrow(|process|process.as_ref().map(body)),
            _=>panic!("foreign process lookup"),
        };
        assert!(crate::LOCKED.replace(false));result
    }
}
mod syscall {
    pub mod security {pub fn current_process_id()->Option<u64>{crate::CURRENT.get()}}
    pub mod fs {
        use crate::{Error,task::fd_table::FileHandle};
        pub fn close_pipe_endpoint_from_kernel(_:usize,_:bool){}
"#);
    program.push_str(probe::between(
        include_str!("../../../core/src/syscall/fs.rs"),
        "pub(crate) fn file_handle_options(",
        "pub(crate) fn read_file_handle(",
    ));
    program.push_str("}}\nuse task::*;\n");
    program.push_str(probe::between(
        syscall,
        "pub(crate) fn object_native(",
        "pub(crate) fn object(raw:",
    ));
    program.push_str(probe::between(
        syscall,
        "pub fn options_get(",
        "fn provider_endpoint(",
    ));
    program.push_str(r#"
fn get(raw:u64)->u64 {
    DENY.store(true,Ordering::Relaxed);let result=options_get(raw);DENY.store(false,Ordering::Relaxed);
    assert!(!LOCKED.get());result
}
fn set(raw:u64,value:u64)->u64 {
    DENY.store(true,Ordering::Relaxed);let result=options_set(raw,value);DENY.store(false,Ordering::Relaxed);
    assert!(!LOCKED.get());result
}
fn insert(table:&mut ObjectHandleTable,raw:u32,object:KernelObject,rights:HandleRights){
    assert!(table.insert_at(ObjectHandle::from_raw(raw).unwrap(),ObjectHandleEntry::new(object,rights)));
}
fn main(){
    use task::fd_table::{FileHandle,OpenFile,FileHandleCap};
    let stream=Arc::new(FileHandle::new_pipe_read(999));
    let alias=Arc::new(stream.duplicate());
    let writer=Arc::new(FileHandle::new_pipe_write(999));
    let invalid=Arc::new(FileHandle::new(OpenFile{pipe_id:None,pipe_write:false,io_options:0},FileHandleCap::READ));
    let provider=Arc::new(ProviderObject{io_options:AtomicU64::new(0)});
    let foreign=Arc::new(ProviderObject{io_options:AtomicU64::new(0)});
    let mut table=ObjectHandleTable::new_boxed();
    insert(&mut table,1,KernelObject::File(stream.clone()),HandleRights::CONTROL);
    insert(&mut table,2,KernelObject::File(stream.clone()),HandleRights::READ);
    insert(&mut table,3,KernelObject::File(alias),HandleRights::CONTROL);
    insert(&mut table,4,KernelObject::Provider(provider.clone()),HandleRights::CONTROL);
    insert(&mut table,5,KernelObject::Provider(provider.clone()),HandleRights::WRITE);
    insert(&mut table,6,KernelObject::Other,HandleRights::CONTROL);
    insert(&mut table,7,KernelObject::File(invalid),HandleRights::CONTROL);
    insert(&mut table,8,KernelObject::File(writer),HandleRights::CONTROL);
    insert(&mut table,9,KernelObject::Provider(provider.clone()),HandleRights::CONTROL);
    FIRST.set(Some(task::Process(table)));
    let mut other=ObjectHandleTable::new_boxed();
    insert(&mut other,1,KernelObject::Provider(foreign.clone()),HandleRights::CONTROL);
    insert(&mut other,99,KernelObject::Provider(foreign.clone()),HandleRights::CONTROL);
    SECOND.set(Some(task::Process(other)));
    for raw in [0,10,99,1u64<<32,(1u64<<32)|1,u64::MAX] {
        assert_eq!(get(raw),Error::InvalidArgument.into_raw());assert_eq!(set(raw,1),Error::InvalidArgument.into_raw());
    }
    for raw in [2,5] {
        assert_eq!(get(raw),Error::AccessDenied.into_raw());assert_eq!(set(raw,1),Error::AccessDenied.into_raw());
    }
    for raw in [6,7] {
        assert_eq!(get(raw),Error::InvalidArgument.into_raw());assert_eq!(set(raw,1),Error::InvalidArgument.into_raw());
    }
    for (left,right) in [(1,3),(4,9),(8,8)] {
        for value in [1,0,1] {
            assert_eq!(set(left,value),0);assert_eq!(get(right),value);
            assert_eq!(set(right,value),0);assert_eq!(get(left),value);
            assert_eq!(set(left,2),Error::InvalidArgument.into_raw());assert_eq!(get(right),value);
        }
    }
    assert_eq!(foreign.io_options(),0);CURRENT.set(Some(20));assert_eq!(get(1),0);
    assert_eq!(set(1,1),0);CURRENT.set(Some(19));assert_eq!(get(4),1);
    assert_eq!(set(4,0),0);assert_eq!(foreign.io_options(),1);
    assert_eq!(Arc::strong_count(&provider),4,"operation leaked provider references");
    assert_eq!(Arc::strong_count(&stream),3,"operation leaked stream references");
    for context in [false,true] {
        if context{PRESENT.set(false)}else{CURRENT.set(None)}
        assert_eq!(get(1),Error::NotReady.into_raw());assert_eq!(set(1,1),Error::NotReady.into_raw());
        assert_eq!(set(1,2),Error::InvalidArgument.into_raw());
        CURRENT.set(Some(19));PRESENT.set(true);
    }
    FIRST.with_borrow_mut(|process|assert!(process.as_mut().unwrap().0.close(ObjectHandle::from_raw(1).unwrap())));
    assert_eq!(get(1),Error::InvalidArgument.into_raw());assert_eq!(get(3),1);
}
"#);
    probe::run_with_toolchain(&program, "nightly-2026-07-16");
}
