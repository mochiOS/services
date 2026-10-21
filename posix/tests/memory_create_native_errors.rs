//! Execute the production entrypoint with real fallible Arc allocations.
#[allow(dead_code)]
#[path = "support/native_error_probe.rs"]
mod probe;

#[test]
fn creation_failures_do_not_publish_handles_or_leak_backing() {
    let mut constants = String::new();
    probe::constants(
        &mut constants,
        include_str!("../../../core/crates/abi/src/lib.rs"),
        &["MEMORY_OBJECT_RESIZABLE"],
    );
    let mut program = format!("#![feature(allocator_api)]\n{}", probe::program()).replacen(
        "mod mnu_abi {",
        &format!("mod mnu_abi {{{constants}"),
        1,
    );
    program.push_str(r#"
use alloc::sync::Arc;
use std::{cell::{Cell,RefCell},sync::atomic::{AtomicIsize,Ordering}};
use mnu_abi::status::Error;
static FAIL:AtomicIsize=AtomicIsize::new(-1);
struct Allocator;
unsafe impl std::alloc::GlobalAlloc for Allocator {
    unsafe fn alloc(&self, layout:std::alloc::Layout)->*mut u8 {
        let left=FAIL.load(Ordering::Relaxed);
        if left>=0 {
            FAIL.store(left-1,Ordering::Relaxed);
            if left==0 {return std::ptr::null_mut();}
        }
        unsafe {std::alloc::System.alloc(layout)}
    }
    unsafe fn dealloc(&self,p:*mut u8,layout:std::alloc::Layout){unsafe {std::alloc::System.dealloc(p,layout)}}
}
#[global_allocator] static ALLOCATOR:Allocator=Allocator;
thread_local! {
    static LIVE:Cell<usize>=const {Cell::new(0)};
    static CONSTRUCTIONS:Cell<usize>=const {Cell::new(0)};
    static CONTEXT:Cell<bool>=const {Cell::new(true)};
    static PROCESS_PRESENT:Cell<bool>=const {Cell::new(true)};
    static FULL:Cell<bool>=const {Cell::new(false)};
    static INSERTS:Cell<usize>=const {Cell::new(0)};
    static PROCESS:RefCell<task::Process>=const {RefCell::new(task::Process{handles:task::Table{entry:None}})};
}
mod syscall {pub mod security {pub fn current_process_id()->Option<u64>{crate::CONTEXT.get().then_some(7)}}}
mod mem {
    pub mod shared_memory {
        pub struct SharedMemory;
        impl Drop for SharedMemory {fn drop(&mut self){crate::LIVE.set(crate::LIVE.get()-1);}}
        impl SharedMemory {
            pub fn new(length:u64,limit:u64)->Result<Self,crate::Error>{
                if length==0||length%4096!=0{return Err(crate::Error::InvalidArgument);}
                Self::new_resizable(length,limit)
            }
            pub fn new_resizable(length:u64,limit:u64)->Result<Self,crate::Error>{
                crate::CONSTRUCTIONS.set(crate::CONSTRUCTIONS.get()+1);
                assert_eq!(limit,1);
                if length>4096{return Err(crate::Error::ResourceUnavailable);}
                crate::LIVE.set(crate::LIVE.get()+1);Ok(Self)
            }
        }
    }
    pub mod vm_object {
        pub struct VmObject(pub crate::Arc<super::shared_memory::SharedMemory>);
        impl VmObject {pub fn shared_memory(memory:crate::Arc<super::shared_memory::SharedMemory>)->Self{Self(memory)}}
    }
}
mod task {
    #[derive(Clone,Copy)] pub struct HandleRights(pub u64);
    impl HandleRights {
        pub const READ:Self=Self(1);pub const WRITE:Self=Self(2);pub const MAP:Self=Self(64);
        pub const DUPLICATE:Self=Self(1<<62);pub const TRANSFER:Self=Self(1<<63);pub const CONTROL:Self=Self(256);
        pub fn union(self,other:Self)->Self{Self(self.0|other.0)}
    }
    pub enum KernelObject {VmObject(crate::Arc<crate::mem::vm_object::VmObject>)}
    pub struct ObjectHandleEntry {pub object:KernelObject,pub rights:HandleRights}
    impl ObjectHandleEntry {pub fn new(object:KernelObject,rights:HandleRights)->Self{Self{object,rights}}}
    pub struct Handle;impl Handle {pub fn raw(&self)->u32{3}}
    pub struct Table {pub entry:Option<ObjectHandleEntry>}
    impl Table {pub fn insert(&mut self,entry:ObjectHandleEntry)->Option<Handle>{
        crate::INSERTS.set(crate::INSERTS.get()+1);
        if crate::FULL.get(){None}else{assert!(self.entry.is_none());self.entry=Some(entry);Some(Handle)}
    }}
    pub struct Limits {pub max_mapped_pages:usize}
    pub struct Process {pub handles:Table}
    impl Process {
        pub fn resource_limits(&self)->Limits{Limits{max_mapped_pages:1}}
        pub fn object_handles_mut(&mut self)->&mut Table{&mut self.handles}
    }
    pub fn with_process_mut<T>(id:u64,body:impl FnOnce(&mut Process)->T)->Option<T>{
        assert_eq!(id,7);
        crate::PROCESS_PRESENT.get().then(||crate::PROCESS.with_borrow_mut(body))
    }
}
use task::{HandleRights,KernelObject,ObjectHandleEntry};
"#);
    program.push_str(probe::between(
        include_str!("../../../core/src/syscall/handle.rs"),
        "pub fn memory_object_create(",
        "pub fn memory_object_length(",
    ));
    program.push_str(r#"
fn reset(){
    FAIL.store(-1,Ordering::Relaxed);
    PROCESS.with_borrow_mut(|p|p.handles.entry=None);
    assert_eq!(LIVE.get(),0);
    CONSTRUCTIONS.set(0);INSERTS.set(0);FULL.set(false);CONTEXT.set(true);PROCESS_PRESENT.set(true);
}
fn main(){
    for mode in 0..7 {
        reset();
        let (length,options,expected)=match mode {
            0=>(4096,2,Error::InvalidArgument),1=>(0,0,Error::InvalidArgument),
            2=>(8192,0,Error::ResourceUnavailable),
            3|4=>{CONTEXT.set(mode!=3);PROCESS_PRESENT.set(mode!=4);(4096,0,Error::NotReady)},
            _=>{FAIL.store((mode-5) as isize,Ordering::Relaxed);(4096,0,Error::ResourceUnavailable)},
        };
        let result=memory_object_create(length,options);
        FAIL.store(-1,Ordering::Relaxed);
        assert_eq!(result,expected.into_raw());assert_eq!(LIVE.get(),0);assert_eq!(INSERTS.get(),0);
        if mode==0||mode==3||mode==4{assert_eq!(CONSTRUCTIONS.get(),0);}
    }
    reset();FULL.set(true);
    assert_eq!(memory_object_create(4096,0),Error::ResourceUnavailable.into_raw());
    assert_eq!(LIVE.get(),0);assert_eq!(INSERTS.get(),1);
    for (length,options) in [(4096,0),(0,1),(1,1)] {
        reset();assert_eq!(memory_object_create(length,options),3);assert_eq!(LIVE.get(),1);
        PROCESS.with_borrow(|p|assert_eq!(p.handles.entry.as_ref().unwrap().rights.0,1|2|64|(1<<62)|(1<<63)|if options==1{256}else{0}));
    }
    reset();
}
"#);
    probe::run_with_toolchain(&program, "nightly-2026-07-16");
}
