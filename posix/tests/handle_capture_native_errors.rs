//! Run the actual syscall with fallible Arc allocation and observable owners.
#[allow(dead_code)]
#[path = "support/native_error_probe.rs"]
mod probe;

#[test]
fn failed_capture_never_publishes_or_leaks_a_reference() {
    let mut program = String::from(
        r#"
#![feature(allocator_api)]
#![allow(dead_code)]
extern crate alloc;
use std::{cell::{Cell,RefCell},sync::atomic::{AtomicBool,Ordering}};
use mnu_abi::status::Error;
static FAIL_ALLOCATION:AtomicBool=AtomicBool::new(false);
struct Allocator;
unsafe impl std::alloc::GlobalAlloc for Allocator {
    unsafe fn alloc(&self,layout:std::alloc::Layout)->*mut u8 {
        if FAIL_ALLOCATION.swap(false,Ordering::Relaxed){return std::ptr::null_mut();}
        unsafe {std::alloc::System.alloc(layout)}
    }
    unsafe fn dealloc(&self,p:*mut u8,layout:std::alloc::Layout){unsafe {std::alloc::System.dealloc(p,layout)}}
}
#[global_allocator]static ALLOCATOR:Allocator=Allocator;
thread_local! {
    static MODE:Cell<u8>=const {Cell::new(0)};
    static LIVE:Cell<usize>=const {Cell::new(0)};
    static CAPTURES:Cell<usize>=const {Cell::new(0)};
    static INSERTS:Cell<usize>=const {Cell::new(0)};
    static PROCESS:RefCell<task::Process>=const {RefCell::new(task::Process(task::Table(None)))};
}
mod syscall {pub mod security {
    pub fn current_process_id()->Option<u64>{(crate::MODE.get()!=1).then_some(7)}
}}
mod task {
    use alloc::sync::Arc;
    pub struct Snapshot;
    impl Drop for Snapshot {fn drop(&mut self){crate::LIVE.set(crate::LIVE.get()-1);}}
    #[derive(Clone,Copy)]pub struct HandleRights(pub u64);
    impl HandleRights {
        pub const READ:Self=Self(1);pub const CONTROL:Self=Self(256);
        pub const DUPLICATE:Self=Self(1<<62);
        pub fn union(self,other:Self)->Self{Self(self.0|other.0)}
    }
    pub enum KernelObject {HandleSnapshot(Arc<Snapshot>)}
    pub struct ObjectHandleEntry(pub KernelObject,pub HandleRights);
    impl ObjectHandleEntry {pub fn new(object:KernelObject,rights:HandleRights)->Self{Self(object,rights)}}
    pub struct Handle;impl Handle {pub fn raw(&self)->u32{37}}
    pub struct Table(pub Option<ObjectHandleEntry>);
    impl Table {
        pub fn capture(&self)->Result<Snapshot,()> {
            crate::CAPTURES.set(crate::CAPTURES.get()+1);
            if crate::MODE.get()==3{return Err(());}
            crate::LIVE.set(crate::LIVE.get()+1);
            // Fail exactly the real Arc::try_new in the production syscall.
            if crate::MODE.get()==4 {crate::FAIL_ALLOCATION.store(true,crate::Ordering::Relaxed);}
            Ok(Snapshot)
        }
        pub fn insert(&mut self,entry:ObjectHandleEntry)->Option<Handle> {
            crate::INSERTS.set(crate::INSERTS.get()+1);
            assert!(self.0.is_none());
            assert_eq!(entry.1.0,1|256|(1<<62),"capture must remain private, without TRANSFER");
            if crate::MODE.get()==5{return None;}
            self.0=Some(entry);Some(Handle)
        }
    }
    pub struct Process(pub Table);
    impl Process {
        pub fn object_handles(&self)->&Table{&self.0}
        pub fn object_handles_mut(&mut self)->&mut Table{&mut self.0}
    }
    pub fn with_process_mut<T>(id:u64,body:impl FnOnce(&mut Process)->T)->Option<T> {
        assert_eq!(id,7);
        (crate::MODE.get()!=2).then(||crate::PROCESS.with_borrow_mut(body))
    }
}
mod production {
use crate::mnu_abi;
"#,
    );
    program.push_str(include_str!("../../../core/src/syscall/handle/capture.rs"));
    program.push_str(
        r#"
}
fn main() {
    for (mode,error,captures,inserts) in [
        (1,Error::NotReady,0,0),(2,Error::NotReady,0,0),
        (3,Error::ResourceUnavailable,1,0),(4,Error::ResourceUnavailable,1,0),
        (5,Error::ResourceUnavailable,1,1),
    ] {
        MODE.set(mode);CAPTURES.set(0);INSERTS.set(0);
        assert_eq!(production::table_capture(),error.into_raw());
        assert_eq!(CAPTURES.get(),captures);assert_eq!(INSERTS.get(),inserts);
        assert_eq!(LIVE.get(),0);
        assert!(!FAIL_ALLOCATION.load(Ordering::Relaxed));
        PROCESS.with_borrow(|p|assert!(p.0.0.is_none()));
    }
    MODE.set(0);
    assert_eq!(production::table_capture(),37);
    assert_eq!(LIVE.get(),1);
    PROCESS.with_borrow_mut(|p|p.0.0=None);
    assert_eq!(LIVE.get(),0);
}
"#,
    );
    program.push_str("\nmod mnu_abi {pub mod status {\n");
    program.push_str(include_str!("../../../core/crates/abi/src/status.rs"));
    program.push_str("\n}}\n");
    probe::run_with_toolchain(&program, "nightly-2026-07-16");
}
