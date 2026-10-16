//! Execute the real close/LaunchContext removal paths with observable owners.
#[allow(dead_code)]
#[path = "support/native_error_probe.rs"]
mod probe;

#[test]
fn close_discards_only_the_callers_reference_and_cleans_launch_aliases_once() {
    let mut program = String::from(
        r#"
#![allow(dead_code)]
use std::{cell::{Cell,RefCell},collections::BTreeMap,sync::{Arc,atomic::{AtomicBool,Ordering}}};
use mnu_abi::status::Error;
static DENY:AtomicBool=AtomicBool::new(false);
struct Allocator;
unsafe impl std::alloc::GlobalAlloc for Allocator {
    unsafe fn alloc(&self,layout:std::alloc::Layout)->*mut u8 {
        if DENY.load(Ordering::Relaxed) {return std::ptr::null_mut();}
        unsafe {std::alloc::System.alloc(layout)}
    }
    unsafe fn dealloc(&self,p:*mut u8,layout:std::alloc::Layout) {
        unsafe {std::alloc::System.dealloc(p,layout)}
    }
}
#[global_allocator]static ALLOCATOR:Allocator=Allocator;
thread_local! {
    static CONTEXT:Cell<Option<u64>>=const {Cell::new(Some(19))};
    static PRESENT:Cell<bool>=const {Cell::new(true)};
    static LOCKED:Cell<bool>=const {Cell::new(false)};
    static TABLE_CALLS:Cell<usize>=const {Cell::new(0)};
    static CLEANUPS:Cell<usize>=const {Cell::new(0)};
    static DROPS:Cell<usize>=const {Cell::new(0)};
    static FIRST:RefCell<task::Process>=const {RefCell::new(task::Process::new())};
    static SECOND:RefCell<task::Process>=const {RefCell::new(task::Process::new())};
}
struct Resource;
impl Drop for Resource {fn drop(&mut self) {DROPS.set(DROPS.get()+1);}}
#[derive(Clone,Copy,Debug,PartialEq,Eq,PartialOrd,Ord)]struct ObjectHandle(u32);
impl ObjectHandle {fn from_raw(raw:u32)->Option<Self> {(raw!=0).then_some(Self(raw))}}
struct Entry(Arc<Resource>,u64);
mod mnu_abi {pub mod status {
"#,
    );
    program.push_str(include_str!("../../../core/crates/abi/src/status.rs"));
    program.push_str(
        r#"
}}
mod syscall {pub mod security {
    pub fn current_process_id()->Option<u64> {crate::CONTEXT.get()}
}}
mod task {
    use super::*;
    pub struct Table {pub entries:BTreeMap<ObjectHandle,Entry>}
    impl Table {
"#,
    );
    program.push_str(probe::between(
        include_str!("../../../core/src/task/handle_table.rs"),
        "    pub fn close(",
        "    /// Installs an explicitly transferred object",
    ));
    program.push_str(
        r#"
    }
    pub struct Launch {pub inherited_handles:BTreeMap<u64,ObjectHandle>}
    impl Launch {
"#,
    );
    program.push_str(probe::between(
        include_str!("../../../core/src/task/launch_context.rs"),
        "    pub fn remove_handle(",
        "    pub fn references_handle(",
    ));
    program.push_str(
        r#"
    }
    pub struct Process {pub table:Table,pub launch:Launch}
    impl Process {
        pub const fn new()->Self {Self{table:Table{entries:BTreeMap::new()},launch:Launch{inherited_handles:BTreeMap::new()}}}
        pub fn object_handles_mut(&mut self)->&mut Table {assert!(LOCKED.get());TABLE_CALLS.set(TABLE_CALLS.get()+1);&mut self.table}
        pub fn launch_context_mut(&mut self)->&mut Launch {assert!(LOCKED.get());CLEANUPS.set(CLEANUPS.get()+1);&mut self.launch}
    }
    pub fn with_process_mut<T>(id:u64,body:impl FnOnce(&mut Process)->T)->Option<T> {
        if !PRESENT.get() {return None;}
        assert!(!LOCKED.replace(true));
        let result=match id {19=>FIRST.with_borrow_mut(body),20=>SECOND.with_borrow_mut(body),_=>panic!("foreign process lookup")};
        assert!(LOCKED.replace(false));Some(result)
    }
}
mod production {use crate::{mnu_abi,ObjectHandle};const SUCCESS:u64=0;
"#,
    );
    program.push_str(probe::between(
        include_str!("../../../core/src/syscall/handle.rs"),
        "pub fn close(",
        "pub fn duplicate(",
    ));
    program.push_str(
        r#"
}
fn check(raw:u64,expected:u64) {
    DENY.store(true,Ordering::Relaxed);
    let result=production::close(raw);
    DENY.store(false,Ordering::Relaxed);
    assert_eq!(result,expected);assert!(!LOCKED.get());
}
fn main() {
    DROPS.set(0);
    let shared=Arc::new(Resource);
    FIRST.with_borrow_mut(|p|{
        p.table.entries.insert(ObjectHandle(7),Entry(shared.clone(),0));
        p.table.entries.insert(ObjectHandle(8),Entry(shared.clone(),0));
        p.launch.inherited_handles.extend([(11,ObjectHandle(7)),(12,ObjectHandle(7)),(13,ObjectHandle(8))]);
    });
    drop(shared);
    SECOND.with_borrow_mut(|p|{p.table.entries.insert(ObjectHandle(9),Entry(Arc::new(Resource),0));p.launch.inherited_handles.insert(14,ObjectHandle(9));});
    for raw in [0,1u64<<32,(1u64<<32)|7,u64::MAX] {check(raw,Error::InvalidArgument.into_raw());}
    assert_eq!(TABLE_CALLS.get(),0);assert_eq!(CLEANUPS.get(),0);
    CONTEXT.set(None);check(7,Error::NotReady.into_raw());CONTEXT.set(Some(19));
    PRESENT.set(false);check(7,Error::NotReady.into_raw());PRESENT.set(true);
    assert_eq!(TABLE_CALLS.get(),0);assert_eq!(CLEANUPS.get(),0);
    check(9,Error::InvalidArgument.into_raw());assert_eq!(CLEANUPS.get(),0);
    check(7,0);assert_eq!(CLEANUPS.get(),1);assert_eq!(DROPS.get(),0);
    FIRST.with_borrow(|p|{assert!(!p.table.entries.contains_key(&ObjectHandle(7)));assert_eq!(p.launch.inherited_handles.len(),1);assert_eq!(p.launch.inherited_handles[&13],ObjectHandle(8));});
    check(7,Error::InvalidArgument.into_raw());assert_eq!(CLEANUPS.get(),1);
    SECOND.with_borrow(|p|{assert_eq!(p.table.entries.len(),1);assert_eq!(p.launch.inherited_handles.len(),1);});
    CONTEXT.set(Some(20));check(9,0);assert_eq!(DROPS.get(),1);
    SECOND.with_borrow(|p|{assert!(p.table.entries.is_empty());assert!(p.launch.inherited_handles.is_empty());});
    CONTEXT.set(Some(19));check(8,0);assert_eq!(DROPS.get(),2);assert_eq!(CLEANUPS.get(),3);
    FIRST.with_borrow(|p|{assert!(p.table.entries.is_empty());assert!(p.launch.inherited_handles.is_empty());});
    check(8,Error::InvalidArgument.into_raw());assert_eq!(DROPS.get(),2);assert_eq!(CLEANUPS.get(),3);
}
"#,
    );
    probe::run(&program);
}
