//! Exercise actual context storage and syscall bodies, including fallible growth.
#[allow(dead_code)]
#[path = "support/native_error_probe.rs"]
mod probe;

#[test]
fn opaque_context_mutations_are_caller_local_atomic_on_failure_and_do_not_own_handles() {
    let table = include_str!("../../../core/src/task/handle_table.rs");
    let context = include_str!("../../../core/src/task/launch_context.rs");
    let mut program = String::from(
        r#"
#![allow(dead_code)]
use std::{cell::{Cell,RefCell},collections::BTreeMap,sync::{Arc,atomic::{AtomicBool,Ordering}}};
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
mod mnu_abi {pub mod status {
"#,
    );
    program.push_str(include_str!("../../../core/crates/abi/src/status.rs"));
    program.push_str("}}\nuse mnu_abi::status::Error;\n");
    program.push_str(probe::between(
        table,
        "#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]",
        "/// Kernel object identity",
    ));
    program.push_str("#[derive(Clone,Debug)]struct KernelObject(Arc<()>);\n");
    program.push_str(probe::between(
        table,
        "#[derive(Clone, Debug)]\npub struct ObjectHandleEntry",
        "#[derive(Clone, Debug)]\npub struct ObjectHandleTable",
    ));
    program.push_str(
        "struct Table {entries:Vec<(ObjectHandle,ObjectHandleEntry)>}\nimpl Table {\n",
    );
    program.push_str(probe::between(
        table,
        "    pub fn get(",
        "    /// Captures transferable references",
    ));
    program.push_str("}\nmod launch {use crate::{ObjectHandle,Error};\n");
    // Only single-key mutations are in this boundary. Image-transition
    // preparation is separate and still has its own error migration pending.
    program.push_str(probe::between(
        context,
        "pub const PROCESS_MAX_INHERITED_HANDLES:",
        "    fn try_copy(",
    ));
    program.push_str("}\n");
    program.push_str(probe::between(
        context,
        "/// Opaque launch metadata",
        "    /// Prepare a replacement off to the side.",
    ));
    program.push_str(
        r#"
    pub fn dimensions(&self)->((usize,usize),(usize,usize)) {
        ((self.inherited_handles.len(),self.inherited_handles.0.capacity()),
         (self.inherited_values.len(),self.inherited_values.0.capacity()))
    }
}}
thread_local! {
    static CONTEXT:Cell<Option<u64>>=const {Cell::new(Some(19))};
    static PRESENT:Cell<bool>=const {Cell::new(true)};
    static LOCKED:Cell<bool>=const {Cell::new(false)};
    static LOOKUPS:Cell<usize>=const {Cell::new(0)};
    static FIRST:RefCell<task::Process>=RefCell::new(task::Process::new());
    static SECOND:RefCell<task::Process>=RefCell::new(task::Process::new());
}
mod syscall {pub mod security {
    pub fn current_process_id()->Option<u64> {crate::CONTEXT.get()}
}}
mod task {
    use super::*;
    pub struct Process {pub table:Table,pub launch:Box<launch::LaunchContext>}
    impl Process {
        pub fn new()->Self {Self{table:Table{entries:Vec::new()},launch:launch::LaunchContext::new_boxed()}}
        pub fn object_handles(&self)->&Table {assert!(LOCKED.get());LOOKUPS.set(LOOKUPS.get()+1);&self.table}
        pub fn launch_context_mut(&mut self)->&mut launch::LaunchContext {assert!(LOCKED.get());LOOKUPS.set(LOOKUPS.get()+1);&mut self.launch}
    }
    pub fn with_process_mut<T>(id:u64,body:impl FnOnce(&mut Process)->T)->Option<T> {
        if !PRESENT.get() {return None;}
        assert!(!LOCKED.replace(true));
        let result=match id {19=>FIRST.with_borrow_mut(body),20=>SECOND.with_borrow_mut(body),_=>panic!("foreign table")};
        assert!(LOCKED.replace(false));Some(result)
    }
}
mod production {use crate::{mnu_abi,ObjectHandle};const SUCCESS:u64=0;
"#,
    );
    program.push_str(probe::between(
        include_str!("../../../core/src/syscall/handle.rs"),
        "pub fn context_handle_set(",
        "pub fn rights_get(",
    ));
    program.push_str(
        r#"
}
fn check(operation:impl FnOnce()->u64,expected:u64) {
    DENY.store(true,Ordering::Relaxed);
    let result=operation();
    DENY.store(false,Ordering::Relaxed);
    assert_eq!(result,expected);assert!(!LOCKED.get());
}
fn snapshot()->String {FIRST.with_borrow(|p|format!("{:?}",p.launch))}
fn main() {
    let first=Arc::new(());let second=Arc::new(());let foreign=Arc::new(());
    FIRST.with_borrow_mut(|p|{
        p.table.entries.push((ObjectHandle(7),ObjectHandleEntry::new(KernelObject(first.clone()),HandleRights::empty())));
        p.table.entries.push((ObjectHandle(8),ObjectHandleEntry::new(KernelObject(second.clone()),HandleRights::ALL)));
    });
    SECOND.with_borrow_mut(|p|{p.table.entries.push((ObjectHandle(9),ObjectHandleEntry::new(KernelObject(foreign.clone()),HandleRights::ALL)));});
    for raw in [0,1u64<<32,(1u64<<32)|7,u64::MAX] {
        LOOKUPS.set(0);check(||production::context_handle_set(0,raw),Error::InvalidArgument.into_raw());assert_eq!(LOOKUPS.get(),0);
    }
    check(||production::context_handle_set(0,9),Error::InvalidArgument.into_raw());
    // Failed initial allocation leaves both independent key spaces untouched.
    let initial=snapshot();
    check(||production::context_handle_set(0,7),Error::ResourceUnavailable.into_raw());
    check(||production::context_value_set(0,u64::MAX),Error::ResourceUnavailable.into_raw());
    assert_eq!(snapshot(),initial);
    for unavailable in [false,true] {
        LOOKUPS.set(0);
        if unavailable {PRESENT.set(false);} else {CONTEXT.set(None);}
        check(||production::context_handle_set(0,7),Error::NotReady.into_raw());
        check(||production::context_value_set(0,0),Error::NotReady.into_raw());
        check(||production::context_handle_remove(0),Error::NotReady.into_raw());
        check(||production::context_value_remove(0),Error::NotReady.into_raw());
        PRESENT.set(true);CONTEXT.set(Some(19));assert_eq!(LOOKUPS.get(),0);
    }
    // Values and keys retain every bit; the two namespaces are independent.
    assert_eq!(production::context_handle_set(u64::MAX,7),0);
    assert_eq!(production::context_value_set(u64::MAX,u64::MAX),0);
    FIRST.with_borrow(|p|{assert_eq!(p.launch.get(u64::MAX),Some(ObjectHandle(7)));assert_eq!(p.launch.value(u64::MAX),Some(u64::MAX));});
    assert_eq!(Arc::strong_count(&first),2);assert_eq!(Arc::strong_count(&second),2);
    // Fill current allocations, then reject real Vec growth without mutation.
    let ((_,handles),(_,values))=FIRST.with_borrow(|p|p.launch.dimensions());
    for key in 0..(handles as u64-1) {assert_eq!(production::context_handle_set(key,7),0);}
    for key in 0..(values as u64-1) {assert_eq!(production::context_value_set(key,key),0);}
    let before=snapshot();
    check(||production::context_handle_set(1000,8),Error::ResourceUnavailable.into_raw());
    check(||production::context_value_set(1000,1),Error::ResourceUnavailable.into_raw());
    assert_eq!(snapshot(),before);
    // At the published limits replacements remain allocation-free.
    for key in 0..(launch::PROCESS_MAX_INHERITED_HANDLES as u64-1) {assert_eq!(production::context_handle_set(key,7),0);}
    for key in 0..(launch::PROCESS_MAX_INHERITED_VALUES as u64-1) {assert_eq!(production::context_value_set(key,key),0);}
    let before=snapshot();
    check(||production::context_handle_set(1000,8),Error::ResourceUnavailable.into_raw());
    check(||production::context_value_set(1000,1),Error::ResourceUnavailable.into_raw());
    assert_eq!(snapshot(),before);
    check(||production::context_handle_set(u64::MAX,8),0);
    check(||production::context_value_set(u64::MAX,Error::NotReady.into_raw()),0);
    FIRST.with_borrow(|p|{assert_eq!(p.launch.get(u64::MAX),Some(ObjectHandle(8)));assert_eq!(p.launch.value(u64::MAX),Some(Error::NotReady.into_raw()));});
    let before=snapshot();
    // Even an existing key cannot be replaced by another process's selector.
    check(||production::context_handle_set(u64::MAX,9),Error::InvalidArgument.into_raw());
    assert_eq!(snapshot(),before);
    check(||production::context_handle_remove(u64::MAX),0);
    check(||production::context_handle_remove(u64::MAX),0);
    FIRST.with_borrow(|p|{assert_eq!(p.launch.get(u64::MAX),None);assert_eq!(p.launch.value(u64::MAX),Some(Error::NotReady.into_raw()));assert_eq!(p.table.entries.len(),2);});
    check(||production::context_value_remove(u64::MAX),0);
    check(||production::context_value_remove(u64::MAX),0);
    assert_eq!(Arc::strong_count(&first),2);assert_eq!(Arc::strong_count(&second),2);
    SECOND.with_borrow(|p|{assert_eq!(p.launch.dimensions(),((0,0),(0,0)));assert_eq!(p.table.entries.len(),1);});
    CONTEXT.set(Some(20));assert_eq!(production::context_handle_set(0,9),0);CONTEXT.set(Some(19));
    FIRST.with_borrow(|p|assert_eq!(p.launch.get(0),Some(ObjectHandle(7))));
    SECOND.with_borrow(|p|assert_eq!(p.launch.get(0),Some(ObjectHandle(9))));
    assert_eq!(Arc::strong_count(&foreign),2);
}
"#,
    );
    probe::run(&program);
}
