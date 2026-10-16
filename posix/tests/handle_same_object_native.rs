//! Run the actual caller-table query with allocation disabled.
#[allow(dead_code)]
#[path = "support/native_error_probe.rs"]
mod probe;

#[test]
fn same_object_is_an_allocation_free_caller_scoped_boolean_query_with_native_failures() {
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
    static LOOKUPS:Cell<usize>=const {Cell::new(0)};
    static COMPARISONS:Cell<usize>=const {Cell::new(0)};
    static PROCESS:RefCell<task::Process>=const {RefCell::new(task::Process(BTreeMap::new()))};
}
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
struct ObjectHandle(u32);
impl ObjectHandle {fn from_raw(raw:u32)->Option<Self> {(raw!=0).then_some(Self(raw))}}
struct Object(Arc<()>);
impl Object {fn is_same_object(&self,other:&Self)->bool {
    assert!(LOCKED.get());COMPARISONS.set(COMPARISONS.get()+1);
    Arc::ptr_eq(&self.0,&other.0)
}}
struct Entry(Object,u64);
impl Entry {fn object(&self)->&Object {&self.0}}
mod task {
    use super::*;
    pub struct Process(pub BTreeMap<u32,Entry>);
    impl Process {pub fn object_handles(&self)->&Self {self}
        pub fn get(&self,handle:ObjectHandle)->Option<&Entry> {
            assert!(LOCKED.get());LOOKUPS.set(LOOKUPS.get()+1);self.0.get(&handle.0)
        }
    }
    pub fn with_process<T>(id:u64,body:impl FnOnce(&Process)->T)->Option<T> {
        assert_eq!(id,19);
        if !PRESENT.get() {return None;}
        assert!(!LOCKED.replace(true));
        let result=PROCESS.with_borrow(body);
        assert!(LOCKED.replace(false));Some(result)
    }
}
mod production {use crate::{mnu_abi,ObjectHandle};
"#,
    );
    program.push_str(probe::between(
        include_str!("../../../core/src/syscall/handle.rs"),
        "pub fn same_object(",
        "const PROCESS_HANDLE_RIGHTS:",
    ));
    program.push_str(
        r#"
}
fn check(left:u64,right:u64,expected:u64) {
    DENY.store(true,Ordering::Relaxed);
    let result=production::same_object(left,right);
    DENY.store(false,Ordering::Relaxed);
    assert_eq!(result,expected);assert!(!LOCKED.get());
}
fn main() {
    let object=Arc::new(());let other=Arc::new(());
    PROCESS.with_borrow_mut(|p|{p.0.insert(7,Entry(Object(object.clone()),0));
        p.0.insert(8,Entry(Object(object.clone()),u64::MAX));
        p.0.insert(9,Entry(Object(other.clone()),0));});
    // Equal selectors still require an existing, caller-owned reference.
    check(7,7,1);check(7,8,1);check(8,7,1);check(7,9,0);check(9,7,0);
    assert_eq!(COMPARISONS.get(),5);
    for invalid in [0,1u64<<32,(1u64<<32)|7,u64::MAX] {
        LOOKUPS.set(0);check(invalid,7,Error::InvalidArgument.into_raw());
        check(7,invalid,Error::InvalidArgument.into_raw());assert_eq!(LOOKUPS.get(),0);
    }
    check(10,10,Error::InvalidArgument.into_raw());
    check(7,10,Error::InvalidArgument.into_raw());check(10,7,Error::InvalidArgument.into_raw());
    PRESENT.set(false);check(7,8,Error::NotReady.into_raw());PRESENT.set(true);
    CONTEXT.set(None);check(7,8,Error::NotReady.into_raw());CONTEXT.set(Some(19));
    assert_eq!(COMPARISONS.get(),5);
    assert_eq!(Arc::strong_count(&object),3);assert_eq!(Arc::strong_count(&other),2);
    PROCESS.with_borrow_mut(|p|{p.0.clear();});
    check(7,8,Error::InvalidArgument.into_raw());
    assert_eq!(Arc::strong_count(&object),1);assert_eq!(Arc::strong_count(&other),1);
}
"#,
    );
    probe::run(&program);
}
