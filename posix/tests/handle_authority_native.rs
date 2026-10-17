//! Execute the real selectors, rights, table operations and syscall bodies.
#[allow(dead_code)]
#[path = "support/native_error_probe.rs"]
mod probe;

#[allow(dead_code)]
#[path = "../../../core/crates/abi/src/status.rs"]
mod status;

#[test]
fn native_probes_expect_the_same_authority_status_not_a_compatibility_errno() {
    let expected = format!("INT64_C({})", status::Error::AccessDenied.into_raw() as i64);
    for (source, call) in [
        (
            include_str!("native_provider_memory_update.c"),
            "native(HANDLE_DUPLICATE, update, 256, 0, 0, 0, 0)",
        ),
        (
            include_str!("native_memory_admission.c"),
            "native(HANDLE_DUPLICATE, first, rights, 0, 0, 0, 0)",
        ),
        (
            include_str!("native_process_create.c"),
            "N(HANDLE_DUPLICATE, file, 1, 0)",
        ),
    ] {
        let assertion = source
            .split(call)
            .nth(1)
            .unwrap()
            .split(';')
            .next()
            .unwrap();
        assert!(assertion.contains(&expected));
    }
}

#[test]
fn queries_and_restricted_duplicates_keep_caller_scope_and_native_failures() {
    let table = include_str!("../../../core/src/task/handle_table.rs");
    let syscall = include_str!("../../../core/src/syscall/handle.rs");
    let mut program = String::from(
        r#"
#![allow(dead_code)]
extern crate alloc;
use std::{cell::{Cell,RefCell},sync::{Arc,atomic::{AtomicBool,Ordering}}};
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
    program.push_str("}\n");
    probe::constants(
        &mut program,
        include_str!("../../../core/crates/abi/src/lib.rs"),
        &["PROCESS_MAX_OBJECT_HANDLES"],
    );
    program.push_str("}\nuse mnu_abi::status::Error;\n");
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
        r#"
const PROCESS_MAX_OBJECT_HANDLES:usize=mnu_abi::PROCESS_MAX_OBJECT_HANDLES;
struct ObjectHandleTable {entries:Vec<(ObjectHandle,ObjectHandleEntry)>,next:u32,pending:HandleReservations,next_reservation:u64}
impl ObjectHandleTable {
    const fn new()->Self {Self{entries:Vec::new(),next:1,pending:HandleReservations(Vec::new()),next_reservation:1}}
"#,
    );
    for (start, end) in [
        (
            "    pub fn get(",
            "    /// Captures transferable references",
        ),
        (
            "    pub fn insert(",
            "    /// Installs an explicitly transferred object",
        ),
        (
            "    pub fn duplicate_restricted(",
            "    /// Creates the entry installed in another process",
        ),
    ] {
        program.push_str(probe::between(table, start, end));
    }
    program.push_str(
        r#"
}
thread_local! {
    static CONTEXT:Cell<Option<u64>>=const {Cell::new(Some(19))};
    static PRESENT:Cell<bool>=const {Cell::new(true)};
    static LOCKED:Cell<bool>=const {Cell::new(false)};
    static LOOKUPS:Cell<usize>=const {Cell::new(0)};
    static FIRST:RefCell<task::Process>=const {RefCell::new(task::Process(ObjectHandleTable::new()))};
    static SECOND:RefCell<task::Process>=const {RefCell::new(task::Process(ObjectHandleTable::new()))};
}
mod syscall {pub mod security {
    pub fn current_process_id()->Option<u64> {crate::CONTEXT.get()}
}}
mod task {
    use super::*;
    pub struct Process(pub ObjectHandleTable);
    impl Process {
        pub fn object_handles(&self)->&ObjectHandleTable {assert!(LOCKED.get());LOOKUPS.set(LOOKUPS.get()+1);&self.0}
        pub fn object_handles_mut(&mut self)->&mut ObjectHandleTable {assert!(LOCKED.get());LOOKUPS.set(LOOKUPS.get()+1);&mut self.0}
    }
    pub fn with_process<T>(id:u64,body:impl FnOnce(&Process)->T)->Option<T> {
        with_process_mut(id,|p|body(p))
    }
    pub fn with_process_mut<T>(id:u64,body:impl FnOnce(&mut Process)->T)->Option<T> {
        if !PRESENT.get() {return None;}
        assert!(!LOCKED.replace(true));
        let result=match id {19=>FIRST.with_borrow_mut(body),20=>SECOND.with_borrow_mut(body),_=>panic!("foreign table")};
        assert!(LOCKED.replace(false));Some(result)
    }
}
mod production {use crate::{mnu_abi,ObjectHandle,HandleRights};
"#,
    );
    program.push_str(probe::between(
        syscall,
        "pub fn duplicate(",
        "/// Compares two process-local handles",
    ));
    program.push_str(probe::between(
        syscall,
        "pub fn rights_get(",
        "/// Creates a native unidirectional byte stream",
    ));
    program.push_str(
        r#"
}
fn query(raw:u64,expected:u64) {
    DENY.store(true,Ordering::Relaxed);
    let result=production::rights_get(raw);
    DENY.store(false,Ordering::Relaxed);
    assert_eq!(result,expected);assert!(!LOCKED.get());
}
fn reject(raw:u64,rights:u64,error:Error) {
    let before=FIRST.with_borrow(|p|p.0.entries.len());
    DENY.store(true,Ordering::Relaxed);
    let result=production::duplicate(raw,rights);
    DENY.store(false,Ordering::Relaxed);
    assert_eq!(result,error.into_raw());assert!(!LOCKED.get());
    assert_eq!(FIRST.with_borrow(|p|p.0.entries.len()),before);
}
fn main() {
    let resource=Arc::new(());let foreign=Arc::new(());
    let full=HandleRights::ALL.bits();
    FIRST.with_borrow_mut(|p|{
        assert_eq!(p.0.insert(ObjectHandleEntry::new(KernelObject(resource.clone()),HandleRights::ALL)),ObjectHandle::from_raw(1));
        assert_eq!(p.0.insert(ObjectHandleEntry::new(KernelObject(resource.clone()),HandleRights::empty())),ObjectHandle::from_raw(2));
        assert_eq!(p.0.insert(ObjectHandleEntry::new(KernelObject(resource.clone()),HandleRights::READ)),ObjectHandle::from_raw(3));
    });
    SECOND.with_borrow_mut(|p|{p.0.entries.push((ObjectHandle(1),ObjectHandleEntry::new(KernelObject(foreign.clone()),HandleRights::WRITE)));
        p.0.entries.push((ObjectHandle(99),ObjectHandleEntry::new(KernelObject(foreign.clone()),HandleRights::ALL)));});
    query(1,full);query(2,0);query(3,HandleRights::READ.bits());
    for invalid in [0,1u64<<32,(1u64<<32)|1,u64::MAX] {
        LOOKUPS.set(0);query(invalid,Error::InvalidArgument.into_raw());
        reject(invalid,0,Error::InvalidArgument);assert_eq!(LOOKUPS.get(),0);
    }
    // Unknown rights do not reach the table, nor truncate high authority bits.
    for invalid in [1u64<<9,1u64<<61,full | (1u64<<9)] {
        LOOKUPS.set(0);reject(1,invalid,Error::InvalidArgument);assert_eq!(LOOKUPS.get(),0);
    }
    query(99,Error::InvalidArgument.into_raw());reject(99,0,Error::InvalidArgument);
    for no_duplicate in [2,3] {reject(no_duplicate,0,Error::AccessDenied);}
    LOOKUPS.set(0);CONTEXT.set(None);
    query(1,Error::NotReady.into_raw());reject(1,0,Error::NotReady);CONTEXT.set(Some(19));
    PRESENT.set(false);query(1,Error::NotReady.into_raw());reject(1,0,Error::NotReady);PRESENT.set(true);
    assert_eq!(LOOKUPS.get(),0);assert_eq!(Arc::strong_count(&resource),4);
    // Duplication retains the exact resource, but can remove DUPLICATE itself.
    let reduced=HandleRights::READ.union(HandleRights::DUPLICATE).bits();
    let first=production::duplicate(1,reduced);assert_eq!(first,4);query(first,reduced);
    reject(first,HandleRights::WRITE.bits(),Error::AccessDenied);
    reject(first,full,Error::AccessDenied);
    let second=production::duplicate(first,HandleRights::READ.bits());assert_eq!(second,5);
    query(second,HandleRights::READ.bits());reject(second,0,Error::AccessDenied);
    let empty=production::duplicate(first,0);assert_eq!(empty,6);query(empty,0);
    assert_eq!(Arc::strong_count(&resource),7);
    FIRST.with_borrow(|p|{
        for raw in [first,second,empty] {assert!(Arc::ptr_eq(&p.0.get(ObjectHandle(raw as u32)).unwrap().object().0,&resource));}
    });
    // The same selector in another process still describes that process only.
    CONTEXT.set(Some(20));query(1,HandleRights::WRITE.bits());reject(1,0,Error::AccessDenied);CONTEXT.set(Some(19));
    assert_eq!(Arc::strong_count(&foreign),3);
    FIRST.with_borrow_mut(|p|{
        while p.0.entries.len()<PROCESS_MAX_OBJECT_HANDLES {
            p.0.insert(ObjectHandleEntry::new(KernelObject(resource.clone()),HandleRights::empty())).unwrap();
        }
    });
    let references=Arc::strong_count(&resource);
    reject(1,0,Error::ResourceUnavailable);
    assert_eq!(Arc::strong_count(&resource),references);
    // No reference leak on capacity failure; existing entries remain usable.
    query(1,full);query(first,reduced);
    FIRST.with_borrow_mut(|p|{assert!(p.0.close(ObjectHandle(1)));});
    query(1,Error::InvalidArgument.into_raw());reject(1,0,Error::InvalidArgument);
    query(first,reduced);
    FIRST.with_borrow_mut(|p|p.0.entries.clear());
    SECOND.with_borrow_mut(|p|p.0.entries.clear());
    assert_eq!(Arc::strong_count(&resource),1);assert_eq!(Arc::strong_count(&foreign),1);
}
"#,
    );
    probe::run(&program);
}
