//! Exercise the production selector/authority checks without legacy errno shims.
#[allow(dead_code)]
#[path = "support/native_error_probe.rs"]
mod probe;

#[test]
fn identity_is_visible_only_through_a_caller_handle_on_the_exact_owner_endpoint() {
    let mut program = String::from(
        r#"
#![allow(dead_code)]
extern crate alloc;
use std::{cell::{Cell, RefCell}, sync::Arc};
use mnu_abi::status::Error;
thread_local! {
    static PROCESS_PRESENT: Cell<bool> = const { Cell::new(true) };
    static TABLE_PRESENT: Cell<bool> = const { Cell::new(true) };
    static CURRENT: Cell<Option<u64>> = const { Cell::new(Some(31)) };
    static ENDPOINT: Cell<Option<(u16,u64)>> = const { Cell::new(Some((4,8))) };
    static LOOKUPS: Cell<usize> = const { Cell::new(0) };
    static PROCESS: RefCell<task::Process> = const { RefCell::new(task::Process(task::Table(None))) };
}
mod mnu_abi {pub mod status {
"#,
    );
    program.push_str(include_str!("../../../core/crates/abi/src/status.rs"));
    program.push_str(
        r#"
}}
mod task {
    use super::*;
    pub struct Thread(u64);
    impl Thread {pub fn as_u64(&self)->u64 {self.0}}
    pub fn current_thread_id()->Option<Thread> {CURRENT.get().map(Thread)}
    #[derive(Clone,Copy)]pub struct HandleRights(u64);
    impl HandleRights {
        pub fn empty()->Self {Self(0)}
        pub fn contains(self, other:Self)->bool {self.0 & other.0 == other.0}
    }
    pub struct ObjectHandle(u32);
    impl ObjectHandle {pub fn from_raw(raw:u32)->Option<Self> {(raw!=0).then_some(Self(raw))}}
    pub struct Provider {
        pub endpoint_thread_id:u64, pub endpoint_slot:u16,
        pub endpoint_generation:u64, pub object_id:u64,
    }
    #[derive(Clone)]pub enum KernelObject {Provider(Arc<Provider>), Other}
    pub struct Entry(pub KernelObject);
    impl Entry {
        pub fn rights(&self)->HandleRights {HandleRights::empty()}
        pub fn object(&self)->&KernelObject {&self.0}
    }
    pub struct Table(pub Option<Entry>);
    impl Table {
        pub fn get(&self, handle:ObjectHandle)->Option<&Entry> {
            LOOKUPS.set(LOOKUPS.get()+1);
            if handle.0!=7 {return None;}
            self.0.as_ref()
        }
    }
    pub struct Process(pub Table);
    impl Process {pub fn object_handles(&self)->&Table {&self.0}}
    pub fn with_process<T>(id:u64, body:impl FnOnce(&Process)->T)->Option<T> {
        assert_eq!(id,19);
        TABLE_PRESENT.get().then(||PROCESS.with_borrow(body))
    }
}
mod syscall {
    pub mod security {
        pub fn current_process_id()->Option<u64> {crate::PROCESS_PRESENT.get().then_some(19)}
    }
    pub mod ipc {
        pub struct Endpoint {pub thread_id:u64,pub slot:u16,pub generation:u64}
        pub fn endpoint_for_thread(thread:u64)->Option<Endpoint> {
            crate::ENDPOINT.get().map(|(slot,generation)|Endpoint{thread_id:thread,slot,generation})
        }
    }
}
mod production {
use crate::{mnu_abi, task::{HandleRights,KernelObject,ObjectHandle}};
"#,
    );
    let source = include_str!("../../../core/src/syscall/handle.rs");
    program.push_str(probe::between(
        source,
        "pub(crate) fn object_native(",
        "pub(crate) fn object_with_rights(",
    ));
    program.push_str(probe::between(
        source,
        "pub fn provider_object_identify(",
        "/// Updates native readiness signals",
    ));
    program.push_str(
        r#"
}
fn check(raw:u64, expected:u64) {
    assert_eq!(production::provider_object_identify(raw),expected);
}
fn main() {
    let provider=Arc::new(task::Provider{endpoint_thread_id:31,endpoint_slot:4,endpoint_generation:8,object_id:42});
    PROCESS.with_borrow_mut(|p|p.0.0=Some(task::Entry(task::KernelObject::Provider(provider.clone()))));
    for raw in [0,1u64<<32,(1u64<<32)|7,u64::MAX] {
        LOOKUPS.set(0);check(raw,Error::InvalidArgument.into_raw());assert_eq!(LOOKUPS.get(),0);
    }
    check(8,Error::InvalidArgument.into_raw());
    PROCESS_PRESENT.set(false);check(7,Error::NotReady.into_raw());PROCESS_PRESENT.set(true);
    TABLE_PRESENT.set(false);check(7,Error::NotReady.into_raw());TABLE_PRESENT.set(true);
    CURRENT.set(None);check(7,Error::NotReady.into_raw());CURRENT.set(Some(31));
    ENDPOINT.set(None);check(7,Error::NotReady.into_raw());
    for (thread,slot,generation) in [(32,4,8),(31,5,8),(31,4,9)] {
        CURRENT.set(Some(thread));ENDPOINT.set(Some((slot,generation)));
        check(7,Error::AccessDenied.into_raw());
        assert_eq!(Arc::strong_count(&provider),2);
    }
    CURRENT.set(Some(31));ENDPOINT.set(Some((4,8)));check(7,42);
    assert_eq!(Arc::strong_count(&provider),2,"identification must not retain an observation");
    PROCESS.with_borrow_mut(|p|p.0.0=Some(task::Entry(task::KernelObject::Other)));
    check(7,Error::InvalidArgument.into_raw());assert_eq!(Arc::strong_count(&provider),1);
    PROCESS.with_borrow_mut(|p|p.0.0=None);check(7,Error::InvalidArgument.into_raw());
}
"#,
    );
    probe::run(&program);
}
