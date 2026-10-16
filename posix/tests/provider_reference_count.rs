extern crate alloc;
use mnu_abi::status::Error;
use std::{
    cell::{Cell, RefCell},
    collections::BTreeMap,
    sync::{Arc, Weak},
};
type Key = (u64, u16, u64, u64);
thread_local! {
    static CURRENT: Cell<Option<u64>> = const { Cell::new(Some(10)) };
    static GENERATION: Cell<u64> = const { Cell::new(1) };
    static ENDPOINT_PRESENT: Cell<bool> = const { Cell::new(true) };
    static LOOKUPS: Cell<usize> = const { Cell::new(0) };
    static OBJECTS: RefCell<BTreeMap<Key, Weak<()>>> = const { RefCell::new(BTreeMap::new()) };
}
mod task {
    pub struct Thread(pub u64);
    impl Thread {
        pub fn as_u64(&self) -> u64 {
            self.0
        }
    }
    pub fn current_thread_id() -> Option<Thread> {
        crate::CURRENT.get().map(Thread)
    }
    pub mod handle_table {
        pub fn provider_object(
            thread: u64,
            slot: u16,
            generation: u64,
            object: u64,
        ) -> Option<std::sync::Arc<()>> {
            crate::LOOKUPS.set(crate::LOOKUPS.get() + 1);
            crate::OBJECTS.with(|objects| {
                objects
                    .borrow()
                    .get(&(thread, slot, generation, object))
                    .and_then(std::sync::Weak::upgrade)
            })
        }
    }
}
mod syscall {
    pub mod ipc {
        pub struct Endpoint {
            pub thread_id: u64,
            pub slot: u16,
            pub generation: u64,
        }
        pub fn endpoint_for_thread(thread: u64) -> Option<Endpoint> {
            if !crate::ENDPOINT_PRESENT.get() {
                return None;
            }
            Some(Endpoint {
                thread_id: thread,
                slot: 3,
                generation: crate::GENERATION.get(),
            })
        }
    }
}
#[path = "../../../core/src/syscall/handle/provider_reference.rs"]
mod production;
fn register(thread: u64, generation: u64, id: u64) -> Arc<()> {
    let object = Arc::new(());
    OBJECTS.with(|objects| {
        objects
            .borrow_mut()
            .insert((thread, 3, generation, id), Arc::downgrade(&object))
    });
    object
}
#[test]
fn samples_all_real_references_but_not_weak_registry_or_query_and_does_not_pin() {
    CURRENT.set(Some(10));
    GENERATION.set(1);
    let object = register(10, 1, 42);
    let handle = object.clone();
    let queued_attachment = object.clone();
    assert_eq!(production::count(42), 3);
    assert_eq!(Arc::strong_count(&object), 3);
    drop(handle);
    assert_eq!(production::count(42), 2);
    drop(queued_attachment);
    assert_eq!(production::count(42), 1);
    drop(object);
    assert_eq!(production::count(42), Error::InvalidArgument.into_raw());
}
#[test]
fn exact_endpoint_identity_scopes_counts_and_reused_ids_cannot_observe_old_objects() {
    let parent = register(10, 1, 99);
    let alias = parent.clone();
    let other = register(11, 1, 99);
    CURRENT.set(Some(10));
    GENERATION.set(1);
    assert_eq!(production::count(99), 2);
    CURRENT.set(Some(11));
    assert_eq!(production::count(99), 1);
    GENERATION.set(2);
    assert_eq!(production::count(99), Error::InvalidArgument.into_raw());
    let fresh = register(11, 2, 99);
    assert_eq!(production::count(99), 1);
    assert_eq!(Arc::strong_count(&alias), 2);
    assert_eq!(Arc::strong_count(&other), 1);
    assert_eq!(Arc::strong_count(&fresh), 1);
}
#[test]
fn absent_caller_and_invalid_or_foreign_object_ids_fail_without_authority_lookup() {
    LOOKUPS.set(0);
    CURRENT.set(None);
    assert_eq!(production::count(42), Error::NotReady.into_raw());
    CURRENT.set(Some(12));
    GENERATION.set(1);
    ENDPOINT_PRESENT.set(false);
    assert_eq!(production::count(42), Error::NotReady.into_raw());
    ENDPOINT_PRESENT.set(true);
    for id in [u64::MAX, i64::MAX as u64 + 1] {
        assert_eq!(production::count(id), Error::InvalidArgument.into_raw());
    }
    assert_eq!(LOOKUPS.get(), 0);
    let foreign = register(10, 1, 42);
    assert_eq!(production::count(42), Error::InvalidArgument.into_raw());
    let zero = register(12, 1, 0);
    assert_eq!(production::count(0), 1);
    assert_eq!(Arc::strong_count(&zero), 1);
    assert_eq!(Arc::strong_count(&foreign), 1);
    assert_eq!(
        mnu_abi::SyscallNumber::ProviderObjectReferenceCount as u64,
        691
    );
}
