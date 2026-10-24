#[path = "support/fifo_manager.rs"]
#[allow(dead_code)]
mod helpers;
use posix_service::{
    fifo::Access,
    fifo_manager::{FilesystemScope, Manager},
};
use std::{
    alloc::{GlobalAlloc, Layout, System},
    cell::Cell,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

thread_local! {static FAIL_AFTER:Cell<Option<usize>>=const{Cell::new(None)};}
fn fail() -> bool {
    FAIL_AFTER.with(|state| match state.get() {
        Some(0) => {
            state.set(None);
            true
        }
        Some(count) => {
            state.set(Some(count - 1));
            false
        }
        None => false,
    })
}
struct Allocator;
unsafe impl GlobalAlloc for Allocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if fail() {
            std::ptr::null_mut()
        } else {
            unsafe { System.alloc(layout) }
        }
    }
    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        if fail() {
            std::ptr::null_mut()
        } else {
            unsafe { System.realloc(pointer, layout, size) }
        }
    }
    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        unsafe { System.dealloc(pointer, layout) }
    }
}
#[global_allocator]
static ALLOCATOR: Allocator = Allocator;

#[test]
fn every_new_channel_allocation_failure_releases_metadata_before_native_creation() {
    let scope = FilesystemScope::new().unwrap();
    for allocation in 0..3 {
        let mut manager = Manager::default();
        let closed = Arc::new(AtomicUsize::new(0));
        let admitted = helpers::admit(scope, 17, Access::Read, &closed);
        let native_calls = Cell::new(0);
        FAIL_AFTER.set(Some(allocation));
        let result = manager.open(
            admitted,
            true,
            |_, _, _| {
                native_calls.set(native_calls.get() + 1);
                Ok(900)
            },
            |_| panic!("no native reference existed"),
        );
        let unconsumed = FAIL_AFTER.replace(None);
        assert_eq!(unconsumed, None);
        assert_eq!(result.err(), Some(-12));
        assert_eq!(native_calls.get(), 0);
        assert_eq!(closed.load(Ordering::Relaxed), 1);
        let fresh = helpers::open(
            &mut manager,
            helpers::admit(scope, 17, Access::Read, &closed),
        );
        assert!(manager.readiness(fresh.object_id).unwrap().end_of_stream);
        helpers::release(&mut manager, fresh.object_id);
        assert_eq!(closed.load(Ordering::Relaxed), 2);
    }
}
