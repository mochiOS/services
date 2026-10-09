extern crate alloc;

#[path = "../../../core/src/mem/object_io.rs"]
mod object_io;

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

#[test]
fn backing_keys_share_ordering_without_serializing_unrelated_objects() {
    let mut registry = object_io::Registry::new();
    let first = registry.get(7);
    let alias = registry.get(7);
    let other = registry.get(8);
    let guard = first.lock(|| panic!("first owner must acquire"));
    let independent = other.lock(|| panic!("unrelated backing must not wait"));
    drop(independent);
    let mut waited = false;
    let mut owner = Some(guard);
    let acquired = alias.lock(|| {
        waited = true;
        drop(owner.take());
    });
    assert!(waited);
    drop(acquired);
    let _again = first.lock(|| panic!("drop must release ownership"));
}

#[test]
fn concurrent_writeback_and_write_sections_do_not_overlap() {
    let mut registry = object_io::Registry::new();
    let gate = registry.get(7);
    let active = Arc::new(AtomicUsize::new(0));
    let finished = Arc::new(AtomicUsize::new(0));
    std::thread::scope(|scope| {
        for _ in 0..8 {
            let gate = gate.clone();
            let active = active.clone();
            let finished = finished.clone();
            scope.spawn(move || {
                for _ in 0..64 {
                    let _guard = gate.lock(std::thread::yield_now);
                    assert_eq!(active.fetch_add(1, Ordering::SeqCst), 0);
                    std::thread::yield_now();
                    assert_eq!(active.fetch_sub(1, Ordering::SeqCst), 1);
                    finished.fetch_add(1, Ordering::SeqCst);
                }
            });
        }
    });
    assert_eq!(finished.load(Ordering::SeqCst), 512);
}
