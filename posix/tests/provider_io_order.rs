extern crate alloc;

#[path = "../../../core/src/mem/object_io.rs"]
mod object_io;

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

#[test]
fn cache_generations_follow_backing_identity_not_unrelated_io() {
    let mut registry = object_io::Registry::new();
    let first = gate(&mut registry, 7);
    let alias = gate(&mut registry, 7);
    let other = gate(&mut registry, 8);
    let initial = first.generation();
    alias.advance_generation();
    assert_eq!(first.generation(), initial + 1);
    assert_eq!(other.generation(), initial);
    assert_eq!(registry.existing(&7).unwrap().generation(), initial + 1);
    assert!(registry.existing(&9).is_none());
}

fn gate(registry: &mut object_io::Registry<u64>, key: u64) -> object_io::IoLock {
    registry
        .try_get(
            key,
            || {
                Ok(object_io::IoLock::from_allocated(Arc::new(
                    object_io::State::new(),
                )))
            },
            (),
        )
        .unwrap()
}

#[test]
fn backing_keys_share_ordering_without_serializing_unrelated_objects() {
    let mut registry = object_io::Registry::new();
    let first = gate(&mut registry, 7);
    let alias = gate(&mut registry, 7);
    let other = gate(&mut registry, 8);
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
fn owner_admission_never_waits_for_an_outstanding_caller() {
    let mut registry = object_io::Registry::new();
    let first = gate(&mut registry, 7);
    let alias = gate(&mut registry, 7);
    let other = gate(&mut registry, 8);
    let request = first.try_lock().expect("first caller acquires");
    for _ in 0..64 {
        assert!(alias.try_lock().is_none());
    }
    let independent = other.try_lock().expect("different backing stays available");
    drop(independent);
    // Failed owner admission must not unlock the caller's critical section.
    assert!(first.try_lock().is_none());
    drop(request);
    let owner = alias.try_lock().expect("retry after caller completion");
    drop(first);
    drop(alias);
    // The guard alone keeps canonical ownership alive across handle teardown.
    let survivor = registry
        .try_get(7, || -> Result<_, ()> { panic!("live guard lost") }, ())
        .unwrap();
    assert!(survivor.try_lock().is_none());
    drop(owner);
    assert!(survivor.try_lock().is_some());
}

#[test]
fn reservation_invalidates_snapshots_and_releases_admission_on_cancel() {
    let mut registry = object_io::Registry::new();
    let gate = gate(&mut registry, 7);
    let generation = gate.generation();
    let request = gate.try_lock().unwrap();
    assert!(!gate.is_reserved());
    assert_eq!(gate.generation(), generation);
    let reservation = request.reserve();
    assert!(gate.is_reserved());
    assert_ne!(gate.generation(), generation);
    assert!(gate.try_lock().is_none());
    let reserved_generation = gate.generation();
    drop(reservation);
    assert!(!gate.is_reserved());
    assert_eq!(gate.generation(), reserved_generation);
    assert!(gate.try_lock().is_some());
}

#[test]
fn concurrent_writeback_and_write_sections_do_not_overlap() {
    let mut registry = object_io::Registry::new();
    let gate = gate(&mut registry, 7);
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

#[test]
fn failed_gate_creation_does_not_publish_and_live_gates_do_not_allocate() {
    let mut registry = object_io::Registry::new();
    assert_eq!(registry.try_get(7, || Err(12), 99).err(), Some(12));
    let first = gate(&mut registry, 7);
    let alias = registry
        .try_get(
            7,
            || -> Result<_, u8> { panic!("live registration must not invoke the allocator") },
            99,
        )
        .unwrap();
    let mut owner = Some(first.lock(|| panic!("uncontended gate")));
    let mut waited = false;
    let acquired = alias.lock(|| {
        waited = true;
        drop(owner.take());
    });
    assert!(waited);
    drop(acquired);
    drop(first);
    // A surviving alias keeps the weak registration reusable across gaps.
    let survivor = registry
        .try_get(7, || -> Result<_, u8> { panic!("alias lost identity") }, 99)
        .unwrap();
    drop(alias);
    drop(survivor);
    assert_eq!(registry.try_get(7, || Err(12), 99).err(), Some(12));
}
