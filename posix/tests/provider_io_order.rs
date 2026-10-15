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
    let guard = first.lock(|| panic!("first owner must acquire")).unwrap();
    let independent = other
        .lock(|| panic!("unrelated backing must not wait"))
        .unwrap();
    drop(independent);
    let mut waited = false;
    let mut owner = Some(guard);
    let acquired = alias
        .lock(|| {
            waited = true;
            drop(owner.take());
        })
        .unwrap();
    assert!(waited);
    drop(acquired);
    let _again = first
        .lock(|| panic!("drop must release ownership"))
        .unwrap();
}

#[test]
fn owner_admission_never_waits_for_an_outstanding_caller() {
    let mut registry = object_io::Registry::new();
    let first = gate(&mut registry, 7);
    let alias = gate(&mut registry, 7);
    let other = gate(&mut registry, 8);
    let request = first.try_lock().unwrap().expect("first caller acquires");
    for _ in 0..64 {
        assert!(alias.try_lock().unwrap().is_none());
    }
    let independent = other
        .try_lock()
        .unwrap()
        .expect("different backing stays available");
    drop(independent);
    // Failed owner admission must not unlock the caller's critical section.
    assert!(first.try_lock().unwrap().is_none());
    drop(request);
    let owner = alias
        .try_lock()
        .unwrap()
        .expect("retry after caller completion");
    drop(first);
    drop(alias);
    // The guard alone keeps canonical ownership alive across handle teardown.
    let survivor = registry
        .try_get(7, || -> Result<_, ()> { panic!("live guard lost") }, ())
        .unwrap();
    assert!(survivor.try_lock().unwrap().is_none());
    drop(owner);
    assert!(survivor.try_lock().unwrap().is_some());
}

#[test]
fn reservation_invalidates_snapshots_and_releases_admission_on_cancel() {
    let mut registry = object_io::Registry::new();
    let gate = gate(&mut registry, 7);
    let generation = gate.generation();
    let request = gate.try_lock().unwrap().unwrap();
    assert!(!gate.is_reserved());
    assert_eq!(gate.generation(), generation);
    let reservation = request.reserve();
    assert!(gate.is_reserved());
    assert_ne!(gate.generation(), generation);
    assert!(gate.try_lock().unwrap().is_none());
    let reserved_generation = gate.generation();
    drop(reservation);
    assert!(!gate.is_reserved());
    assert_eq!(gate.generation(), reserved_generation);
    assert!(gate.try_lock().unwrap().is_some());
}

#[test]
fn unavailable_reservation_is_sticky_idempotent_and_isolated_from_other_backings() {
    let mut registry = object_io::Registry::new();
    let first = gate(&mut registry, 7);
    let alias = gate(&mut registry, 7);
    let other = gate(&mut registry, 8);
    let owner = first.try_lock().unwrap().unwrap().reserve();
    let generation = first.generation();
    owner.mark_unavailable();
    assert!(alias.is_unavailable());
    assert_ne!(alias.generation(), generation);
    let failed_generation = alias.generation();
    owner.mark_unavailable();
    assert_eq!(alias.generation(), failed_generation);
    assert_eq!(alias.try_lock().err(), Some(object_io::Unavailable));
    assert_eq!(
        alias.lock(|| panic!("unavailable is not busy")).err(),
        Some(object_io::Unavailable)
    );
    drop(owner);
    assert!(!alias.is_reserved());
    assert!(alias.is_unavailable());
    assert_eq!(alias.try_lock().err(), Some(object_io::Unavailable));
    let independent = other
        .lock(|| panic!("unrelated backing must stay available"))
        .unwrap();
    drop(independent);
    let retained = registry
        .try_get(7, || -> Result<_, ()> { panic!("lost live failure") }, ())
        .unwrap();
    assert!(retained.is_unavailable());
}

#[test]
fn waiting_io_stops_when_the_current_owner_marks_backing_unavailable() {
    let mut registry = object_io::Registry::new();
    let first = gate(&mut registry, 7);
    let alias = gate(&mut registry, 7);
    let mut owner = Some(first.try_lock().unwrap().unwrap().reserve());
    let mut waits = 0;
    let result = alias.lock(|| {
        waits += 1;
        owner.as_ref().unwrap().mark_unavailable();
        drop(owner.take());
    });
    assert_eq!(result.err(), Some(object_io::Unavailable));
    assert_eq!(waits, 1);
}

#[test]
fn concurrent_waiters_never_acquire_after_unavailable_owner_releases() {
    for _ in 0..16 {
        let mut registry = object_io::Registry::new();
        let gate = gate(&mut registry, 7);
        let owner = gate.try_lock().unwrap().unwrap().reserve();
        let ready = Arc::new(std::sync::Barrier::new(9));
        std::thread::scope(|scope| {
            let mut workers = Vec::new();
            for _ in 0..8 {
                let gate = gate.clone();
                let ready = ready.clone();
                workers.push(scope.spawn(move || {
                    ready.wait();
                    gate.lock(std::thread::yield_now).err()
                }));
            }
            ready.wait();
            owner.mark_unavailable();
            drop(owner);
            for worker in workers {
                assert_eq!(worker.join().unwrap(), Some(object_io::Unavailable));
            }
        });
    }
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
                    let _guard = gate.lock(std::thread::yield_now).unwrap();
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
    let mut owner = Some(first.lock(|| panic!("uncontended gate")).unwrap());
    let mut waited = false;
    let acquired = alias
        .lock(|| {
            waited = true;
            drop(owner.take());
        })
        .unwrap();
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
