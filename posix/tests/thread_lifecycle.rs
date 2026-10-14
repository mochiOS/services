use mochios_posix_client::thread_lifecycle::{EnterError, Gate};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

#[test]
fn preparation_and_reclamation_can_nest_but_exclude_capture() {
    let gate = Gate::new();
    let first = gate.try_enter().unwrap();
    let nested = gate.try_enter().unwrap();
    assert!(gate.try_freeze().is_none());
    drop(first);
    assert!(gate.try_freeze().is_none());
    drop(nested);
    let capture = gate.try_freeze().unwrap();
    assert!(matches!(gate.try_enter(), Err(EnterError::Frozen(_))));
    assert!(gate.try_freeze().is_none());
    // Another process's private gate must remain independent.
    assert!(Gate::new().try_enter().is_ok());
    drop(capture);
    assert!(gate.try_enter().is_ok());
}

#[test]
fn failure_paths_release_activity_and_capture() {
    let gate = Gate::new();
    let failed: Result<(), ()> = (|| {
        let _activity = gate.try_enter().unwrap();
        Err(())
    })();
    assert_eq!(failed, Err(()));
    let failed: Result<(), ()> = (|| {
        let _capture = gate.try_freeze().unwrap();
        Err(())
    })();
    assert_eq!(failed, Err(()));
    assert!(gate.try_enter().is_ok());
    assert!(gate.try_freeze().is_some());
}

#[test]
fn activity_count_never_wraps_into_the_frozen_bit() {
    let gate = Gate::new();
    gate.word().store((1 << 31) - 1, Ordering::Relaxed);
    assert!(matches!(gate.try_enter(), Err(EnterError::Exhausted)));
    assert_eq!(gate.word().load(Ordering::Relaxed), (1 << 31) - 1);
    assert!(gate.try_freeze().is_none());
}

#[test]
fn capture_never_observes_an_in_progress_thread_mutation() {
    let gate = Arc::new(Gate::new());
    let mutating = Arc::new(AtomicUsize::new(0));
    let completed = Arc::new(AtomicUsize::new(0));
    let workers: Vec<_> = (0..4)
        .map(|_| {
            let (gate, mutating, completed) = (gate.clone(), mutating.clone(), completed.clone());
            std::thread::spawn(move || {
                for _ in 0..1000 {
                    let activity = loop {
                        match gate.try_enter() {
                            Ok(activity) => break activity,
                            Err(EnterError::Frozen(_)) => std::thread::yield_now(),
                            Err(EnterError::Exhausted) => panic!("unexpected lease exhaustion"),
                        }
                    };
                    mutating.fetch_add(1, Ordering::Relaxed);
                    std::thread::yield_now();
                    mutating.fetch_sub(1, Ordering::Relaxed);
                    completed.fetch_add(1, Ordering::Relaxed);
                    drop(activity);
                }
            })
        })
        .collect();
    for _ in 0..1000 {
        if let Some(_capture) = gate.try_freeze() {
            assert_eq!(mutating.load(Ordering::Relaxed), 0);
            assert!(gate.try_enter().is_err());
        }
        std::thread::yield_now();
    }
    for worker in workers {
        worker.join().unwrap();
    }
    let _capture = gate.try_freeze().unwrap();
    assert_eq!(completed.load(Ordering::Relaxed), 4000);
    assert_eq!(mutating.load(Ordering::Relaxed), 0);
}
