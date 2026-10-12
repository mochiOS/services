#[path = "../../../user/crates/posix-client/src/pthread_mutex.rs"]
mod implementation;

use implementation::{DEFAULT, ERRORCHECK, Error, Mutex, NORMAL, RECURSIVE};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

#[test]
fn normal_default_and_errorcheck_have_their_own_relock_semantics() {
    for kind in [NORMAL, DEFAULT, ERRORCHECK] {
        let lock = Mutex::new(kind);
        assert_eq!(lock.try_lock(1), Ok(()));
        assert_eq!(lock.try_lock(1), Err(Error::Busy));
        assert_eq!(lock.try_lock(2), Err(Error::Busy));
        assert_eq!(
            lock.unlock(2, |_| panic!("not owner")),
            Err(Error::NotOwner)
        );
        assert_eq!(lock.destroy(), Err(Error::Busy));
        let mut waited = false;
        let result = lock.lock(1, |_, expected| {
            assert_eq!(expected, 2);
            waited = true;
            Err(99)
        });
        if kind == ERRORCHECK {
            assert_eq!(result, Ok(Err(Error::Deadlock)));
            assert!(!waited);
        } else {
            assert_eq!(result, Err(99));
            assert!(waited);
        }
        assert_eq!(lock.unlock(1, |_| {}), Ok(()));
        assert_eq!(lock.destroy(), Ok(()));
        assert_eq!(lock.try_lock(1), Err(Error::Invalid));
    }
}

#[test]
fn recursive_release_wakes_only_after_the_last_unlock() {
    let lock = Mutex::new(RECURSIVE);
    for _ in 0..4 {
        assert_eq!(lock.try_lock(1), Ok(()));
    }
    assert_eq!(lock.lock(1, |_, _| Err::<(), ()>(())), Ok(Ok(())));
    assert_eq!(lock.unlock(2, |_| panic!()), Err(Error::NotOwner));
    for _ in 0..4 {
        assert_eq!(lock.unlock(1, |_| panic!()), Ok(()));
        assert_eq!(lock.try_lock(2), Err(Error::Busy));
    }
    assert_eq!(lock.unlock(1, |_| panic!()), Ok(()));
    assert_eq!(lock.try_lock(2), Ok(()));
    assert_eq!(lock.unlock(2, |_| {}), Ok(()));
}

#[test]
fn wait_error_releases_waiter_accounting_without_abandoning_the_owner() {
    let lock = Mutex::new(NORMAL);
    assert_eq!(lock.try_lock(1), Ok(()));
    assert_eq!(lock.lock(2, |_, _| Err(99)), Err(99));
    let wakes = AtomicUsize::new(0);
    assert_eq!(
        lock.unlock(1, |_| {
            wakes.fetch_add(1, Ordering::Relaxed);
        }),
        Ok(())
    );
    assert_eq!(wakes.load(Ordering::Relaxed), 1);
    assert_eq!(lock.destroy(), Ok(()));
}

#[test]
fn a_waiter_prevents_destroy_even_in_the_unlocked_wakeup_window() {
    let lock = Mutex::new(NORMAL);
    lock.try_lock(1).unwrap();
    let mut calls = 0;
    assert_eq!(
        lock.lock(2, |_, _| {
            calls += 1;
            lock.unlock(1, |_| {}).unwrap();
            assert_eq!(lock.destroy(), Err(Error::Busy));
            Ok::<(), ()>(())
        }),
        Ok(Ok(()))
    );
    assert_eq!(calls, 1);
    lock.unlock(2, |_| {}).unwrap();
    lock.destroy().unwrap();
}

#[test]
fn contended_threads_publish_protected_data_to_the_next_owner() {
    let lock = Arc::new(Mutex::new(NORMAL));
    let count = Arc::new(AtomicUsize::new(0));
    let mut threads = Vec::new();
    for owner in 1..=6 {
        let lock = Arc::clone(&lock);
        let count = Arc::clone(&count);
        threads.push(std::thread::spawn(move || {
            for _ in 0..2000 {
                assert_eq!(
                    lock.lock(owner, |_, _| {
                        std::thread::yield_now();
                        Ok::<(), ()>(())
                    }),
                    Ok(Ok(()))
                );
                let previous = count.load(Ordering::Relaxed);
                count.store(previous + 1, Ordering::Relaxed);
                lock.unlock(owner, |_| {}).unwrap();
            }
        }));
    }
    for thread in threads {
        thread.join().unwrap();
    }
    assert_eq!(count.load(Ordering::Relaxed), 12000);
    lock.destroy().unwrap();
}
