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
        assert_eq!(lock.check_owner(1), Ok(()));
        assert_eq!(lock.check_owner(2), Err(Error::NotOwner));
        assert_eq!(lock.try_lock(1), Err(Error::Busy));
        assert_eq!(lock.try_lock(2), Err(Error::Busy));
        assert_eq!(
            lock.unlock(2, |_| panic!("not owner")),
            Err(Error::NotOwner)
        );
        assert_eq!(lock.destroy(), Err(Error::Busy));
        let mut waited = false;
        let result = lock.lock(
            1,
            |_, expected| {
                assert_eq!(expected, 2);
                waited = true;
                Err(99)
            },
            |_| panic!("the mutex is still owned"),
        );
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
    assert_eq!(
        lock.lock(1, |_, _| Err::<(), ()>(()), |_| panic!()),
        Ok(Ok(()))
    );
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
    assert_eq!(
        lock.lock(2, |_, _| Err(99), |_| panic!("still owned")),
        Err(99)
    );
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
fn failed_selected_waiter_hands_unlock_notification_to_a_sleeping_waiter() {
    use std::sync::{Mutex as Queue, mpsc};
    use std::time::Duration;

    let lock = Arc::new(Mutex::new(NORMAL));
    lock.try_lock(1).unwrap();
    let queue = Arc::new(Queue::new(std::collections::VecDeque::new()));
    let (admitted, admission) = mpsc::channel();
    let (fail, failure) = mpsc::channel();
    let mut failure = Some(failure);
    let (finished, completion) = mpsc::channel();
    let wake = |queue: &Queue<std::collections::VecDeque<mpsc::Sender<()>>>| {
        if let Some(waiter) = queue.lock().unwrap().pop_front() {
            waiter.send(()).unwrap();
        }
    };
    let mut threads = Vec::new();
    for owner in [2, 3] {
        let lock = Arc::clone(&lock);
        let queue = Arc::clone(&queue);
        let admitted = admitted.clone();
        let finished = finished.clone();
        let failure = if owner == 2 { failure.take() } else { None };
        threads.push(std::thread::spawn(move || {
            let result = lock.lock(
                owner,
                |address, expected| {
                    let (notify, notification) = mpsc::channel();
                    {
                        let mut queue = queue.lock().unwrap();
                        if address.load(Ordering::Acquire) != expected {
                            return Ok(());
                        }
                        queue.push_back(notify);
                        admitted.send(owner).unwrap();
                    }
                    notification.recv_timeout(Duration::from_secs(5)).unwrap();
                    if let Some(failure) = &failure {
                        failure.recv_timeout(Duration::from_secs(5)).unwrap();
                        Err(99)
                    } else {
                        Ok(())
                    }
                },
                |_| wake(&queue),
            );
            if owner == 2 {
                assert_eq!(result, Err(99));
            } else {
                assert_eq!(result, Ok(Ok(())));
                lock.unlock(owner, |_| wake(&queue)).unwrap();
            }
            finished.send(owner).unwrap();
        }));
        assert_eq!(
            admission.recv_timeout(Duration::from_secs(5)).unwrap(),
            owner
        );
    }
    lock.unlock(1, |_| wake(&queue)).unwrap(); // Only waiter 2 receives this wake.
    fail.send(()).unwrap(); // It must hand the wake to waiter 3 before returning.
    let mut completed = [
        completion.recv_timeout(Duration::from_secs(5)).unwrap(),
        completion.recv_timeout(Duration::from_secs(5)).unwrap(),
    ];
    completed.sort();
    assert_eq!(completed, [2, 3]);
    for thread in threads {
        thread.join().unwrap();
    }
    assert!(queue.lock().unwrap().is_empty());
    lock.destroy().unwrap();
}

#[test]
fn failed_wait_handoff_keeps_its_registration_until_wake_finishes() {
    let lock = Mutex::new(NORMAL);
    lock.try_lock(1).unwrap();
    let mut replacements = 0;
    assert_eq!(
        lock.lock(
            2,
            |_, _| {
                lock.unlock(1, |_| {}).unwrap();
                Err(99)
            },
            |word| {
                assert_eq!(word.load(Ordering::Acquire), 0);
                assert_eq!(lock.destroy(), Err(Error::Busy));
                replacements += 1;
            }
        ),
        Err(99)
    );
    assert_eq!(replacements, 1);
    lock.destroy().unwrap();
}

#[test]
fn a_waiter_prevents_destroy_even_in_the_unlocked_wakeup_window() {
    let lock = Mutex::new(NORMAL);
    lock.try_lock(1).unwrap();
    let mut calls = 0;
    assert_eq!(
        lock.lock(
            2,
            |_, _| {
                calls += 1;
                lock.unlock(1, |_| {}).unwrap();
                assert_eq!(lock.destroy(), Err(Error::Busy));
                Ok::<(), ()>(())
            },
            |_| panic!()
        ),
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
                    lock.lock(
                        owner,
                        |_, _| {
                            std::thread::yield_now();
                            Ok::<(), ()>(())
                        },
                        |_| panic!()
                    ),
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
