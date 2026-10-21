//! Host substitute for the provider cleanup probe's native spin locks.
//! Cross-thread contention waits; recursive acquisition is a separate failure.
use std::cell::Cell;
use std::ops::{Deref, DerefMut};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, MutexGuard, TryLockError};

static NEXT_OWNER: AtomicUsize = AtomicUsize::new(1);
thread_local! { static OWNER: Cell<usize> = const { Cell::new(0) }; }

fn caller() -> usize {
    OWNER.with(|owner| {
        let current = owner.get();
        if current != 0 {
            return current;
        }
        let current = NEXT_OWNER.fetch_add(1, Ordering::Relaxed);
        assert_ne!(current, 0, "fixture owner identities exhausted");
        owner.set(current);
        current
    })
}

pub struct SpinLock<T> {
    value: Mutex<T>,
    owner: AtomicUsize,
    contentions: AtomicUsize,
}

impl<T> SpinLock<T> {
    pub const fn new(value: T) -> Self {
        Self {
            value: Mutex::new(value),
            owner: AtomicUsize::new(0),
            contentions: AtomicUsize::new(0),
        }
    }

    pub fn lock(&self) -> Guard<'_, T> {
        let caller = caller();
        assert_ne!(
            self.owner.load(Ordering::Acquire),
            caller,
            "recursive provider cleanup lock"
        );
        let value = match self.value.try_lock() {
            Ok(value) => value,
            Err(TryLockError::WouldBlock) => {
                self.contentions.fetch_add(1, Ordering::Release);
                self.value.lock().expect("poisoned provider cleanup lock")
            }
            Err(TryLockError::Poisoned(_)) => panic!("poisoned provider cleanup lock"),
        };
        self.owner.store(caller, Ordering::Release);
        Guard { lock: self, value }
    }

    pub fn try_lock(&self) -> Option<Guard<'_, T>> {
        let value = self.value.try_lock().ok()?;
        self.owner.store(caller(), Ordering::Release);
        Some(Guard { lock: self, value })
    }
}

pub struct Guard<'a, T> {
    lock: &'a SpinLock<T>,
    value: MutexGuard<'a, T>,
}
impl<T> Deref for Guard<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.value
    }
}
impl<T> DerefMut for Guard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        &mut self.value
    }
}
impl<T> Drop for Guard<'_, T> {
    fn drop(&mut self) {
        self.lock.owner.store(0, Ordering::Release);
        // The mutex guard is released after clearing its owner. No payload is
        // dropped or callback invoked in that interval, and contenders wait.
    }
}

pub fn verify() {
    let lock = std::sync::Arc::new(SpinLock::new(0));
    let held = lock.lock();
    let other = lock.clone();
    let worker = std::thread::spawn(move || {
        *other.lock() += 1;
    });
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while lock.contentions.load(Ordering::Acquire) == 0
        && !worker.is_finished()
        && std::time::Instant::now() < deadline
    {
        std::thread::yield_now();
    }
    let waited = lock.contentions.load(Ordering::Acquire) != 0 && !worker.is_finished();
    drop(held);
    worker.join().unwrap();
    assert!(waited, "cross-thread lock must wait instead of panicking");
    let held = lock.lock();
    assert_eq!(*held, 1);
    assert!(lock.try_lock().is_none());
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            drop(lock.lock());
        }))
        .is_err(),
        "genuine recursion must still be detected"
    );
    assert!(lock.try_lock().is_none());
    drop(held);
    assert_eq!(*lock.try_lock().unwrap(), 1);
}
