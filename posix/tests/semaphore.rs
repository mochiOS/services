use mochios_posix_client::semaphore::{Error, Semaphore, VALUE_MAX};
use std::sync::atomic::{AtomicU32, Ordering};

#[test]
fn counting_state_never_underflows_and_posts_can_be_acquired_once() {
    let semaphore = Semaphore::new(0, false).unwrap();
    assert_eq!(semaphore.try_take(), Ok(false));
    assert_eq!(semaphore.value(), Ok(0));
    semaphore.post().unwrap();
    semaphore.post().unwrap();
    assert_eq!(semaphore.value(), Ok(2));
    assert_eq!(semaphore.try_take(), Ok(true));
    assert_eq!(semaphore.try_take(), Ok(true));
    assert_eq!(semaphore.try_take(), Ok(false));
}

#[test]
fn capacity_and_destruction_preserve_counts_and_reject_dead_objects() {
    assert!(matches!(
        Semaphore::new(VALUE_MAX + 1, false),
        Err(Error::Invalid)
    ));
    let semaphore = Semaphore::new(VALUE_MAX, true).unwrap();
    assert_eq!(semaphore.post(), Err(Error::Overflow));
    assert_eq!(semaphore.value(), Ok(VALUE_MAX));
    assert_eq!(semaphore.try_take(), Ok(true));
    assert_eq!(semaphore.post(), Ok(()));
    assert_eq!(semaphore.destroy(), Ok(()));
    assert_eq!(semaphore.destroy(), Err(Error::Invalid));
    assert_eq!(semaphore.value(), Err(Error::Invalid));
    assert_eq!(semaphore.try_take(), Err(Error::Invalid));
    assert_eq!(semaphore.post(), Err(Error::Invalid));
}

#[test]
fn competing_consumers_cannot_duplicate_tokens() {
    let semaphore = Semaphore::new(5000, false).unwrap();
    let consumed = AtomicU32::new(0);
    std::thread::scope(|scope| {
        for _ in 0..8 {
            scope.spawn(|| {
                while semaphore.try_take().unwrap() {
                    consumed.fetch_add(1, Ordering::Relaxed);
                }
            });
        }
    });
    assert_eq!(consumed.load(Ordering::Relaxed), 5000);
    assert_eq!(semaphore.value(), Ok(0));
}

#[test]
fn post_publishes_data_to_a_successful_consumer() {
    let semaphore = Semaphore::new(0, true).unwrap();
    let published = AtomicU32::new(0);
    std::thread::scope(|scope| {
        scope.spawn(|| {
            while !semaphore.try_take().unwrap() {
                std::thread::yield_now();
            }
            assert_eq!(published.load(Ordering::Relaxed), 42);
        });
        published.store(42, Ordering::Relaxed);
        semaphore.post().unwrap();
    });
}

#[test]
fn failed_admission_leaves_a_stable_zero_wait_predicate() {
    let semaphore = Semaphore::new(0, false).unwrap();
    assert_eq!(semaphore.try_take(), Ok(false));
    semaphore.post().unwrap();
    // Native guarded wait must observe the changed word and never enqueue
    // against a newly sampled nonzero value after a failed acquisition.
    assert_ne!(semaphore.word().load(Ordering::Acquire), 0);
    assert_eq!(semaphore.try_take(), Ok(true));
    assert_eq!(std::mem::size_of::<Semaphore>(), 16);
    assert_eq!(std::mem::align_of::<Semaphore>(), 8);
}
