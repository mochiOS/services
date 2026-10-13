use mochios_posix_client::pthread_rwlock::{self as state, Error};
use std::sync::atomic::{AtomicU32, Ordering};

#[test]
fn readers_share_the_word_while_writers_are_exclusive() {
    let word = AtomicU32::new(state::INITIALIZER);
    assert_eq!(state::try_read(&word), Ok(()));
    assert_eq!(state::try_read(&word), Ok(()));
    assert_eq!(state::try_write(&word), Err(Error::Busy(2)));
    assert_eq!(state::unlock(&word), Ok(false));
    assert_eq!(state::unlock(&word), Ok(true));
    assert_eq!(state::try_write(&word), Ok(()));
    let busy = word.load(Ordering::Relaxed);
    assert_eq!(state::try_read(&word), Err(Error::Busy(busy)));
    assert_eq!(state::try_write(&word), Err(Error::Busy(busy)));
    assert_eq!(state::unlock(&word), Ok(true));
}

#[test]
fn lifetime_and_reader_overflow_do_not_corrupt_the_object() {
    let word = AtomicU32::new(state::MAX_READERS);
    assert_eq!(state::try_read(&word), Err(Error::ReaderLimit));
    assert_eq!(word.load(Ordering::Relaxed), state::MAX_READERS);
    assert_eq!(state::destroy(&word), Err(Error::Busy(state::MAX_READERS)));
    state::initialize(&word);
    assert_eq!(state::destroy(&word), Ok(()));
    assert_eq!(state::try_read(&word), Err(Error::Invalid));
    assert_eq!(state::try_write(&word), Err(Error::Invalid));
    assert_eq!(state::destroy(&word), Err(Error::Invalid));
    assert_eq!(state::unlock(&word), Err(Error::Invalid));
    state::initialize(&word);
    assert_eq!(state::try_write(&word), Ok(()));
    assert_eq!(state::unlock(&word), Ok(true));
    assert_eq!(state::unlock(&word), Err(Error::Invalid));
    assert_eq!(state::destroy(&AtomicU32::new(state::INITIALIZER)), Ok(()));
}

#[test]
fn captured_busy_value_prevents_waiting_on_a_later_acquirable_state() {
    let word = AtomicU32::new(0);
    state::try_write(&word).unwrap();
    let expected = match state::try_read(&word) {
        Err(Error::Busy(value)) => value,
        other => panic!("{other:?}"),
    };
    state::unlock(&word).unwrap();
    state::try_read(&word).unwrap();
    assert_ne!(word.load(Ordering::Acquire), expected);
    state::try_read(&word).unwrap();
}

#[test]
fn contended_writers_publish_data_to_readers_without_overlapping_holders() {
    let word = AtomicU32::new(state::INITIALIZER);
    let data = AtomicU32::new(0);
    std::thread::scope(|scope| {
        for _ in 0..8 {
            scope.spawn(|| {
                for _ in 0..500 {
                    loop {
                        match state::try_write(&word) {
                            Ok(()) => break,
                            Err(Error::Busy(_)) => std::thread::yield_now(),
                            other => panic!("{other:?}"),
                        }
                    }
                    let value = data.load(Ordering::Relaxed);
                    data.store(value + 1, Ordering::Relaxed);
                    state::unlock(&word).unwrap();
                }
            });
        }
    });
    state::try_read(&word).unwrap();
    assert_eq!(data.load(Ordering::Relaxed), 4000);
    state::unlock(&word).unwrap();
    assert_eq!(state::destroy(&word), Ok(()));
}

#[test]
fn inline_abi_matches_the_sdk_static_initializer() {
    assert_eq!(std::mem::size_of::<AtomicU32>(), 4);
    let sdk = include_str!("../../../libraries/newlib/newlib/libc/include/sys/_pthreadtypes.h");
    assert!(sdk.contains("typedef __uint32_t pthread_rwlock_t;"));
    assert!(sdk.contains("#define _PTHREAD_RWLOCK_INITIALIZER ((pthread_rwlock_t) 0xFFFFFFFF)"));
}

#[test]
fn simultaneous_readers_hold_shared_access_and_block_the_writer() {
    let word = AtomicU32::new(state::INITIALIZER);
    let acquired = std::sync::Barrier::new(9);
    let release = std::sync::Barrier::new(9);
    std::thread::scope(|scope| {
        for _ in 0..8 {
            scope.spawn(|| {
                state::try_read(&word).unwrap();
                acquired.wait();
                release.wait();
                state::unlock(&word).unwrap();
            });
        }
        acquired.wait();
        assert_eq!(state::try_write(&word), Err(Error::Busy(8)));
        release.wait();
    });
    state::try_write(&word).unwrap();
    state::unlock(&word).unwrap();
}
