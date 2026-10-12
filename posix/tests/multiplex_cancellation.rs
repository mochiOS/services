use mochios_posix_client::multiplex::{wait_cancellable, with_signal_mask, WaitError};
use std::cell::{Cell, RefCell};

#[test]
fn pending_cancellation_at_entry_does_not_enter_the_native_wait() {
    let result = wait_cancellable::<i32>(
        0,
        || 0,
        || true,
        || 7,
        |_| panic!("entered wait with cancellation already pending"),
        || Ok(false),
    );
    assert_eq!(result, Err(WaitError::Cancelled));
}

#[test]
fn cancellation_after_native_return_precedes_ready_or_timeout_results() {
    for ready in [false, true] {
        let pending = Cell::new(false);
        let result = wait_cancellable::<i32>(
            0,
            || 0,
            || pending.get(),
            || 0,
            |_| {
                pending.set(true);
                Ok(ready)
            },
            || Ok(true),
        );
        assert_eq!(result, Err(WaitError::Cancelled));
    }
}

#[test]
fn notification_snapshot_closes_the_predicate_to_native_admission_race() {
    let notification = Cell::new(0);
    let pending = Cell::new(false);
    let checks = Cell::new(0);
    let calls = Cell::new(0);
    let result = wait_cancellable::<i32>(
        0,
        || 0,
        || {
            let before = pending.get();
            if checks.replace(checks.get() + 1) == 0 {
                // A concurrent cancel arrives just after reading the predicate.
                pending.set(true);
                notification.set(1);
            }
            before
        },
        || notification.get(),
        |expected| {
            calls.set(calls.get() + 1);
            assert_ne!(notification.get(), expected); // Native guard rejects sleep.
            Ok(false)
        },
        || Ok(false),
    );
    assert_eq!(result, Err(WaitError::Cancelled));
    assert_eq!(calls.get(), 1);
}

#[test]
fn disabled_cancellation_retries_against_the_updated_counter_without_false_eintr() {
    let notification = Cell::new(0);
    let calls = Cell::new(0);
    let pending = Cell::new(false);
    let result = wait_cancellable::<i32>(
        0,
        || 0,
        || false,
        || notification.get(),
        |expected| {
            let call = calls.replace(calls.get() + 1);
            assert_eq!(expected, notification.get());
            if call == 0 {
                pending.set(true);
                notification.set(1);
                Ok(false)
            } else {
                assert_eq!(call, 1); // No polling loop on the still-pending request.
                Ok(true)
            }
        },
        || Ok(false),
    );
    assert_eq!(result, Ok(()));
    assert!(pending.get());
    assert_eq!(calls.get(), 2);
}

#[test]
fn temporary_mask_is_restored_before_cancellation_is_returned_to_the_public_api() {
    let mask = Cell::new(0x12);
    let events = RefCell::new(Vec::new());
    let result = with_signal_mask(
        Some(0x34),
        |replacement| {
            events.borrow_mut().push(replacement);
            Ok::<_, WaitError<i32>>(mask.replace(replacement))
        },
        || {
            assert_eq!(mask.get(), 0x34);
            wait_cancellable::<i32>(
                0,
                || 0,
                || true,
                || 0,
                |_| panic!("unexpected wait"),
                || Ok(false),
            )
        },
    );
    assert_eq!(result, Err(WaitError::Cancelled));
    assert_eq!(mask.get(), 0x12);
    assert_eq!(*events.borrow(), [0x34, 0x12]);
}

#[test]
fn caught_handlers_remain_distinct_from_cancellation_and_io_failure() {
    assert_eq!(
        wait_cancellable::<i32>(
            0,
            || 1,
            || false,
            || 1,
            |_| panic!("already caught a handler"),
            || Ok(false)
        ),
        Err(WaitError::Interrupted)
    );
    assert_eq!(
        wait_cancellable::<i32>(0, || 0, || false, || 0, |_| Err(9), || Ok(false)),
        Err(WaitError::Io(9))
    );
}

#[test]
fn public_cancellation_points_run_after_masked_wait_restoration_not_inside_the_bridge() {
    let source = include_str!("../../../user/crates/newlib-runtime/src/lib.rs");
    for entry in [
        "fn select(",
        "fn poll(",
        "fn pselect(",
        "fn ppoll(",
        "fn pause()",
        "fn sigsuspend(",
    ] {
        let start = source.find(entry).unwrap();
        let end = start + source[start..].find("\n}\n").unwrap();
        let body = &source[start..end];
        assert_eq!(body.matches("pthread_testcancel()").count(), 2, "{entry}");
        assert!(
            body.rfind("pthread_testcancel()").unwrap() < body.rfind("result_with_errno(").unwrap()
        );
    }
    let bridge = source
        .split("fn wait_for_multiplex(")
        .nth(1)
        .unwrap()
        .split("fn select_deadline(")
        .next()
        .unwrap();
    assert!(!bridge.contains("pthread_testcancel()"));
    assert!(bridge.contains("multiplex_generation as *const AtomicU64"));
    assert!(bridge.contains("WaitError::Cancelled => EINTR"));
    assert_eq!(
        source
            .matches("multiplex_generation.store(0, Ordering::Relaxed)")
            .count(),
        2
    );
}
