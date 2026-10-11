use mochios_posix_client::{
    newlib_errno::{EINTR, EIO},
    signal::terminal_operation,
};
use std::cell::Cell;

#[test]
fn default_job_stop_is_retried_after_resume_without_replaying_success() {
    let attempts = Cell::new(0);
    let stops = Cell::new(0u64);
    let drains = Cell::new(0);
    let result = terminal_operation(
        || {
            attempts.set(attempts.get() + 1);
            if attempts.get() == 1 {
                Err(EINTR)
            } else {
                Ok(3)
            }
        },
        || {
            drains.set(drains.get() + 1);
            stops.set(stops.get() + 1);
            Ok(())
        },
        || (0, stops.get(), 0),
        || false,
    );
    assert_eq!(result, Ok(3));
    assert_eq!(attempts.get(), 2);
    assert_eq!(drains.get(), 1);
}

#[test]
fn caught_handlers_and_unknown_interruptions_are_never_silently_retried() {
    for caught in [false, true] {
        let attempts = Cell::new(0);
        let generations = Cell::new((0u64, 0u64, 0u64));
        let result: Result<(), _> = terminal_operation(
            || {
                attempts.set(attempts.get() + 1);
                Err(EINTR)
            },
            || {
                if caught {
                    generations.set((1, 1, 0));
                }
                Ok(())
            },
            || generations.get(),
            || caught,
        );
        assert_eq!(result, Err(EINTR));
        assert_eq!(attempts.get(), 1);
    }
}

#[test]
fn failed_drains_and_non_interrupt_errors_propagate_without_retry() {
    assert_eq!(
        terminal_operation::<()>(|| Err(EINTR), || Err(EIO), || (0, 0, 0), || true),
        Err(EIO)
    );
    assert_eq!(
        terminal_operation::<()>(
            || Err(EIO),
            || panic!("must not drain"),
            || (0, 0, 0),
            || true
        ),
        Err(EIO)
    );
    assert_eq!(
        terminal_operation(
            || Ok(2),
            || panic!("partial success must not replay"),
            || (0, 0, 0),
            || panic!("success must not consult restart policy"),
        ),
        Ok(2)
    );
}

#[test]
fn stops_observed_inside_native_call_and_wrapped_generations_are_detected() {
    let stops = Cell::new(u64::MAX);
    let attempts = Cell::new(0);
    assert_eq!(
        terminal_operation(
            || {
                attempts.set(attempts.get() + 1);
                if attempts.get() <= 2 {
                    stops.set(stops.get().wrapping_add(1));
                    Err(EINTR)
                } else {
                    Ok(())
                }
            },
            || Ok(()),
            || (7, stops.get(), 0),
            || false,
        ),
        Ok(())
    );
    assert_eq!(attempts.get(), 3);
}

#[test]
fn backend_default_stop_can_be_selected_before_another_threads_upcall_starts() {
    let attempts = Cell::new(0);
    assert_eq!(
        terminal_operation(
            || {
                attempts.set(attempts.get() + 1);
                if attempts.get() == 1 {
                    Err(EINTR)
                } else {
                    Ok(())
                }
            },
            || Ok(()),
            || (0, 0, 0),
            || true,
        ),
        Ok(())
    );
    assert_eq!(attempts.get(), 2);
}

#[test]
fn runtime_records_actual_stops_and_wraps_only_terminal_paths() {
    let source = include_str!("../../../user/crates/newlib-runtime/src/lib.rs");
    let stop = source
        .split("fn apply_default_signal_action(")
        .nth(1)
        .unwrap()
        .split("fn drain_pending_signals(")
        .next()
        .unwrap();
    assert!(stop.contains("JOB_STOP_GENERATION.fetch_add(1, Ordering::Release)"));
    assert!(
        stop.find("report_process_stopped(delivery)").unwrap()
            < stop.find("JOB_STOP_GENERATION.fetch_add").unwrap()
    );
    let wrapper = source
        .split("fn retry_terminal_operation<")
        .nth(1)
        .unwrap()
        .split("fn terminal_control(")
        .next()
        .unwrap();
    assert!(wrapper.contains("drain_terminal_signals"));
    assert!(wrapper.contains("nonrestart_signal_generation.load"));
    assert!(wrapper.contains("JOB_STOP_GENERATION.load"));
    assert!(source.contains("static JOB_STOPS_IN_FLIGHT: AtomicU32"));
    assert!(wrapper.contains("synchronization::wait_u32("));
    assert!(stop.contains("synchronization::wake_u32(&JOB_STOPS_IN_FLIGHT"));
    let handles = include_str!("../../../core/src/syscall/handle.rs");
    let ipc = include_str!("../../../core/src/syscall/ipc.rs");
    assert!(!handles.contains("EINTR"));
    assert!(!ipc.contains("EINTR"));
}
