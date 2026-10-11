use mochios_posix_client::multiplex::select_ready_count;
use mochios_posix_client::multiplex::{wait, WaitError};
use std::cell::Cell;

#[test]
fn nanosecond_waits_validate_the_entire_timespec_without_rounding() {
    use mochios_posix_client::multiplex::timespec_timeout_nanoseconds as parse;
    assert_eq!(parse(0, 0), Some(0));
    assert_eq!(parse(0, 1), Some(1));
    assert_eq!(parse(2, 123), Some(2_000_000_123));
    for (seconds, nanoseconds) in [(-1, 0), (0, -1), (0, 1_000_000_000), (i64::MAX, 0)] {
        assert_eq!(parse(seconds, nanoseconds), None);
    }
}

#[test]
fn temporary_mask_is_restored_after_success_and_operation_errors() {
    use mochios_posix_client::multiplex::with_signal_mask;
    for outcome in [Ok(7), Err(4)] {
        let mask = Cell::new(0x10);
        let changes = Cell::new(0);
        let result = with_signal_mask(
            Some(0x20),
            |new| {
                changes.set(changes.get() + 1);
                Ok(mask.replace(new))
            },
            || {
                assert_eq!(mask.get(), 0x20);
                outcome
            },
        );
        assert_eq!(result, outcome);
        assert_eq!((mask.get(), changes.get()), (0x10, 2));
    }
    assert_eq!(
        with_signal_mask::<_, i32>(None, |_| panic!("null mask must not replace"), || Ok(7)),
        Ok(7)
    );
}

#[test]
fn failed_mask_installation_does_not_wait_and_failed_restoration_is_reported() {
    use mochios_posix_client::multiplex::with_signal_mask;
    assert_eq!(
        with_signal_mask(
            Some(0),
            |_| Err(9),
            || -> Result<(), i32> { panic!("must not wait") }
        ),
        Err(9)
    );
    let changes = Cell::new(0);
    assert_eq!(
        with_signal_mask(
            Some(0),
            |_| {
                changes.set(changes.get() + 1);
                if changes.get() == 1 {
                    Ok(7)
                } else {
                    Err(10)
                }
            },
            || Ok(())
        ),
        Err(10)
    );
    assert_eq!(changes.get(), 2);
}

#[test]
fn masked_entry_captures_generation_before_unblocking_and_keeps_nanosecond_deadlines() {
    let runtime = include_str!("../../../user/crates/newlib-runtime/src/lib.rs");
    let masked = runtime
        .split("fn masked_multiplex(")
        .nth(1)
        .unwrap()
        .split("fn pselect(")
        .next()
        .unwrap();
    assert!(
        masked.find("caught_signal_generation.load").unwrap()
            < masked.find("with_signal_mask(").unwrap()
    );
    assert!(masked.contains("operation(control, caught)"));
    for (begin, end, backend) in [
        ("fn pselect(", "fn ppoll(", "select_with_deadline"),
        ("fn ppoll(", "fn getgroups(", "poll_with_deadline"),
    ] {
        let function = runtime
            .split(begin)
            .nth(1)
            .unwrap()
            .split(end)
            .next()
            .unwrap();
        assert!(function.contains("timespec_deadline(timeout)"));
        assert!(function.contains("masked_multiplex(mask"));
        assert!(function.contains(backend));
        assert!(!function.contains("timeout.write"));
    }
}

#[test]
fn every_negative_poll_timeout_is_infinite_and_nonnegative_values_are_exact() {
    use mochios_posix_client::multiplex::poll_timeout_nanoseconds;
    for value in [i32::MIN, -1000, -2, -1] {
        assert_eq!(poll_timeout_nanoseconds(value), None);
    }
    for value in [0, 1, 1000, i32::MAX] {
        assert_eq!(
            poll_timeout_nanoseconds(value),
            Some(value as u64 * 1_000_000)
        );
    }
    let runtime = include_str!("../../../user/crates/newlib-runtime/src/lib.rs");
    let poll = runtime
        .split("fn poll(")
        .nth(1)
        .unwrap()
        .split("fn getgroups(")
        .next()
        .unwrap();
    assert!(poll.contains("multiplex::poll_timeout_nanoseconds(timeout_ms)"));
    assert!(!poll.contains("value if value < -1"));
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[test]
fn negative_timeouts_match_host_poll_including_values_below_minus_one() {
    use std::os::fd::AsRawFd;
    #[repr(C)]
    struct PollFd {
        fd: i32,
        events: i16,
        revents: i16,
    }
    unsafe extern "C" {
        fn poll(fds: *mut PollFd, count: usize, timeout: i32) -> i32;
    }
    let file = std::fs::File::open("/dev/null").unwrap();
    for timeout in [i32::MIN, -1000, -2, -1, 0, 1, i32::MAX] {
        // /dev/null is always readable, so even infinite waits complete.
        let mut item = PollFd {
            fd: file.as_raw_fd(),
            events: 1,
            revents: 0,
        };
        assert_eq!(unsafe { poll(&mut item, 1, timeout) }, 1);
        assert_eq!(item.revents & 1, 1);
    }
}

#[test]
fn caught_handler_interrupts_before_entry_and_after_a_native_return() {
    let result = wait::<i32>(
        1,
        || 2,
        || panic!("must not wait"),
        || panic!("must not check timeout"),
    );
    assert_eq!(result, Err(WaitError::Interrupted));
    for ready in [false, true] {
        let generation = Cell::new(1);
        let result = wait::<i32>(
            1,
            || generation.get(),
            || {
                generation.set(2);
                Ok(ready)
            },
            || panic!("caught handler takes precedence"),
        );
        assert_eq!(result, Err(WaitError::Interrupted));
    }
}

#[test]
fn unrelated_wakeups_retry_until_ready_or_the_original_deadline_expires() {
    let attempts = Cell::new(0);
    let clocks = Cell::new(0);
    let result = wait::<i32>(
        1,
        || 1,
        || {
            attempts.set(attempts.get() + 1);
            Ok(attempts.get() == 3)
        },
        || {
            clocks.set(clocks.get() + 1);
            Ok(false)
        },
    );
    assert_eq!(result, Ok(()));
    assert_eq!((attempts.get(), clocks.get()), (3, 2));
    let clock = Cell::new(10);
    let deadline = 13;
    assert_eq!(
        wait::<i32>(
            1,
            || 1,
            || Ok(false),
            || {
                clock.set(clock.get() + 1);
                Ok(clock.get() >= deadline)
            }
        ),
        Ok(())
    );
    assert_eq!(clock.get(), deadline);
}

#[test]
fn native_and_clock_errors_are_not_converted_to_false_timeouts() {
    assert_eq!(
        wait(1, || 1, || Err(9), || Ok(false)),
        Err(WaitError::Io(9))
    );
    assert_eq!(
        wait(1, || 1, || Ok(false), || Err(10)),
        Err(WaitError::Io(10))
    );
}

#[test]
fn both_entry_points_guard_the_all_handler_generation_not_only_nonrestart_handlers() {
    let runtime = include_str!("../../../user/crates/newlib-runtime/src/lib.rs");
    let bridge = runtime
        .split("fn wait_for_multiplex(")
        .nth(1)
        .unwrap()
        .split("fn select_deadline(")
        .next()
        .unwrap();
    assert!(bridge.contains("HandleWaitManyGuarded"));
    assert!(bridge.contains("&control.caught_signal_generation as *const AtomicU64"));
    assert!(!bridge.contains("nonrestart_signal_generation"));
    for (begin, end) in [("fn select(", "fn poll("), ("fn poll(", "fn getgroups(")] {
        let entry = runtime
            .split(begin)
            .nth(1)
            .unwrap()
            .split(end)
            .next()
            .unwrap();
        assert!(entry.contains("control.caught_signal_generation.load(Ordering::Acquire)"));
        assert!(entry.contains("wait_for_multiplex(&mut items[..item_count]"));
        assert!(!entry.contains("SyscallNumber::HandleWaitMany,"));
    }
}

#[test]
fn select_counts_each_ready_set_instead_of_distinct_descriptors() {
    assert_eq!(select_ready_count(0, 0, 0), 0);
    for fd in 0..64 {
        let bit = 1u64 << fd;
        assert_eq!(select_ready_count(bit, 0, 0), 1);
        assert_eq!(select_ready_count(bit, bit, 0), 2);
        assert_eq!(select_ready_count(bit, bit, bit), 3);
    }
    assert_eq!(select_ready_count(0b101, 0b110, 0b100), 5);
    assert_eq!(select_ready_count(u64::MAX, u64::MAX, u64::MAX), 192);
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[test]
fn select_count_matches_host_select_for_a_readable_and_writable_file() {
    use std::os::fd::AsRawFd;

    unsafe extern "C" {
        fn select(
            nfds: i32,
            read: *mut [u64; 16],
            write: *mut [u64; 16],
            exceptional: *mut [u64; 16],
            timeout: *mut [i64; 2],
        ) -> i32;
    }
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/null")
        .unwrap();
    let fd = file.as_raw_fd();
    assert!((0..64).contains(&fd));
    let mut read = [0u64; 16];
    let mut write = [0u64; 16];
    let mut exceptional = [0u64; 16];
    read[0] = 1u64 << fd;
    write[0] = 1u64 << fd;
    let mut timeout = [0i64; 2];
    // Linux x86_64 fd_set is 1024 bits and timeval has two signed longs.
    let count = unsafe {
        select(
            fd + 1,
            &mut read,
            &mut write,
            &mut exceptional,
            &mut timeout,
        )
    };
    assert_eq!(count, 2);
    assert_eq!(
        select_ready_count(read[0], write[0], exceptional[0]),
        count as u32
    );
}

#[test]
fn newlib_select_uses_the_shared_posix_result_count() {
    let runtime = include_str!("../../../user/crates/newlib-runtime/src/lib.rs");
    assert!(runtime.contains("mochios_posix_client::multiplex::select_ready_count("));
    assert!(!runtime.contains("(ready_read | ready_write | ready_except).count_ones()"));
}
