use mochios_posix_client::time::{ClockKind, classify_clock_id};

#[test]
fn clock_sleep_parsing_uses_sdk_flags_and_rejects_unusable_clocks() {
    use mochios_posix_client::newlib_errno::{EINVAL, ENOTSUP};
    use mochios_posix_client::time::{ClockSleep, TIMER_ABSTIME};
    let header = include_str!("../../../libraries/newlib/newlib/libc/include/time.h");
    let value: i32 = header
        .lines()
        .find_map(|line| {
            let mut fields = line.split_whitespace();
            (fields.next() == Some("#define") && fields.next() == Some("TIMER_ABSTIME"))
                .then(|| fields.next().unwrap().parse().unwrap())
        })
        .unwrap();
    assert_eq!(TIMER_ABSTIME, value);
    let absolute = ClockSleep::parse(4, value, 2, 3).unwrap();
    assert!(absolute.absolute);
    assert_eq!(absolute.nanoseconds, 2_000_000_003);
    assert_eq!(absolute.remaining(2_000_000_000), 3);
    assert_eq!(absolute.remaining(3_000_000_000), 0);
    assert!(!ClockSleep::parse(1, 0, 0, 1).unwrap().absolute);
    for (clock, flags, sec, nano) in [
        (-1, 0, 0, 0),
        (3, 0, 0, 0),
        (4, 1, 0, 0),
        (4, -1, 0, 0),
        (4, 0, -1, 0),
        (4, 0, 0, -1),
        (4, 0, 0, 1_000_000_000),
        (4, 0, i64::MAX, 0),
    ] {
        assert_eq!(ClockSleep::parse(clock, flags, sec, nano), Err(EINVAL));
    }
    for clock in [0, 2, 5, 6, 7, 8, 9] {
        assert_eq!(ClockSleep::parse(clock, 0, 0, 0), Err(ENOTSUP));
    }
    let header = include_str!("../../../libraries/newlib/newlib/libc/include/time.h");
    assert!(header.contains("#if defined(_POSIX_CLOCK_SELECTION) || defined(__mochios__)"));
    let libc = include_str!("../../../libraries/libc/newlib/mochios.rs");
    assert!(libc.contains("pub const TIMER_ABSTIME: c_int = 4;"));
    assert!(libc.contains("pub fn clock_nanosleep("));
}

#[test]
fn sleep_observation_distinguishes_spurious_wakes_caught_handlers_and_expiry() {
    use mochios_posix_client::time::{SleepObservation, observe_sleep};
    assert_eq!(observe_sleep(100, 40, 7, 7), SleepObservation::Waiting);
    assert_eq!(observe_sleep(100, 100, 7, 7), SleepObservation::Complete);
    assert_eq!(observe_sleep(100, 101, 7, 7), SleepObservation::Complete);
    assert_eq!(
        observe_sleep(100, 40, 7, 8),
        SleepObservation::Interrupted {
            remaining_nanoseconds: 60
        }
    );
    assert_eq!(
        observe_sleep(100, 101, 7, 8),
        SleepObservation::Interrupted {
            remaining_nanoseconds: 0
        }
    );
    assert_eq!(
        observe_sleep(100, 40, u64::MAX, 0),
        SleepObservation::Interrupted {
            remaining_nanoseconds: 60
        }
    );
}

#[test]
fn posix_clock_ids_are_classified_in_user_space() {
    for clock_id in [0, 1, 8] {
        assert_eq!(classify_clock_id(clock_id), Some(ClockKind::Realtime));
    }
    for clock_id in [4, 5, 6, 7, 9] {
        assert_eq!(classify_clock_id(clock_id), Some(ClockKind::Monotonic));
    }
    assert_eq!(classify_clock_id(2), Some(ClockKind::ProcessCpu));
    assert_eq!(classify_clock_id(3), Some(ClockKind::ThreadCpu));
    assert_eq!(classify_clock_id(-1), None);
    assert_eq!(classify_clock_id(10), None);
    // TAI has a distinct epoch and must not be silently treated as realtime.
    assert_eq!(classify_clock_id(11), None);
}

#[test]
fn clock_translation_matches_the_sdk_headers_not_linux_numbers() {
    let header = include_str!("../../../libraries/newlib/newlib/libc/include/time.h");
    for (name, kind) in [
        ("CLOCK_REALTIME", ClockKind::Realtime),
        ("CLOCK_REALTIME_COARSE", ClockKind::Realtime),
        ("CLOCK_REALTIME_ALARM", ClockKind::Realtime),
        ("CLOCK_MONOTONIC", ClockKind::Monotonic),
        ("CLOCK_MONOTONIC_RAW", ClockKind::Monotonic),
        ("CLOCK_MONOTONIC_COARSE", ClockKind::Monotonic),
        ("CLOCK_BOOTTIME", ClockKind::Monotonic),
        ("CLOCK_BOOTTIME_ALARM", ClockKind::Monotonic),
        ("CLOCK_PROCESS_CPUTIME_ID", ClockKind::ProcessCpu),
        ("CLOCK_THREAD_CPUTIME_ID", ClockKind::ThreadCpu),
    ] {
        let value = header
            .lines()
            .find_map(|line| {
                let mut fields = line.split_whitespace();
                if fields.next() != Some("#define") || fields.next() != Some(name) {
                    return None;
                }
                fields.next()?.trim_matches(['(', ')']).parse::<i32>().ok()
            })
            .unwrap_or_else(|| panic!("SDK clock definition missing: {name}"));
        assert_eq!(classify_clock_id(value), Some(kind), "SDK selector {name}");
    }
}
