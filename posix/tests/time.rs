use mochios_posix_client::time::{ClockKind, classify_clock_id};

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
