use mochios_posix_client::time::{ClockKind, classify_clock_id};

#[test]
fn posix_clock_ids_are_classified_in_user_space() {
    for clock_id in [0, 5, 8] {
        assert_eq!(classify_clock_id(clock_id), Some(ClockKind::Realtime));
    }
    for clock_id in [1, 4, 6, 7, 9] {
        assert_eq!(classify_clock_id(clock_id), Some(ClockKind::Monotonic));
    }
    assert_eq!(classify_clock_id(2), Some(ClockKind::ProcessCpu));
    assert_eq!(classify_clock_id(3), Some(ClockKind::ThreadCpu));
    assert_eq!(classify_clock_id(-1), None);
    assert_eq!(classify_clock_id(10), None);
}
