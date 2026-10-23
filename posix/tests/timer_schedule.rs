#[path = "../src/timer_schedule.rs"]
mod timer_schedule;
use timer_schedule::Schedule;

#[test]
fn absolute_relative_disarm_and_expired_deadlines_remain_distinct() {
    let relative = Schedule::arm(100, 20, 7, false, 1_000).unwrap();
    let absolute = Schedule::arm(100, 20, 7, true, 1_000).unwrap();
    assert_eq!(relative.deadline(), Some(120));
    assert_eq!(absolute.deadline(), Some(20));
    assert_eq!(relative.remaining(101), 19);
    assert_eq!(absolute.remaining(100), 0);
    let (advanced, expirations) = absolute.observe(100);
    assert_eq!(expirations, 12); // 20, 27, ... 97.
    assert_eq!(advanced.deadline(), Some(104));
    assert_eq!(advanced.remaining(100), 4);
    for absolute in [false, true] {
        let timer = Schedule::arm(100, 0, 7, absolute, 1_000).unwrap();
        assert_eq!(timer.deadline(), None);
        assert_eq!(timer.interval(), 7);
        assert_eq!(timer.observe(1_000), (timer, 0));
    }
}

#[test]
fn one_shot_and_periodic_observation_are_idempotent_without_phase_drift() {
    let timer = Schedule::arm(10, 5, 0, false, 1_000).unwrap();
    assert_eq!(timer.observe(14), (timer, 0));
    let (done, expirations) = timer.observe(15);
    assert_eq!(expirations, 1);
    assert_eq!(done.deadline(), None);
    assert_eq!(done.observe(1_000), (done, 0));
    let timer = Schedule::arm(10, 5, 6, false, 1_000).unwrap();
    let (advanced, count) = timer.observe(99);
    assert_eq!(count, 15);
    assert_eq!(advanced.deadline(), Some(105));
    assert_eq!(advanced.observe(99), (advanced, 0));
    assert_eq!(advanced.observe(104), (advanced, 0));
    assert_eq!(advanced.observe(105).0.deadline(), Some(111));
}

#[test]
fn finite_clock_limits_never_wrap_or_publish_infinite_waits() {
    let ceiling = u64::MAX as u128 - 1;
    assert!(Schedule::arm(ceiling, 1, 0, false, ceiling).is_err());
    assert!(Schedule::arm(0, ceiling + 1, 0, true, ceiling).is_err());
    let timer = Schedule::arm(ceiling - 1, 1, 1, false, ceiling).unwrap();
    let (done, count) = timer.observe(ceiling);
    assert_eq!(count, 1);
    assert_eq!(done.deadline(), None);
    assert_eq!(done.interval(), 1);
    assert!(Schedule::arm(u128::MAX, 1, 0, false, u128::MAX).is_err());
    let timer = Schedule::arm(0, 1, 1, false, u128::MAX).unwrap();
    let (done, count) = timer.observe(u128::MAX);
    assert_eq!(count, u128::MAX);
    assert_eq!(done.deadline(), None);
    // Multiplication overflow is also a disarm, not a panic or past deadline.
    let timer = Schedule::arm(0, 1, u128::MAX / 2 + 1, true, u128::MAX).unwrap();
    assert_eq!(
        timer.observe(u128::MAX),
        (
            Schedule::arm(0, 0, u128::MAX / 2 + 1, false, u128::MAX).unwrap(),
            2
        )
    );
}

#[test]
fn full_timespec_range_is_not_truncated_to_native_wait_width() {
    let far_future = i64::MAX as u128 * 1_000_000_000 + 999_999_999;
    let timer = Schedule::arm(0, far_future, far_future, true, u128::MAX).unwrap();
    assert_eq!(timer.remaining(0), far_future);
    let (advanced, count) = timer.observe(far_future);
    assert_eq!(count, 1);
    assert_eq!(advanced.deadline(), Some(far_future * 2));
    // A backward clock change postpones an absolute deadline; it does not
    // manufacture expirations. Clock-domain selection is the caller's job.
    assert_eq!(advanced.observe(0), (advanced, 0));
}

#[test]
fn bounded_calculation_matches_independent_expiration_by_expiration_model() {
    for initial in 0..=20 {
        for interval in 0..=20 {
            for absolute in [false, true] {
                let mut timer = Schedule::arm(10, initial, interval, absolute, 200).unwrap();
                let mut deadline = if initial == 0 {
                    None
                } else {
                    Some(initial + if absolute { 0 } else { 10 })
                };
                for now in [0, 5, 10, 19, 29, 35, 80, 150, 200] {
                    let mut expected_count = 0;
                    while let Some(end) = deadline.filter(|&end| end <= now) {
                        expected_count += 1;
                        deadline = if interval == 0 {
                            None
                        } else {
                            end.checked_add(interval).filter(|&next| next <= 200)
                        };
                    }
                    let (updated, count) = timer.observe(now);
                    assert_eq!(count, expected_count);
                    assert_eq!(updated.deadline(), deadline);
                    assert_eq!(
                        updated.remaining(now),
                        deadline.map_or(0, |end| end.saturating_sub(now))
                    );
                    assert_eq!(updated.interval(), interval);
                    timer = updated;
                }
            }
        }
    }
}
