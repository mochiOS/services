use posix_service::{STATUS_EOVERFLOW, WaitedChildCpuUsage};

#[test]
fn raw_native_precision_survives_accumulation_beyond_u64_without_rounding() {
    let child = WaitedChildCpuUsage {
        user_ticks: u128::from(u64::MAX),
        kernel_ticks: 1,
        ticks_per_second: 500,
    };
    let sum = WaitedChildCpuUsage::default()
        .checked_add(child)
        .unwrap()
        .checked_add(child)
        .unwrap();
    assert_eq!(sum.user_ticks, 2 * u128::from(u64::MAX));
    assert_eq!(sum.kernel_ticks, 2);
    assert_eq!(sum.ticks_per_second, 500);
}

#[test]
fn incompatible_units_invalid_empty_rate_and_overflow_are_not_silently_accepted() {
    let original = WaitedChildCpuUsage {
        user_ticks: 7,
        kernel_ticks: 9,
        ticks_per_second: 500,
    };
    assert_eq!(
        original.checked_add(WaitedChildCpuUsage {
            ticks_per_second: 1000,
            ..original
        }),
        Err(-5)
    );
    assert_eq!(
        original.checked_add(WaitedChildCpuUsage {
            ticks_per_second: 0,
            ..original
        }),
        Err(-5)
    );
    for overflow in [
        WaitedChildCpuUsage {
            user_ticks: u128::MAX,
            ..original
        },
        WaitedChildCpuUsage {
            kernel_ticks: u128::MAX,
            ..original
        },
    ] {
        assert_eq!(original.checked_add(overflow), Err(STATUS_EOVERFLOW));
    }
    assert_eq!(
        original,
        WaitedChildCpuUsage {
            user_ticks: 7,
            kernel_ticks: 9,
            ticks_per_second: 500
        }
    );
}
