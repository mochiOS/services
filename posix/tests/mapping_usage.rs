#[path = "../../../core/src/mem/mapping_usage.rs"]
mod native;
use native::{Error, bytes, permits};

fn usage(regions: &[(u64, u64)], leaves: &[u64]) -> u64 {
    bytes(regions.iter().copied(), |start, end| {
        Ok::<_, ()>(
            leaves
                .iter()
                .copied()
                .find(|&page| start <= page && page < end),
        )
    })
    .unwrap()
}

#[test]
fn reservations_and_retained_leaves_are_a_union_not_a_cursor_or_rss_sum() {
    let regions = [(0x8000, 0xc000), (0x1000, 0x3000)];
    // Outside leaves model image, initial stack, TLS and borrowed mappings.
    // Inside leaves include both present and temporarily inaccessible pages.
    assert_eq!(
        usage(
            &regions,
            &[0x1000, 0x2000, 0x4000, 0x8000, 0xa000, 0x100000]
        ),
        8 * 4096
    );
    assert_eq!(usage(&regions, &[]), 6 * 4096);
    assert_eq!(usage(&[], &[0x4000, 0x100000]), 2 * 4096);
    assert_eq!(usage(&[], &[]), 0);
}

#[test]
fn partial_and_complete_revocation_release_only_the_removed_reservations() {
    let full = usage(&[(0x4000, 0x8000)], &[0x4000, 0x7000]);
    let cut = usage(&[(0x4000, 0x5000), (0x7000, 0x8000)], &[0x4000, 0x7000]);
    assert_eq!(full - cut, 8192);
    assert_eq!(usage(&[], &[]), 0);
    assert!(permits(cut, 8192, full));
    assert!(!permits(cut, 8193, full));
}

#[test]
fn one_jump_skips_a_terabyte_of_faulted_or_unfaulted_reservation() {
    let regions = [(4096, 1 << 40)];
    let mut calls = 0;
    let total = bytes(regions.into_iter(), |start, _| {
        calls += 1;
        Ok::<_, ()>(if start == 0 {
            Some(4096)
        } else {
            assert_eq!(start, 1 << 40);
            None
        })
    })
    .unwrap();
    assert_eq!(calls, 2);
    assert_eq!(total, (1 << 40) - 4096);
}

#[test]
fn every_small_reservation_and_leaf_pattern_matches_a_page_set() {
    for mask in 0..256u64 {
        let regions: Vec<_> = (0..8)
            .filter(|&n| mask & (1 << n) != 0)
            .map(|n| (n * 4096, (n + 1) * 4096))
            .collect();
        for resident in 0..256u64 {
            let leaves: Vec<_> = (0..8)
                .filter(|&n| resident & (1 << n) != 0)
                .map(|n| n * 4096)
                .collect();
            assert_eq!(
                usage(&regions, &leaves),
                u64::from((mask | resident).count_ones()) * 4096
            );
        }
    }
}

#[test]
fn malformed_metadata_or_backend_is_never_accepted_as_zero_usage() {
    for regions in [
        vec![(4096, 4096)],
        vec![(8192, 4096)],
        vec![(1, 4096)],
        vec![(0, 4097)],
        vec![(0, u64::MAX)],
        vec![(4096, 12288), (8192, 16384)],
        vec![(4096, 8192), (4096, 8192)],
    ] {
        assert_eq!(
            bytes(regions.into_iter(), |_, _| Ok::<_, ()>(None)),
            Err(Error::InvalidRange)
        );
    }
    assert_eq!(
        bytes([].into_iter(), |_, _| Err(17)),
        Err(Error::Backend(17))
    );
    for page in [1, 1 << 47, u64::MAX] {
        assert_eq!(
            bytes([].into_iter(), |_, _| Ok::<_, ()>(Some(page))),
            Err(Error::InvalidRange)
        );
    }
    let mut calls = 0;
    assert_eq!(
        bytes([].into_iter(), |_, _| {
            calls += 1;
            assert!(calls <= 2);
            Ok::<_, ()>(Some(4096))
        }),
        Err(Error::InvalidRange)
    );
}

#[test]
fn checked_ceiling_accepts_exact_fit_and_rejects_overflow_and_lowered_limits() {
    assert!(permits(8192, 4096, 12288));
    assert!(!permits(8192, 4096, 12287));
    assert!(!permits(8192, 4096, 0));
    assert!(!permits(u64::MAX, 1, u64::MAX));
    assert!(permits(0, u64::MAX, u64::MAX));
}
