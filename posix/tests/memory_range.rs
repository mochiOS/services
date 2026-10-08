#[path = "../../../core/src/task/memory_range.rs"]
mod native;

use native::{Range, cut};

#[test]
fn middle_unmap_retains_both_sides_and_removes_only_the_hole() {
    let pieces = cut(
        Range {
            start: 4096,
            end: 16384,
        },
        Range {
            start: 8192,
            end: 12288,
        },
    )
    .unwrap();
    assert_eq!(
        pieces.before,
        Some(Range {
            start: 4096,
            end: 8192
        })
    );
    assert_eq!(
        pieces.removed,
        Some(Range {
            start: 8192,
            end: 12288
        })
    );
    assert_eq!(
        pieces.after,
        Some(Range {
            start: 12288,
            end: 16384
        })
    );
}

#[test]
fn removal_spanning_multiple_regions_clips_each_intersection() {
    let removal = Range {
        start: 8192,
        end: 20480,
    };
    let first = cut(
        Range {
            start: 4096,
            end: 12288,
        },
        removal,
    )
    .unwrap();
    let second = cut(
        Range {
            start: 16384,
            end: 24576,
        },
        removal,
    )
    .unwrap();
    assert_eq!(
        first.removed,
        Some(Range {
            start: 8192,
            end: 12288
        })
    );
    assert_eq!(
        second.removed,
        Some(Range {
            start: 16384,
            end: 20480
        })
    );
    assert!(first.after.is_none());
    assert!(second.before.is_none());
}

#[test]
fn disjoint_and_whole_removals_preserve_interval_invariants() {
    let region = Range {
        start: 4096,
        end: 8192,
    };
    let disjoint = cut(
        region,
        Range {
            start: 8192,
            end: 12288,
        },
    )
    .unwrap();
    assert_eq!(disjoint.before, Some(region));
    assert!(disjoint.removed.is_none());
    let whole = cut(
        region,
        Range {
            start: 1,
            end: u64::MAX,
        },
    )
    .unwrap();
    assert_eq!(whole.removed, Some(region));
    assert!(whole.before.is_none() && whole.after.is_none());
    assert!(cut(region, Range { start: 5, end: 5 }).is_none());
}
