#[path = "../../../core/src/task/memory_range.rs"]
mod native;

use native::{Range, cut};

#[test]
fn placement_rejects_a_single_resident_page_inside_a_larger_hole() {
    assert_eq!(
        native::any_page(4096, 16384, |page| page == 12288),
        Some(true)
    );
    assert_eq!(native::any_page(4096, 16384, |_| false), Some(false));
    assert_eq!(native::any_page(u64::MAX - 1, 4, |_| false), None);
}

#[test]
fn page_iteration_includes_both_unaligned_endpoints() {
    let mut visited = Vec::new();
    assert_eq!(
        native::any_page(8191, 2, |page| {
            visited.push(page);
            false
        }),
        Some(false)
    );
    assert_eq!(visited, [4096, 8192]);
    assert_eq!(
        native::any_page(0, 0, |_| panic!("empty range visited")),
        Some(false)
    );
}

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
