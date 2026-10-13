#[path = "../../../core/src/task/memory_range.rs"]
mod native;

use native::{cut, Range};

#[test]
fn reserved_coverage_skips_large_spans_but_never_bridges_a_hole() {
    let mut queries = 0;
    assert!(native::covers_pages(
        0,
        1 << 40,
        |_| {
            queries += 1;
            Some(1 << 40)
        },
        |_| panic!("reservation coverage must not walk resident leaves")
    ));
    assert_eq!(queries, 1);
    assert!(!native::covers_pages(
        0,
        16384,
        |page| match page {
            0 => Some(4096),
            12288 => Some(16384),
            _ => None,
        },
        |page| page == 4096
    ));
    assert!(native::covers_pages(
        0,
        16384,
        |page| match page {
            0 => Some(4096),
            12288 => Some(16384),
            _ => None,
        },
        |page| page == 4096 || page == 8192
    ));
    assert!(!native::covers_pages(4096, 8192, |_| Some(8191), |_| false));
    assert!(!native::covers_pages(0, 4096, |_| Some(0), |_| false));
    assert!(!native::covers_pages(1, 4096, |_| panic!(), |_| panic!()));
    assert!(native::covers_pages(4096, 4096, |_| panic!(), |_| panic!()));
}

#[test]
fn reservation_jump_matches_the_original_per_page_coverage_rule() {
    for low in 0..6 {
        for high in low + 1..=6 {
            for mask in 0..64u64 {
                for start in 0..=6 {
                    for end in start..=6 {
                        let region = |page: u64| {
                            (low * 4096 <= page && page < high * 4096).then_some(high * 4096)
                        };
                        let retained = |page: u64| mask & (1u64 << (page / 4096)) != 0;
                        let original = (start..end).all(|page| {
                            retained(page * 4096)
                                || region(page * 4096)
                                    .is_some_and(|limit| limit >= (page + 1) * 4096)
                        });
                        assert_eq!(
                            native::covers_pages(start * 4096, end * 4096, region, retained),
                            original
                        );
                    }
                }
            }
        }
    }
}

#[test]
fn every_interval_cut_preserves_exact_coverage_without_overlap() {
    // Exercise all relative interval placements, including adjacency, and
    // repeat near the address-space ceiling to catch unchecked arithmetic.
    for base in [0, u64::MAX - 16] {
        for start in 0..8 {
            for end in start + 1..=8 {
                let region = Range {
                    start: base + start,
                    end: base + end,
                };
                for remove_start in 0..9 {
                    for remove_end in remove_start + 1..=9 {
                        let removal = Range {
                            start: base + remove_start,
                            end: base + remove_end,
                        };
                        let pieces = cut(region, removal).unwrap();
                        let ranges = [pieces.before, pieces.removed, pieces.after];
                        let mut cursor = region.start;
                        for piece in ranges.into_iter().flatten() {
                            assert_eq!(piece.start, cursor);
                            assert!(piece.start < piece.end);
                            assert!(piece.end <= region.end);
                            cursor = piece.end;
                        }
                        assert_eq!(cursor, region.end);
                        for address in region.start..region.end {
                            let in_removal = removal.start <= address && address < removal.end;
                            let removed = pieces
                                .removed
                                .is_some_and(|piece| piece.start <= address && address < piece.end);
                            assert_eq!(removed, in_removal);
                        }
                    }
                }
            }
        }
    }
}

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
