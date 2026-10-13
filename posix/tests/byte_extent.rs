extern crate alloc;
#[path = "../../../core/src/mem/byte_extent.rs"]
mod byte_extent;
#[path = "../../../core/src/mem/shared_pages.rs"]
mod shared_pages;

use byte_extent::{plan, ResizePlan};
use shared_pages::SizeError;

#[test]
fn shrink_revokes_boundary_and_discards_only_complete_pages() {
    assert_eq!(
        plan(10000, 5000, 4096, 3),
        Ok(ResizePlan {
            length: 5000,
            capacity: 8192,
            invalidate: Some(4096..12288),
            zero: Some(5000..8192),
        })
    );
    let aligned = plan(10000, 4096, 4096, 3).unwrap();
    assert_eq!(aligned.invalidate, Some(4096..12288));
    assert_eq!(aligned.zero, None);
    let empty = plan(10000, 0, 4096, 3).unwrap();
    assert_eq!(empty.capacity, 0);
    assert_eq!(empty.invalidate, Some(0..12288));
    assert_eq!(empty.zero, None);
}

#[test]
fn growth_clears_previously_writable_padding() {
    let grow = plan(5000, 10000, 4096, 3).unwrap();
    assert_eq!(grow.capacity, 12288);
    assert_eq!(grow.invalidate, Some(4096..8192));
    assert_eq!(grow.zero, Some(5000..8192));
    let same_page = plan(1, 2, 4096, 1).unwrap();
    assert_eq!(same_page.invalidate, Some(0..4096));
    assert_eq!(same_page.zero, Some(1..4096));
    for old in [0, 4096, 8192] {
        let grow = plan(old, old + 1, 4096, 3).unwrap();
        assert_eq!(grow.invalidate, None);
        assert_eq!(grow.zero, None);
    }
}

#[test]
fn unchanged_extent_needs_no_revocation_or_zeroing() {
    for length in [0, 1, 4096, 4097, 12288] {
        let unchanged = plan(length, length, 4096, 3).unwrap();
        assert_eq!(unchanged.invalidate, None);
        assert_eq!(unchanged.zero, None);
    }
}

#[test]
fn invalid_geometry_overflow_and_original_quota_are_rejected() {
    for page_bytes in [0, 3, 4095] {
        assert_eq!(plan(0, 1, page_bytes, 3), Err(SizeError::Invalid));
    }
    assert_eq!(plan(0, 12289, 4096, 3), Err(SizeError::LimitExceeded));
    assert_eq!(plan(12289, 0, 4096, 3), Err(SizeError::LimitExceeded));
    assert_eq!(
        plan(0, u64::MAX, 4096, u64::MAX),
        Err(SizeError::LimitExceeded)
    );
    assert_eq!(plan(0, u64::MAX, 1, u64::MAX).unwrap().capacity, u64::MAX);
    assert_eq!(plan(0, 0, 4096, 0).unwrap().capacity, 0);
    assert_eq!(plan(0, 1, 4096, 0), Err(SizeError::LimitExceeded));
}
