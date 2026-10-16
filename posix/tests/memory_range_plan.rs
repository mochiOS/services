extern crate alloc;
use mnu_abi::status::Error;

#[path = "../../../core/src/mem/range_plan.rs"]
mod range_plan;

thread_local! {
    static FAIL_ALLOCATION: std::cell::Cell<Option<usize>> = const { std::cell::Cell::new(None) };
}

struct Allocator;
fn fail_allocation() -> bool {
    FAIL_ALLOCATION
        .try_with(|remaining| match remaining.get() {
            Some(0) => true,
            Some(count) => {
                remaining.set(Some(count - 1));
                false
            }
            None => false,
        })
        .unwrap_or(false)
}

unsafe impl std::alloc::GlobalAlloc for Allocator {
    unsafe fn alloc(&self, layout: std::alloc::Layout) -> *mut u8 {
        if fail_allocation() {
            core::ptr::null_mut()
        } else {
            unsafe { std::alloc::System.alloc(layout) }
        }
    }
    unsafe fn realloc(&self, pointer: *mut u8, layout: std::alloc::Layout, size: usize) -> *mut u8 {
        if fail_allocation() {
            core::ptr::null_mut()
        } else {
            unsafe { std::alloc::System.realloc(pointer, layout, size) }
        }
    }
    unsafe fn dealloc(&self, pointer: *mut u8, layout: std::alloc::Layout) {
        unsafe { std::alloc::System.dealloc(pointer, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: Allocator = Allocator;

#[test]
fn adjacent_regions_are_clipped_and_keep_backing_offsets() {
    let regions = [(0x1000, 0x3000, 8192), (0x3000, 0x5000, 65536)];
    let plan = range_plan::collect(0x2000, 0x2000, |cursor| {
        regions
            .iter()
            .find(|(start, end, _)| cursor >= *start && cursor < *end)
            .map(|(start, end, offset)| (*end, Some(offset + cursor - start)))
    });
    assert_eq!(plan, Ok(vec![(12288, 4096), (65536, 4096)]));
}

#[test]
fn no_work_regions_still_validate_coverage() {
    let plan = range_plan::collect(4096, 12288, |cursor| match cursor {
        4096 => Some((8192, None)),
        8192 => Some((12288, Some(7))),
        12288 => Some((16384, None)),
        _ => None,
    });
    assert_eq!(plan, Ok(vec![(7, 4096)]));
    assert_eq!(
        range_plan::collect::<u64>(4096, 4096, |_| Some((8192, None))),
        Ok(vec![])
    );
}

#[test]
fn holes_overflow_and_nonadvancing_regions_fail_before_io() {
    assert_eq!(
        range_plan::collect(4096, 8192, |cursor| {
            (cursor == 4096).then_some((8192, Some(7)))
        }),
        Err(Error::InvalidAddress)
    );
    assert_eq!(
        range_plan::collect::<u64>(u64::MAX - 1, 4096, |_| panic!("overflow lookup")),
        Err(Error::InvalidAddress)
    );
    assert_eq!(
        range_plan::collect(4096, 4096, |_| Some((4096, Some(7)))),
        Err(Error::BackingFailure)
    );
    assert_eq!(
        range_plan::collect(4096, 4096, |_| Some((0, Some(7)))),
        Err(Error::BackingFailure)
    );
}

#[test]
fn plan_owns_backing_references_after_mapping_is_removed() {
    use std::sync::Arc;
    let object = Arc::new(42);
    let plan = range_plan::collect(4096, 4096, |_| Some((8192, Some(object.clone())))).unwrap();
    drop(object);
    assert_eq!(*plan[0].0, 42);
}

#[test]
fn initial_and_growth_allocation_failures_release_every_owned_reference() {
    use std::sync::Arc;
    let object = Arc::new(42);
    for allocations_before_failure in [0, 1] {
        FAIL_ALLOCATION.set(Some(allocations_before_failure));
        let result = range_plan::collect(4096, 4096 * 16, |cursor| {
            Some((cursor + 4096, Some(Arc::clone(&object))))
        });
        FAIL_ALLOCATION.set(None);
        assert_eq!(result, Err(Error::ResourceUnavailable));
        assert_eq!(Arc::strong_count(&object), 1);
    }
    // No work means no allocation even though every region needs validation.
    FAIL_ALLOCATION.set(Some(0));
    let result = range_plan::collect::<u64>(4096, 8192, |cursor| Some((cursor + 4096, None)));
    FAIL_ALLOCATION.set(None);
    assert_eq!(result, Ok(vec![]));
}

#[test]
fn a_later_hole_drops_previously_collected_backing_references() {
    use std::sync::Arc;
    let object = Arc::new(42);
    let result = range_plan::collect(4096, 8192, |cursor| {
        (cursor == 4096).then(|| (8192, Some(Arc::clone(&object))))
    });
    assert_eq!(result, Err(Error::InvalidAddress));
    assert_eq!(Arc::strong_count(&object), 1);
}
