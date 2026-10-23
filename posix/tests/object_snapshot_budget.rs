extern crate alloc;

#[allow(dead_code)]
#[path = "../../../core/src/util/object_snapshot.rs"]
mod snapshot;

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

thread_local! {
    static TRACK: Cell<bool> = const { Cell::new(false) };
    static LIVE: Cell<usize> = const { Cell::new(0) };
    static CALLS: Cell<usize> = const { Cell::new(0) };
}
const BUDGET: usize = 20 * 1024 * 1024;
struct BudgetAllocator;
// Exercise the default realloc contract: acquire the replacement while the
// previous allocation is still live. System.realloc could expand in place and
// hide the kernel allocator's transient memory requirement.
unsafe impl GlobalAlloc for BudgetAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let tracked = TRACK.try_with(Cell::get).unwrap_or(false);
        if tracked && layout.size() > BUDGET.saturating_sub(LIVE.get()) {
            return core::ptr::null_mut();
        }
        let result = unsafe { System.alloc(layout) };
        if tracked && !result.is_null() {
            LIVE.set(LIVE.get() + layout.size());
            CALLS.set(CALLS.get() + 1);
        }
        result
    }
    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        if TRACK.try_with(Cell::get).unwrap_or(false) {
            LIVE.set(LIVE.get() - layout.size());
        }
        unsafe { System.dealloc(pointer, layout) };
    }
}
#[global_allocator]
static ALLOCATOR: BudgetAllocator = BudgetAllocator;

struct Budget;
impl Budget {
    fn enter() -> Self {
        LIVE.set(0);
        CALLS.set(0);
        TRACK.set(true);
        Self
    }
}
impl Drop for Budget {
    fn drop(&mut self) {
        TRACK.set(false);
    }
}

const LENGTH: usize = 14 * 1024 * 1024 + 137;
fn source(offset: u64, output: &mut [u8]) -> Result<usize, u64> {
    let count = LENGTH.saturating_sub(offset as usize).min(output.len());
    output[..count].fill(0x5a);
    Ok(count)
}

#[test]
fn a_finite_image_fits_without_holding_two_large_snapshot_buffers() {
    let old_failed = {
        let _budget = Budget::enter();
        let result = snapshot::read_to_end(64 * 1024 * 1024, 4096, source);
        let failed = matches!(result, Err(error) if error == mnu_abi::status::Error::ResourceUnavailable.into_raw());
        drop(result);
        assert_eq!(LIVE.get(), 0);
        failed
    };
    assert!(
        old_failed,
        "the fixture must reproduce transient realloc pressure"
    );
    let (valid, calls) = {
        let _budget = Budget::enter();
        let result = snapshot::read_extent(LENGTH as u64, 64 * 1024 * 1024, 4096, source);
        let valid = result.as_ref().is_ok_and(|bytes| {
            bytes.len() == LENGTH && bytes[0] == 0x5a && bytes[LENGTH - 1] == 0x5a
        });
        drop(result);
        assert_eq!(LIVE.get(), 0);
        (valid, CALLS.get())
    };
    assert!(valid);
    assert_eq!(calls, 1, "the declared extent needs only one allocation");
}
