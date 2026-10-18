#[allow(dead_code)]
#[path = "support/allocation_profile.rs"]
mod profile;

#[test]
fn counters_report_requests_and_phase_deltas_without_allocation() {
    let counters = profile::Counters::default();
    counters.allocation(4096, 10);
    counters.deallocation(4);
    let before = counters.sample();
    counters.allocation(32, 20);
    counters.allocation(64, 30);
    counters.deallocation(7);
    assert_eq!(
        counters.sample().since(&before),
        profile::Sample {
            calls: 2,
            bytes: 96,
            cycles: 50,
            frees: 1,
            free_cycles: 7
        }
    );
}

#[test]
fn measured_system_preserves_alignment_contents_and_zero_initialization() {
    use std::alloc::{GlobalAlloc, Layout};
    let allocator = profile::MeasuredSystem;
    let layout = Layout::from_size_align(32, 64).unwrap();
    // Safety: the same allocator owns each valid live allocation and layout.
    unsafe {
        let first = allocator.alloc_zeroed(layout);
        assert!(!first.is_null());
        assert_eq!(first as usize % 64, 0);
        assert!(
            std::slice::from_raw_parts(first, 32)
                .iter()
                .all(|byte| *byte == 0)
        );
        first.write(0x7a);
        let second = allocator.realloc(first, layout, 128);
        assert!(!second.is_null());
        assert_eq!(second as usize % 64, 0);
        assert_eq!(second.read(), 0x7a);
        allocator.dealloc(second, Layout::from_size_align(128, 64).unwrap());
    }
}
