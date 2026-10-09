use mochios_posix_client::memory::unmap_span;

#[test]
fn byte_lengths_round_up_without_rounding_the_address_down() {
    assert_eq!(unmap_span(4096, 1), Some(4096));
    assert_eq!(unmap_span(4096, 4096), Some(4096));
    assert_eq!(unmap_span(4096, 4097), Some(8192));
    assert_eq!(unmap_span(4097, 4096), None);
    assert_eq!(unmap_span(4096, 0), None);
}

#[test]
fn length_and_range_overflow_are_rejected() {
    assert_eq!(unmap_span(4096, u64::MAX), None);
    assert_eq!(unmap_span(u64::MAX & !4095, 4096), None);
    assert_eq!(unmap_span(4096, u64::MAX & !4095), None);
}
