#[path = "../../../core/src/mem/cache_range.rs"]
mod cache_range;

#[test]
fn cached_ranges_replace_only_intersecting_bytes() {
    let mut output = *b"abcdefgh";
    cache_range::copy_overlap(4094, &mut output, 4096, b"WXYZ").unwrap();
    assert_eq!(&output, b"abWXYZgh");
    cache_range::copy_overlap(4094, &mut output, 4092, b"0123").unwrap();
    assert_eq!(&output, b"23WXYZgh");
    cache_range::copy_overlap(4094, &mut output, 4100, b"+-TAIL").unwrap();
    assert_eq!(&output, b"23WXYZ+-");
}

#[test]
fn uncached_and_empty_ranges_keep_lower_read_data() {
    let mut output = *b"abcdefgh";
    for (offset, data) in [(90, b"before".as_slice()), (108, b"after"), (102, b"")] {
        cache_range::copy_overlap(100, &mut output, offset, data).unwrap();
        assert_eq!(&output, b"abcdefgh");
    }
    cache_range::copy_overlap(100, &mut [], 100, b"data").unwrap();
}

#[test]
fn overflowing_ranges_fail_before_modifying_output() {
    let mut output = *b"abcd";
    assert_eq!(
        cache_range::copy_overlap(u64::MAX - 2, &mut output, 0, b"x"),
        Err(())
    );
    assert_eq!(
        cache_range::copy_overlap(0, &mut output, u64::MAX, b"x"),
        Err(())
    );
    assert_eq!(&output, b"abcd");
}
