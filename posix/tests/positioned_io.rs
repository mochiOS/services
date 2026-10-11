use filesystem_service::positioned_io::transfer;

#[test]
fn short_operations_advance_only_the_explicit_position() {
    let mut calls = Vec::new();
    assert_eq!(
        transfer(100, 7, false, |done, position, remaining| {
            calls.push((done, position, remaining));
            Ok(remaining.min(3))
        }),
        Ok(7)
    );
    assert_eq!(calls, [(0, 100, 7), (3, 103, 4), (6, 106, 1)]);
}

#[test]
fn errors_after_progress_preserve_the_transferred_prefix() {
    for write in [false, true] {
        assert_eq!(
            transfer(50, 10, write, |done, _, _| {
                if done == 0 { Ok(4) } else { Err(28) }
            }),
            Ok(4)
        );
        assert_eq!(transfer(50, 10, write, |_, _, _| Err(13)), Err(13));
    }
}

#[test]
fn eof_and_zero_progress_writes_have_distinct_results() {
    assert_eq!(transfer(0, 10, false, |_, _, _| Ok(0)), Ok(0));
    assert_eq!(transfer(0, 10, true, |_, _, _| Ok(0)), Err(5));
    for write in [false, true] {
        assert_eq!(
            transfer(0, 10, write, |done, _, _| {
                Ok(if done == 0 { 3 } else { 0 })
            }),
            Ok(3)
        );
    }
}

#[test]
fn invalid_ranges_are_rejected_before_backend_io() {
    for write in [false, true] {
        assert_eq!(
            transfer(u64::MAX, 1, write, |_, _, _| panic!("overflow did I/O")),
            Err(27)
        );
        assert_eq!(
            transfer(u64::MAX, 0, write, |_, _, _| panic!(
                "empty transfer did I/O"
            )),
            Ok(0)
        );
        assert_eq!(
            transfer(u64::MAX - 1, 1, write, |_, position, _| {
                assert_eq!(position, u64::MAX - 1);
                Ok(1)
            }),
            Ok(1)
        );
    }
}

#[test]
fn impossible_backend_counts_never_overflow_or_index_outside_the_buffer() {
    assert_eq!(transfer(0, 4, false, |_, _, _| Ok(5)), Err(5));
    assert_eq!(transfer(0, 4, true, |_, _, _| Ok(usize::MAX)), Err(5));
}
