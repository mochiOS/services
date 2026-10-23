extern crate alloc;

#[path = "../../../core/src/util/object_snapshot.rs"]
mod snapshot;

use mnu_abi::status::Error;

#[test]
fn snapshot_is_exact_bounded_and_owned_without_a_seekable_file() {
    let mut source = b"image".to_vec();
    let bytes = snapshot::read(5, 5, |output| {
        output.copy_from_slice(&source);
        Ok(output.len())
    })
    .unwrap();
    source.fill(0);
    assert_eq!(bytes, b"image");
    assert_eq!(
        snapshot::read(0, 5, |output| {
            assert!(output.is_empty());
            Ok(0)
        }),
        Ok(vec![])
    );
}

#[test]
fn extent_errors_and_short_reads_never_produce_an_executable_snapshot() {
    assert_eq!(
        snapshot::read(6, 5, |_| panic!("oversized read")),
        Err(Error::LimitExceeded.into_raw())
    );
    assert_eq!(
        snapshot::read(u64::MAX, 5, |_| panic!("oversized read")),
        Err(Error::LimitExceeded.into_raw())
    );
    for count in [0, 4, 6] {
        assert_eq!(
            snapshot::read(5, 5, |_| Ok(count)),
            Err(Error::BackingFailure.into_raw())
        );
    }
    assert_eq!(
        snapshot::read(5, 5, |_| Err((-13i64) as u64)),
        Err((-13i64) as u64)
    );
}

#[test]
fn positional_snapshot_accepts_partial_reads_and_probes_exact_limit_without_cursor_authority() {
    for maximum in [5, 9] {
        let mut positions = Vec::new();
        let source = b"image";
        let result = snapshot::read_to_end(maximum, 3, |offset, output| {
            positions.push(offset);
            let remaining = &source[offset as usize..];
            let count = remaining.len().min(output.len()).min(2);
            output[..count].copy_from_slice(&remaining[..count]);
            Ok(count)
        })
        .unwrap();
        assert_eq!(result, b"image");
        assert_eq!(positions, [0, 2, 4, 5]);
    }
    assert_eq!(
        snapshot::read_to_end(0, 3, |offset, bytes| {
            assert_eq!(offset, 0);
            assert_eq!(bytes.len(), 1);
            Ok(0)
        }),
        Ok(vec![])
    );
}

#[test]
fn positional_snapshot_never_silently_truncates_or_acknowledges_invalid_backend_counts() {
    let mut reads = Vec::new();
    assert_eq!(
        snapshot::read_to_end(5, 3, |offset, bytes| {
            reads.push((offset, bytes.len()));
            bytes.fill(1);
            Ok(bytes.len())
        }),
        Err(Error::LimitExceeded.into_raw())
    );
    assert_eq!(reads, [(0, 3), (3, 2), (5, 1)]);
    assert_eq!(
        snapshot::read_to_end(0, 3, |_, _| Ok(1)),
        Err(Error::LimitExceeded.into_raw())
    );
    assert_eq!(
        snapshot::read_to_end(5, 0, |_, _| panic!("zero chunk")),
        Err(Error::InvalidArgument.into_raw())
    );
    for maximum in [0, 5] {
        assert_eq!(
            snapshot::read_to_end(maximum, 3, |_, bytes| Ok(bytes.len() + 1)),
            Err(Error::BackingFailure.into_raw())
        );
    }
}

#[test]
fn positional_snapshot_failure_after_progress_and_at_eof_probe_is_not_partial_success() {
    for failing_offset in [0, 2, 4, 5] {
        let mut positions = Vec::new();
        let error = Error::PeerClosed.into_raw();
        assert_eq!(
            snapshot::read_to_end(5, 2, |offset, bytes| {
                positions.push(offset);
                if offset == failing_offset {
                    return Err(error);
                }
                bytes.fill(1);
                Ok(bytes.len())
            }),
            Err(error)
        );
        assert_eq!(positions.last(), Some(&failing_offset));
    }
}

#[test]
fn extent_snapshot_handles_short_reads_and_rejects_forged_lengths() {
    for declared in 0..=6u64 {
        for actual in 0..=6usize {
            let result = snapshot::read_extent(declared, 6, 3, |offset, output| {
                let available = actual.saturating_sub(offset as usize);
                let count = available.min(output.len()).min(2);
                output[..count].fill(0x5a);
                Ok(count)
            });
            if declared as usize == actual {
                assert_eq!(result.unwrap(), vec![0x5a; actual]);
            } else {
                assert_eq!(result, Err(Error::BackingFailure.into_raw()));
            }
        }
    }
    assert_eq!(
        snapshot::read_extent(7, 6, 3, |_, _| panic!("extent exceeds budget")),
        Err(Error::LimitExceeded.into_raw())
    );
    assert_eq!(
        snapshot::read_extent(0, 6, 0, |_, _| panic!("zero chunk")),
        Err(Error::InvalidArgument.into_raw())
    );
}

#[test]
fn extent_snapshot_preserves_io_errors_and_rejects_invalid_counts() {
    for fail_at in [0, 2, 4, 5] {
        let error = Error::PeerClosed.into_raw();
        assert_eq!(
            snapshot::read_extent(5, 6, 2, |offset, output| {
                if offset == fail_at {
                    Err(error)
                } else {
                    Ok(output.len().min(5usize.saturating_sub(offset as usize)))
                }
            }),
            Err(error)
        );
    }
    for declared in [0, 5] {
        assert_eq!(
            snapshot::read_extent(declared, 6, 3, |_, bytes| Ok(bytes.len() + 1)),
            Err(Error::BackingFailure.into_raw())
        );
    }
}
