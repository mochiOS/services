use filesystem_service::provider_buffer::{ProviderReadBuffer, publish};
use mnu_abi::provider::MAX_SHARED_READ_LEN;

#[test]
fn bounded_scratch_storage_reuses_resident_bytes_between_requests() {
    let mut buffer = ProviderReadBuffer::default();
    let bytes = buffer.get(MAX_SHARED_READ_LEN).unwrap();
    assert!(bytes.iter().all(|byte| *byte == 0));
    bytes.fill(0xa5);
    let address = bytes.as_ptr();
    for length in [1, 4096, MAX_SHARED_READ_LEN / 2, MAX_SHARED_READ_LEN] {
        let bytes = buffer.get(length).unwrap();
        assert_eq!(bytes.len(), length);
        assert_eq!(bytes.as_ptr(), address);
        assert!(bytes.iter().all(|byte| *byte == 0xa5));
    }
}

#[test]
fn invalid_sizes_do_not_allocate_or_mutate_the_existing_buffer() {
    let mut buffer = ProviderReadBuffer::default();
    assert_eq!(buffer.get(0), Err(22));
    assert_eq!(buffer.get(MAX_SHARED_READ_LEN + 1), Err(22));
    buffer.get(4096).unwrap().fill(0x7b);
    assert_eq!(buffer.get(usize::MAX), Err(22));
    let grown = buffer.get(8192).unwrap();
    assert!(grown[..4096].iter().all(|byte| *byte == 0x7b));
    assert!(grown[4096..].iter().all(|byte| *byte == 0));
}

#[test]
fn publishing_short_reads_does_not_expose_resident_scratch_suffix() {
    let mut buffer = ProviderReadBuffer::default();
    let bytes = buffer.get(4096).unwrap();
    bytes.fill(0xa5);
    bytes[..5].copy_from_slice(b"hello");
    let mut target = [0x7b; 16];
    let mut positions = Vec::new();
    publish(&bytes[..5], 3, |bytes, offset| {
        positions.push(offset);
        let count = bytes.len().min(2);
        target[offset as usize..offset as usize + count].copy_from_slice(&bytes[..count]);
        Ok(count)
    })
    .unwrap();
    assert_eq!(positions, [3, 5, 7]);
    assert_eq!(&target[3..8], b"hello");
    assert!(
        target[..3]
            .iter()
            .chain(target[8..].iter())
            .all(|byte| *byte == 0x7b)
    );
}

#[test]
fn publishing_retries_interrupts_but_preserves_errors_after_progress() {
    let mut calls = 0;
    assert_eq!(
        publish(b"abc", 0, |_, offset| {
            calls += 1;
            match calls {
                1 => Err(4),
                2 => {
                    assert_eq!(offset, 0);
                    Ok(1)
                }
                _ => {
                    assert_eq!(offset, 1);
                    Err(12)
                }
            }
        }),
        Err(12)
    );
    for count in [0, 4, usize::MAX] {
        assert_eq!(publish(b"abc", 0, |_, _| Ok(count)), Err(5));
    }
}

#[test]
fn publishing_validates_ranges_before_writing_and_handles_eof() {
    assert_eq!(
        publish(b"abc", u64::MAX - 1, |_, _| panic!("overflow")),
        Err(22)
    );
    assert_eq!(publish(b"", 0, |_, _| panic!("EOF")), Ok(()));
}
