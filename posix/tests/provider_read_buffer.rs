use filesystem_service::provider_buffer::ProviderReadBuffer;
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
