use mnu_abi::provider;
use posix_service::pty::{ENOTSUP, PtyManager, handle_provider_request};

#[test]
fn generic_file_and_pager_requests_are_rejected_without_killing_the_byte_stream() {
    let mut manager = PtyManager::new();
    let pair = manager.open().unwrap();
    for opcode in [
        provider::OP_READ_AT,
        provider::OP_WRITE_AT,
        provider::OP_SYNC,
        provider::OP_MEMORY_OBJECT,
        provider::OP_READ_WITH_POSITION,
        provider::OP_READ_SHARED,
    ] {
        let length = u32::from(opcode == provider::OP_READ_SHARED);
        let mut request = [0; provider::REQUEST_HEADER_LEN];
        provider::RequestHeader {
            opcode,
            object_id: pair.slave_object_id,
            argument: 0,
            basis: 0,
            length,
            data_length: 0,
        }
        .encode(&[], &mut request)
        .unwrap();
        let mut response = [0; provider::RESPONSE_HEADER_LEN];
        let count = handle_provider_request(&mut manager, &request, &mut response).unwrap();
        let (header, payload) = provider::ResponseHeader::decode(&response[..count]).unwrap();
        assert_eq!(header.opcode, opcode);
        assert_eq!(
            header.status,
            if opcode == provider::OP_MEMORY_OBJECT {
                0
            } else {
                -(i64::from(ENOTSUP))
            }
        );
        assert_eq!(header.value, 0);
        assert!(payload.is_empty());
    }
    assert_eq!(manager.write(pair.slave_object_id, b"still alive"), Ok(11));
    assert_eq!(
        manager.read(pair.master_object_id, 32),
        Ok(b"still alive".to_vec())
    );
}
