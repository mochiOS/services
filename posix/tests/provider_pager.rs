use mnu_abi::provider::{
    DecodeError, MAX_DATA_LEN, OP_MEMORY_OBJECT, OP_READ_AT, OP_SYNC, OP_WRITE, OP_WRITE_AT,
    REQUEST_HEADER_LEN, RESPONSE_HEADER_LEN, RequestHeader, ResponseHeader,
};

#[test]
fn positioned_requests_preserve_their_offset_without_a_shared_seek() {
    for opcode in [OP_READ_AT, OP_WRITE_AT] {
        let payload: &[u8] = if opcode == OP_WRITE_AT { b"page" } else { &[] };
        let request = RequestHeader {
            opcode,
            object_id: 19,
            argument: 0,
            basis: 8192,
            length: 4,
            data_length: payload.len() as u32,
        };
        let mut wire = [0; REQUEST_HEADER_LEN + 4];
        let length = request.encode(payload, &mut wire).unwrap();
        let (decoded, data) = RequestHeader::decode(&wire[..length]).unwrap();
        assert_eq!(decoded, request);
        assert_eq!(data, payload);
        assert_eq!(
            RequestHeader {
                argument: 1,
                ..request
            }
            .encode(payload, &mut wire),
            Err(DecodeError::InvalidFields)
        );
    }
}

#[test]
fn pager_requests_reject_oversized_and_ambiguous_payloads() {
    let request = RequestHeader {
        opcode: OP_READ_AT,
        object_id: 19,
        argument: 0,
        basis: 8192,
        length: (MAX_DATA_LEN + 1) as u32,
        data_length: 0,
    };
    assert_eq!(
        request.encode(&[], &mut [0; REQUEST_HEADER_LEN]),
        Err(DecodeError::InvalidFields)
    );
    for opcode in [OP_SYNC, OP_MEMORY_OBJECT] {
        let request = RequestHeader {
            opcode,
            length: 0,
            basis: 0,
            ..request
        };
        assert!(request.encode(&[], &mut [0; REQUEST_HEADER_LEN]).is_ok());
        assert_eq!(
            RequestHeader {
                basis: 1,
                ..request
            }
            .encode(&[], &mut [0; REQUEST_HEADER_LEN]),
            Err(DecodeError::InvalidFields)
        );
    }
}

#[test]
fn write_response_captures_position_and_memory_identity_is_nonzero() {
    let header = ResponseHeader {
        opcode: OP_WRITE,
        status: 0,
        object_id: 19,
        value: 4,
        data_length: 8,
    };
    let position = 8192u64.to_le_bytes();
    let mut wire = [0; RESPONSE_HEADER_LEN + 8];
    let length = header.encode(&position, &mut wire).unwrap();
    assert_eq!(
        ResponseHeader::decode(&wire[..length]).unwrap(),
        (header, position.as_slice())
    );
    let identity = ResponseHeader {
        opcode: OP_MEMORY_OBJECT,
        value: 7,
        data_length: 0,
        ..header
    };
    assert!(identity.encode(&[], &mut wire).is_ok());
    assert_eq!(
        ResponseHeader {
            value: 0,
            ..identity
        }
        .encode(&[], &mut wire),
        Err(DecodeError::InvalidFields)
    );
}
