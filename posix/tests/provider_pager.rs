use mnu_abi::provider::{
    DecodeError, MAX_DATA_LEN, OP_MEMORY_OBJECT, OP_READ_AT, OP_SYNC, OP_WRITE, OP_WRITE_AT,
    REQUEST_HEADER_LEN, RESPONSE_HEADER_LEN, RequestHeader, ResponseHeader,
};

#[test]
fn sequential_read_response_captures_position_including_eof() {
    use mnu_abi::provider::{MAX_POSITIONED_READ_LEN, OP_READ_WITH_POSITION, READ_POSITION_LEN};
    let request = RequestHeader {
        opcode: OP_READ_WITH_POSITION,
        object_id: 19,
        argument: 0,
        basis: 0,
        length: MAX_POSITIONED_READ_LEN as u32,
        data_length: 0,
    };
    let mut wire = vec![0; RESPONSE_HEADER_LEN + MAX_DATA_LEN];
    let length = request.encode(&[], &mut wire).unwrap();
    assert_eq!(RequestHeader::decode(&wire[..length]).unwrap().0, request);
    for invalid in [
        RequestHeader {
            length: request.length + 1,
            ..request
        },
        RequestHeader {
            argument: 1,
            ..request
        },
        RequestHeader {
            basis: 1,
            ..request
        },
    ] {
        assert_eq!(
            invalid.encode(&[], &mut wire),
            Err(DecodeError::InvalidFields)
        );
    }
    for count in [0, 3, MAX_POSITIONED_READ_LEN] {
        let mut payload = 8192u64.to_le_bytes().to_vec();
        payload.resize(READ_POSITION_LEN + count, 42);
        let response = ResponseHeader {
            opcode: OP_READ_WITH_POSITION,
            status: 0,
            object_id: 19,
            value: count as u64,
            data_length: payload.len() as u32,
        };
        let length = response.encode(&payload, &mut wire).unwrap();
        assert_eq!(
            ResponseHeader::decode(&wire[..length]).unwrap(),
            (response, payload.as_slice())
        );
        assert_eq!(
            ResponseHeader {
                value: count as u64 + 1,
                ..response
            }
            .encode(&payload, &mut wire),
            Err(DecodeError::InvalidFields)
        );
    }
    let missing_position = ResponseHeader {
        opcode: OP_READ_WITH_POSITION,
        status: 0,
        object_id: 19,
        value: 0,
        data_length: 0,
    };
    assert_eq!(
        missing_position.encode(&[], &mut wire),
        Err(DecodeError::InvalidFields)
    );
}

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
    assert!(
        ResponseHeader {
            value: 0,
            ..identity
        }
        .encode(&[], &mut wire).is_ok()
    );
}
