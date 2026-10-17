use mnu_abi::provider::*;

#[test]
fn shared_read_request_has_bounded_object_offsets_and_no_inline_body() {
    let request = RequestHeader {
        opcode: OP_READ_SHARED,
        object_id: 7,
        argument: 0,
        basis: 4096,
        length: MAX_SHARED_READ_LEN as u32,
        data_length: 0,
    };
    let mut bytes = [0; REQUEST_HEADER_LEN];
    assert_eq!(request.encode(&[], &mut bytes), Ok(REQUEST_HEADER_LEN));
    assert_eq!(RequestHeader::decode(&bytes), Ok((request, &[][..])));
    for invalid in [
        RequestHeader {
            length: 0,
            ..request
        },
        RequestHeader {
            length: request.length + 1,
            ..request
        },
        RequestHeader {
            basis: u64::MAX,
            ..request
        },
        RequestHeader {
            argument: 1,
            ..request
        },
        RequestHeader {
            data_length: 1,
            ..request
        },
    ] {
        assert_eq!(
            invalid.encode(&[], &mut bytes),
            Err(DecodeError::InvalidFields)
        );
    }
}

#[test]
fn shared_read_reply_reports_count_and_position_not_contents() {
    let position = 123456u64.to_le_bytes();
    let mut bytes = [0; RESPONSE_HEADER_LEN + READ_POSITION_LEN];
    for count in [0, 1, MAX_SHARED_READ_LEN] {
        let reply = ResponseHeader {
            opcode: OP_READ_SHARED,
            object_id: 7,
            status: 0,
            value: count as u64,
            data_length: READ_POSITION_LEN as u32,
        };
        reply.encode(&position, &mut bytes).unwrap();
        assert_eq!(ResponseHeader::decode(&bytes), Ok((reply, &position[..])));
        assert_eq!(
            ResponseHeader {
                value: MAX_SHARED_READ_LEN as u64 + 1,
                ..reply
            }
            .encode(&position, &mut bytes),
            Err(DecodeError::InvalidFields)
        );
        assert_eq!(
            ResponseHeader {
                data_length: 0,
                ..reply
            }
            .encode(&[], &mut bytes),
            if count == 0 {
                Ok(RESPONSE_HEADER_LEN)
            } else {
                Err(DecodeError::InvalidFields)
            }
        );
    }
    let failed = ResponseHeader {
        opcode: OP_READ_SHARED,
        object_id: 7,
        status: -13,
        value: 0,
        data_length: 0,
    };
    let length = failed.encode(&[], &mut bytes).unwrap();
    assert_eq!(
        ResponseHeader::decode(&bytes[..length]),
        Ok((failed, &[][..]))
    );
}

#[test]
fn empty_success_declines_transport_but_does_not_encode_eof_or_a_byte_count() {
    let reply = ResponseHeader {
        opcode: OP_READ_SHARED,
        object_id: 7,
        status: 0,
        value: 0,
        data_length: 0,
    };
    let mut bytes = [0; RESPONSE_HEADER_LEN];
    assert_eq!(reply.encode(&[], &mut bytes), Ok(RESPONSE_HEADER_LEN));
    assert_eq!(ResponseHeader::decode(&bytes), Ok((reply, &[][..])));
    // A provider cannot claim consumed bytes while requesting inline retry.
    bytes[24..32].copy_from_slice(&1u64.to_le_bytes());
    assert_eq!(
        ResponseHeader::decode(&bytes),
        Err(DecodeError::InvalidFields)
    );
}
