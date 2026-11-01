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

#[test]
fn positioned_shared_reads_keep_source_and_destination_offsets_separate() {
    let request = RequestHeader {
        opcode: OP_READ_AT_SHARED,
        object_id: 19,
        argument: 0,
        basis: 4096,
        length: MAX_SHARED_READ_LEN as u32,
        data_length: 8,
    };
    let source = (u64::MAX - MAX_SHARED_READ_LEN as u64).to_le_bytes();
    let mut wire = [0; REQUEST_HEADER_LEN + 8];
    request.encode(&source, &mut wire).unwrap();
    assert_eq!(RequestHeader::decode(&wire), Ok((request, &source[..])));
    for bad in [
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
    ] {
        assert_eq!(
            bad.encode(&source, &mut wire),
            Err(DecodeError::InvalidFields)
        );
    }
    assert_eq!(
        request.encode(&u64::MAX.to_le_bytes(), &mut wire),
        Err(DecodeError::InvalidFields)
    );
    assert_eq!(
        request.encode(&source[..7], &mut wire),
        Err(DecodeError::InvalidFields)
    );
    request.encode(&source, &mut wire).unwrap();
    wire[REQUEST_HEADER_LEN..].copy_from_slice(&u64::MAX.to_le_bytes());
    assert_eq!(
        RequestHeader::decode(&wire),
        Err(DecodeError::InvalidFields)
    );

    let reply = ResponseHeader {
        opcode: OP_READ_AT_SHARED,
        object_id: request.object_id,
        status: 0,
        value: 0,
        data_length: 8,
    };
    let mut wire = [0; RESPONSE_HEADER_LEN + 8];
    reply.encode(&source, &mut wire).unwrap();
    assert_eq!(ResponseHeader::decode(&wire), Ok((reply, &source[..])));
    let declined = ResponseHeader {
        data_length: 0,
        ..reply
    };
    let count = declined.encode(&[], &mut wire).unwrap();
    assert_eq!(
        ResponseHeader::decode(&wire[..count]),
        Ok((declined, &[][..]))
    );
}

#[test]
fn backing_features_are_explicit_bounded_and_not_inferred_from_errors() {
    let mut wire = [0; RESPONSE_HEADER_LEN + 8];
    let base = ResponseHeader {
        opcode: OP_MEMORY_OBJECT,
        object_id: 7,
        status: 0,
        value: 33,
        data_length: 0,
    };
    let count = base.encode(&[], &mut wire).unwrap();
    assert_eq!(ResponseHeader::decode(&wire[..count]), Ok((base, &[][..])));
    assert_eq!(memory_features(33, &[]), Ok(0));
    let extended = ResponseHeader {
        data_length: 8,
        ..base
    };
    let features = MEMORY_FEATURE_READ_AT_SHARED.to_le_bytes();
    extended.encode(&features, &mut wire).unwrap();
    assert_eq!(ResponseHeader::decode(&wire), Ok((extended, &features[..])));
    assert_eq!(
        memory_features(33, &features),
        Ok(MEMORY_FEATURE_READ_AT_SHARED)
    );
    assert_eq!(
        ResponseHeader {
            value: 0,
            ..extended
        }
        .encode(&features, &mut wire),
        Err(DecodeError::InvalidFields)
    );
    assert_eq!(
        extended.encode(&u64::MAX.to_le_bytes(), &mut wire),
        Err(DecodeError::InvalidFields)
    );
    extended.encode(&features, &mut wire).unwrap();
    wire[RESPONSE_HEADER_LEN..].copy_from_slice(&u64::MAX.to_le_bytes());
    assert_eq!(
        ResponseHeader::decode(&wire),
        Err(DecodeError::InvalidFields)
    );
    assert_eq!(
        ResponseHeader {
            status: -11,
            value: 0,
            ..extended
        }
        .encode(&features, &mut wire),
        Err(DecodeError::InvalidFields)
    );
}
