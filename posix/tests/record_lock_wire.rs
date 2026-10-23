//! Authority-free lock messages: corruption must fail before a service can
//! resolve a FileHandle or mutate its process-owned lock registry.
use mochios_posix_protocol::{ProtocolError, record_lock::*};

fn request(operation: Operation) -> Request {
    Request {
        operation,
        origin: Origin::Start,
        start: 0,
        length: 0,
    }
}

#[test]
fn requests_preserve_relative_negative_and_extreme_offsets() {
    for operation in [
        Operation::Query(Kind::Read),
        Operation::Query(Kind::Write),
        Operation::Set(Kind::Read),
        Operation::Set(Kind::Write),
        Operation::Unlock,
    ] {
        for origin in [Origin::Start, Origin::Current, Origin::End] {
            for (start, length) in [
                (0, 0),
                (-10, -20),
                (i64::MIN, i64::MAX),
                (i64::MAX, i64::MIN),
            ] {
                let expected = Request {
                    operation,
                    origin,
                    start,
                    length,
                };
                let mut bytes = [0xa5; REQUEST_LEN + 1];
                encode_request(expected, &mut bytes).unwrap();
                assert_eq!(bytes[REQUEST_LEN], 0xa5);
                assert_eq!(decode_request(&bytes[..REQUEST_LEN]), Ok(expected));
                assert!(decode_request(&bytes).is_err());
            }
        }
    }
}

#[test]
fn requests_reject_unknown_versions_actions_origins_and_reserved_data() {
    let mut valid = [0; REQUEST_LEN];
    encode_request(request(Operation::Set(Kind::Read)), &mut valid).unwrap();
    for length in 0..REQUEST_LEN {
        assert!(decode_request(&valid[..length]).is_err());
    }
    for index in [0, 1, 2, 3, 4, 5, 6, 7, 24, 25, 26, 27, 28, 29, 30, 31] {
        let mut invalid = valid;
        invalid[index] = 0xff;
        assert!(decode_request(&invalid).is_err(), "byte {index}");
    }
    for operation in [Operation::Unlock, Operation::ReleaseFile] {
        encode_request(request(operation), &mut valid).unwrap();
        for kind in 1..=u8::MAX {
            valid[2] = kind;
            assert!(decode_request(&valid).is_err());
        }
    }
}

#[test]
fn file_release_cannot_smuggle_range_or_kind_data() {
    let expected = request(Operation::ReleaseFile);
    let mut valid = [0; REQUEST_LEN];
    encode_request(expected, &mut valid).unwrap();
    assert_eq!(decode_request(&valid), Ok(expected));
    for index in [
        2, 3, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
    ] {
        let mut invalid = valid;
        invalid[index] = 1;
        assert!(decode_request(&invalid).is_err(), "byte {index}");
    }
    for invalid in [
        Request {
            origin: Origin::Current,
            ..expected
        },
        Request {
            start: -1,
            ..expected
        },
        Request {
            length: 1,
            ..expected
        },
    ] {
        let mut out = [0xa5; REQUEST_LEN];
        assert!(encode_request(invalid, &mut out).is_err());
        assert_eq!(out, [0xa5; REQUEST_LEN]);
    }
}

#[test]
fn conflict_replies_keep_full_process_identity_and_absolute_range() {
    for expected in [
        Reply::Done,
        Reply::Unlocked,
        Reply::Conflict {
            owner: 70_000,
            kind: Kind::Read,
            start: 10,
            length: 20,
        },
        Reply::Conflict {
            owner: u64::MAX,
            kind: Kind::Write,
            start: i64::MAX,
            length: 0,
        },
        Reply::Conflict {
            owner: 1,
            kind: Kind::Write,
            start: i64::MAX,
            length: 1,
        },
    ] {
        let mut bytes = [0xa5; REPLY_LEN + 1];
        encode_reply(expected, &mut bytes).unwrap();
        assert_eq!(bytes[REPLY_LEN], 0xa5);
        assert_eq!(decode_reply(&bytes[..REPLY_LEN]), Ok(expected));
        for length in 0..REPLY_LEN {
            assert!(decode_reply(&bytes[..length]).is_err());
        }
        assert!(decode_reply(&bytes).is_err());
    }
}

#[test]
fn replies_reject_noncanonical_results_without_partial_output() {
    for expected in [Reply::Done, Reply::Unlocked] {
        let mut valid = [0; REPLY_LEN];
        encode_reply(expected, &mut valid).unwrap();
        for index in 2..REPLY_LEN {
            let mut invalid = valid;
            invalid[index] = 1;
            assert!(decode_reply(&invalid).is_err(), "byte {index}");
        }
    }
    let conflict = Reply::Conflict {
        owner: 1,
        kind: Kind::Write,
        start: 0,
        length: 0,
    };
    let mut valid = [0; REPLY_LEN];
    encode_reply(conflict, &mut valid).unwrap();
    for index in 0..8 {
        let mut invalid = valid;
        invalid[index] = 0xff;
        assert!(decode_reply(&invalid).is_err());
    }
    for (owner, start, length) in [(0, 0, 0), (1, -1, 0), (1, 0, -1), (1, i64::MAX, 2)] {
        let invalid = Reply::Conflict {
            owner,
            kind: Kind::Read,
            start,
            length,
        };
        let mut out = [0xa5; REPLY_LEN];
        assert!(encode_reply(invalid, &mut out).is_err());
        assert_eq!(out, [0xa5; REPLY_LEN]);
        let mut bytes = valid;
        bytes[8..16].copy_from_slice(&owner.to_le_bytes());
        bytes[16..24].copy_from_slice(&start.to_le_bytes());
        bytes[24..32].copy_from_slice(&length.to_le_bytes());
        assert!(decode_reply(&bytes).is_err());
    }
}

#[test]
fn short_output_buffers_are_unchanged() {
    for length in 0..REQUEST_LEN {
        let mut out = [0xa5; REQUEST_LEN];
        assert_eq!(
            encode_request(request(Operation::Unlock), &mut out[..length]),
            Err(ProtocolError::BufferTooSmall)
        );
        assert_eq!(out, [0xa5; REQUEST_LEN]);
    }
    for length in 0..REPLY_LEN {
        let mut out = [0xa5; REPLY_LEN];
        assert_eq!(
            encode_reply(Reply::Done, &mut out[..length]),
            Err(ProtocolError::BufferTooSmall)
        );
        assert_eq!(out, [0xa5; REPLY_LEN]);
    }
}
