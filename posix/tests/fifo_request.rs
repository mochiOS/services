use mnu_abi::{HANDLE_RIGHT_READ as R, HANDLE_RIGHT_TRANSFER as T, HANDLE_RIGHT_WRITE as W};
use mochios_posix_protocol::{self as wire, fifo::WaitCondition};
use posix_service::{AttachedObject, OpenedObject, fifo_request};

#[test]
fn rejects_malformed_frames_and_excess_authority_before_worker_call() {
    let payload = WaitCondition::Read.encode().unwrap();
    let good = wire::Header {
        opcode: wire::OP_FIFO_WAIT,
        request_id: 71,
        payload_len: payload.len() as u32,
        ..Default::default()
    };
    let source = AttachedObject {
        handle: 7,
        rights: R | T,
    };
    for header in [
        wire::Header {
            opcode: 65535,
            ..good
        },
        wire::Header { flags: 1, ..good },
        wire::Header { status: 1, ..good },
        wire::Header {
            payload_len: 0,
            ..good
        },
    ] {
        let reply = fifo_request::execute(
            header,
            &payload,
            &[source],
            |_, _| panic!("unvalidated query"),
            |_| panic!("borrowed source"),
        );
        assert!(reply.response.header.status < 0);
        assert!(reply.handles.is_empty());
    }
    for rights in [
        0,
        R,
        W | T,
        R | W | T,
        R | T | mnu_abi::HANDLE_RIGHT_CONTROL,
    ] {
        let reply = fifo_request::execute(
            good,
            &payload,
            &[AttachedObject { rights, ..source }],
            |_, _| panic!("excess authority"),
            |_| panic!("borrowed source"),
        );
        assert_eq!(reply.response.header.status, -13);
    }
    for payload in [&payload[..15], &[0u8; 16][..]] {
        let reply = fifo_request::execute(
            wire::Header {
                payload_len: payload.len() as u32,
                ..good
            },
            payload,
            &[source],
            |_, _| panic!("bad codec"),
            |_| panic!("borrowed source"),
        );
        assert_eq!(reply.response.header.status, -22);
    }
}

#[test]
fn transfers_only_notification_and_closes_invalid_owned_reply() {
    let payload = WaitCondition::Write(512).encode().unwrap();
    let header = wire::Header {
        opcode: wire::OP_FIFO_WAIT,
        request_id: 8,
        payload_len: 16,
        ..Default::default()
    };
    let source = AttachedObject {
        handle: 7,
        rights: W | T,
    };
    for rights in [wire::fifo::NOTIFICATION_RIGHTS, R | T] {
        let mut closed = vec![];
        let reply = fifo_request::execute(
            header,
            &payload,
            &[source],
            |received, condition| {
                assert_eq!(received.handle, 7);
                assert_eq!(condition, WaitCondition::Write(512));
                Ok(OpenedObject { handle: 42, rights })
            },
            |handle| closed.push(handle),
        );
        if rights == wire::fifo::NOTIFICATION_RIGHTS {
            assert_eq!(reply.response.header.status, 0);
            assert_eq!(reply.handles.len(), 1);
            assert!(closed.is_empty());
        } else {
            assert_eq!(reply.response.header.status, -5);
            assert_eq!(closed, vec![42]);
            assert!(reply.handles.is_empty());
        }
    }
}
