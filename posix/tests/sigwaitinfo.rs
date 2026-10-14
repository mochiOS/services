use mochios_posix_client::{Client, Transport};
use mochios_posix_protocol::{
    self as protocol,
    signal_origin::{CHILD, ChildStatus, EXITED, FAULT, Origin},
    signal_wait::{Accepted, LEN, decode, encode},
};

fn accepted() -> Accepted {
    Accepted {
        signal: protocol::SIGNAL_CHLD,
        origin: Origin {
            source: CHILD,
            process_id: 123,
            real_uid: 501,
            child: ChildStatus {
                event: EXITED,
                status: 37,
            },
        },
    }
}

#[test]
fn wire_round_trip_is_exact_and_rejects_fabricated_or_incomplete_info() {
    let value = accepted();
    let mut bytes = [0; LEN];
    encode(value, &mut bytes).unwrap();
    assert_eq!(decode(&bytes), Ok(value));
    assert_eq!(bytes.len(), 32);
    for length in [0, LEN - 1, LEN + 1] {
        let mut input = bytes.to_vec();
        input.resize(length, 0);
        assert!(decode(&input).is_err());
    }
    bytes[4] = 1;
    assert!(decode(&bytes).is_err());
    assert!(encode(value, &mut [0; LEN - 1]).is_err());
    for invalid in [
        Accepted { signal: 0, ..value },
        Accepted {
            signal: 65,
            ..value
        },
        Accepted {
            signal: protocol::SIGNAL_KILL,
            ..value
        },
        Accepted {
            signal: protocol::SIGNAL_STOP,
            ..value
        },
        Accepted {
            signal: 12,
            ..value
        },
        Accepted {
            origin: Origin {
                source: FAULT,
                ..Origin::system()
            },
            ..value
        },
        Accepted {
            origin: Origin {
                process_id: 0,
                ..value.origin
            },
            ..value
        },
        Accepted {
            origin: Origin {
                child: ChildStatus::default(),
                ..value.origin
            },
            ..value
        },
    ] {
        assert!(encode(invalid, &mut bytes).is_err());
    }
}

struct Reply;
impl Transport for Reply {
    type Error = ();
    fn call(&self, request: &[u8], response: &mut [u8]) -> Result<usize, ()> {
        let (header, payload) = protocol::decode(request).unwrap();
        assert_eq!(header.opcode, protocol::OP_SIGNAL_THREAD_WAIT_INFO);
        assert_eq!(
            protocol::decode_signal_wait_request(payload),
            Ok((1 << (protocol::SIGNAL_CHLD - 1), 7))
        );
        let mut bytes = [0; LEN];
        encode(accepted(), &mut bytes).unwrap();
        protocol::encode(
            protocol::Header {
                opcode: protocol::OP_STATUS,
                request_id: header.request_id,
                payload_len: LEN as u32,
                ..Default::default()
            },
            &bytes,
            response,
        )
        .map_err(|_| ())
    }
}

#[test]
fn client_gets_signal_and_child_status_in_one_transaction() {
    let client = Client::new(Reply);
    let result = client
        .wait_thread_signal_info_since(1 << (protocol::SIGNAL_CHLD - 1), 7)
        .unwrap();
    assert_eq!(result, accepted());
    let info =
        mochios_posix_client::signal_context::SigInfo::from_origin(result.signal, result.origin)
            .unwrap();
    assert_eq!((info.si_pid, info.si_uid, info.si_status), (123, 501, 37));
    assert_eq!(
        info.si_code,
        mochios_posix_client::signal_context::CLD_EXITED
    );
}

#[test]
fn retired_number_only_opcode_has_no_compatibility_path() {
    let response = posix_service::PosixService::new().handle(
        posix_service::PeerIdentity {
            process_id: 1,
            effective_uid: 0,
            effective_gid: 0,
        },
        protocol::Header {
            opcode: 72,
            ..Default::default()
        },
        &[],
    );
    assert_eq!(response.header.status, protocol::STATUS_ENOSYS);
}
