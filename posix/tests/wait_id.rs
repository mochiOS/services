use mochios_posix_client::{Client, Transport, wait};
use mochios_posix_protocol as protocol;

#[test]
fn selectors_cover_all_pid_current_group_and_group_one_without_aliasing() {
    for (kind, id, selector, group) in [
        (wait::P_ALL, 99, -1, false),
        (wait::P_PID, 1, 1, false),
        (wait::P_PGID, 0, 0, true),
        (wait::P_PGID, 1, 1, true),
        (wait::P_PGID, 32, 32, true),
    ] {
        let request = wait::request(kind, id, wait::WEXITED | wait::WNOWAIT).unwrap();
        assert_eq!(request.selector, selector);
        assert_eq!(request.options & protocol::WAIT_SELECT_GROUP != 0, group);
        assert!(protocol::wait_options_valid(request.options));
        assert_ne!(request.options & protocol::WAIT_SELECT_EVENTS, 0);
    }
    for (kind, id, options) in [
        (wait::P_PID, 0, 4),
        (99, 0, 4),
        (0, 0, 0),
        (0, 0, 16),
        (0, 0, -1),
    ] {
        assert_eq!(wait::request(kind, id, options), Err(22));
    }
}

#[test]
fn child_status_is_described_without_fabricating_sender_identity() {
    use protocol::signal_origin::*;
    for (status, event, detail) in [
        (37 << 8, EXITED, 37),
        (15, KILLED, 15),
        (15 | 0x80, DUMPED, 15),
        ((19 << 8) | 0x7f, STOPPED, 19),
        (0xffff, CONTINUED, protocol::SIGNAL_CONT),
    ] {
        let info = protocol::WaitInfo {
            result: protocol::WaitResult {
                process_id: 42,
                status,
            },
            real_uid: 505,
        };
        let origin = wait::origin(info).unwrap();
        assert_eq!(
            (origin.source, origin.process_id, origin.real_uid),
            (CHILD, 42, 505)
        );
        assert_eq!((origin.child.event, origin.child.status), (event, detail));
    }
    for status in [0x10000, 0x7f, 0x70] {
        assert_eq!(
            wait::origin(protocol::WaitInfo {
                result: protocol::WaitResult {
                    process_id: 42,
                    status
                },
                real_uid: 505
            }),
            Err(5)
        );
    }
}

struct DetailedTransport;
impl Transport for DetailedTransport {
    type Error = ();
    fn call(&self, request: &[u8], response: &mut [u8]) -> Result<usize, ()> {
        let (header, payload) = protocol::decode(request).unwrap();
        assert_eq!(header.opcode, protocol::OP_WAIT_CHILD_INFO);
        let (request, epoch) = protocol::decode_guarded_wait_request(payload).unwrap();
        assert_eq!(
            (request.selector, request.options, epoch),
            (-1, protocol::WAIT_SELECT_EVENTS | protocol::WAIT_EXITED, 23)
        );
        assert_eq!(payload.len(), 24); // selector/options/epoch only, no identity or pointer.
        let mut bytes = [0; protocol::WAIT_INFO_LEN];
        protocol::encode_wait_info(
            protocol::WaitInfo {
                result: protocol::WaitResult {
                    process_id: 42,
                    status: 37 << 8,
                },
                real_uid: 505,
            },
            &mut bytes,
        )
        .unwrap();
        protocol::encode(
            protocol::Header {
                opcode: protocol::OP_STATUS,
                request_id: header.request_id,
                payload_len: bytes.len() as u32,
                ..Default::default()
            },
            &bytes,
            response,
        )
        .map_err(|_| ())
    }
}

#[test]
fn client_decodes_detailed_guarded_reply_in_one_request() {
    let info = Client::new(DetailedTransport)
        .wait_child_info_since(-1, protocol::WAIT_SELECT_EVENTS | protocol::WAIT_EXITED, 23)
        .unwrap();
    assert_eq!(
        (info.result.process_id, info.result.status, info.real_uid),
        (42, 37 << 8, 505)
    );
}
