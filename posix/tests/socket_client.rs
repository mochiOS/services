use mochios_posix_client::{
    Client, ClientError, ObjectHandleAttachment, ObjectHandles, ObjectTransport, Transport,
};
use mochios_posix_protocol::{
    self as protocol,
    socket::{self as wire, Create, Domain, Kind},
};
use std::sync::{Arc, Mutex};

#[derive(Default)]
struct Reply {
    single: bool,
    status: i32,
    mismatch: bool,
    transport_error: bool,
    payload: Vec<u8>,
    attachments: Vec<ObjectHandleAttachment<u32>>,
    calls: usize,
}
#[derive(Clone)]
struct Mock(Arc<Mutex<Reply>>);
impl Transport for Mock {
    type Error = ();
    fn call(&self, _: &[u8], _: &mut [u8]) -> Result<usize, ()> {
        panic!("socket creation requires Handle-aware IPC")
    }
}
impl ObjectTransport for Mock {
    type Handle = u32;

    fn close_received_handle(&self, _: u32) {
        panic!("unexpected owned reply Handle in this fixture");
    }
    fn call_with_handles(
        &self,
        request: &[u8],
        output: &mut [u8],
        handles: &mut ObjectHandles<u32>,
    ) -> Result<usize, ()> {
        let (header, payload) = protocol::decode(request).unwrap();
        let mut reply = self.0.lock().unwrap();
        assert_eq!(
            header.opcode,
            if reply.single {
                protocol::OP_SOCKET_CREATE
            } else {
                protocol::OP_SOCKET_PAIR
            }
        );
        assert_eq!(header.flags, 0);
        assert_eq!(Create::decode(payload).unwrap(), request_create());
        assert!(handles.is_empty());
        reply.calls += 1;
        for attachment in &reply.attachments {
            handles.push(*attachment).unwrap();
        }
        if reply.transport_error {
            return Err(());
        }
        Ok(protocol::encode(
            protocol::Header {
                opcode: protocol::OP_STATUS,
                request_id: header.request_id + u64::from(reply.mismatch),
                status: reply.status,
                payload_len: reply.payload.len() as u32,
                ..Default::default()
            },
            &reply.payload,
            output,
        )
        .unwrap())
    }
}
fn request_create() -> Create {
    Create {
        domain: Domain::Unix,
        kind: Kind::Stream,
        protocol: 0,
        options: wire::NONBLOCKING,
    }
}
fn pair() -> [ObjectHandleAttachment<u32>; 2] {
    [
        ObjectHandleAttachment {
            handle: 7,
            rights: wire::descriptor_rights(),
        },
        ObjectHandleAttachment {
            handle: 8,
            rights: wire::descriptor_rights(),
        },
    ]
}

#[test]
fn successful_pair_transfers_both_handles_without_closing_them() {
    let state = Arc::new(Mutex::new(Reply {
        attachments: pair().to_vec(),
        ..Default::default()
    }));
    let client = Client::new(Mock(state.clone()));
    let mut closed = Vec::new();
    assert_eq!(
        client.socket_pair(request_create(), |handle| closed.push(handle)),
        Ok(pair())
    );
    assert!(closed.is_empty());
    assert_eq!(state.lock().unwrap().calls, 1);
}

#[test]
fn single_socket_receives_exactly_one_handle_and_reclaims_invalid_replies() {
    let state = Arc::new(Mutex::new(Reply {
        single: true,
        attachments: vec![pair()[0]],
        ..Default::default()
    }));
    let client = Client::new(Mock(state.clone()));
    let mut closed = Vec::new();
    assert_eq!(
        client.open_socket(request_create(), |handle| closed.push(handle)),
        Ok(pair()[0])
    );
    assert!(closed.is_empty());
    for case in 0..6 {
        let mut reply = Reply {
            single: true,
            attachments: vec![pair()[0]],
            ..Default::default()
        };
        match case {
            0 => reply.attachments.clear(),
            1 => reply.attachments.push(pair()[1]),
            2 => reply.attachments[0].rights |= mnu_abi::HANDLE_RIGHT_SEEK,
            3 => reply.status = -95,
            4 => reply.transport_error = true,
            _ => reply.mismatch = true,
        }
        let expected: Vec<_> = reply
            .attachments
            .iter()
            .map(|attachment| attachment.handle)
            .collect();
        *state.lock().unwrap() = reply;
        closed.clear();
        assert!(
            client
                .open_socket(request_create(), |handle| closed.push(handle))
                .is_err()
        );
        assert_eq!(closed, expected);
    }
}

#[test]
fn every_failed_or_malformed_reply_releases_all_owned_attachments() {
    let state = Arc::new(Mutex::new(Reply::default()));
    let client = Client::new(Mock(state.clone()));
    for case in 0..10 {
        let mut reply = Reply {
            attachments: pair().to_vec(),
            ..Default::default()
        };
        match case {
            0 => reply.status = -13,
            1 => reply.mismatch = true,
            2 => reply.transport_error = true,
            3 => reply.payload = vec![0],
            4 => reply.attachments.clear(),
            5 => {
                reply.attachments.pop();
            }
            6 => reply.attachments.push(ObjectHandleAttachment {
                handle: 9,
                rights: wire::descriptor_rights(),
            }),
            7 => reply.attachments[0].rights |= mnu_abi::HANDLE_RIGHT_MAP,
            8 => reply.attachments[1].rights &= !mnu_abi::HANDLE_RIGHT_WAIT,
            _ => reply.attachments[1].handle = reply.attachments[0].handle,
        }
        let mut expected: Vec<_> = reply
            .attachments
            .iter()
            .map(|attachment| attachment.handle)
            .collect();
        expected.dedup();
        *state.lock().unwrap() = reply;
        let mut closed = Vec::new();
        let result = client.socket_pair(request_create(), |handle| closed.push(handle));
        assert!(result.is_err(), "case={case}");
        assert_eq!(closed, expected, "case={case}");
        if case == 0 {
            assert_eq!(result, Err(ClientError::Remote(-13)));
        }
        if case == 2 {
            assert_eq!(result, Err(ClientError::Transport(())));
        }
    }
}

#[test]
fn invalid_request_options_are_rejected_before_allocating_remote_resources() {
    let state = Arc::new(Mutex::new(Reply::default()));
    let client = Client::new(Mock(state.clone()));
    let mut closed = Vec::new();
    assert!(
        client
            .socket_pair(
                Create {
                    options: 2,
                    ..request_create()
                },
                |handle| closed.push(handle)
            )
            .is_err()
    );
    assert_eq!(state.lock().unwrap().calls, 0);
    assert!(closed.is_empty());
}

#[test]
fn c_socket_types_translate_flags_and_keep_cloexec_descriptor_local() {
    use mochios_posix_client::socket::{SOCK_CLOEXEC, SOCK_NONBLOCK, newlib_create};
    for flags in [0, SOCK_NONBLOCK, SOCK_CLOEXEC, SOCK_CLOEXEC | SOCK_NONBLOCK] {
        let (create, cloexec) = newlib_create(1, 1 | flags, 0).unwrap();
        assert_eq!(create.domain, Domain::Unix);
        assert_eq!(create.kind, Kind::Stream);
        assert_eq!(
            create.options,
            if flags & SOCK_NONBLOCK != 0 {
                wire::NONBLOCKING
            } else {
                0
            }
        );
        assert_eq!(cloexec, flags & SOCK_CLOEXEC != 0);
    }
    assert_eq!(
        newlib_create(10, 5, 0).unwrap().0.kind,
        Kind::SequencedPacket
    );
    assert_eq!(newlib_create(2, 2, 17).unwrap().0.protocol, 17);
    assert_eq!(newlib_create(0, 1, 0), Err(-97));
    assert_eq!(newlib_create(1, 3, 0), Err(-94));
    assert_eq!(newlib_create(1, 0x1001, 0), Err(-22));
    assert_eq!(newlib_create(1, 1, -1), Err(-22));
    let metadata = protocol::InheritedFdMetadata {
        kind: protocol::INHERITED_FD_KIND_SOCKET,
        open_flags: 2,
        descriptor_flags: 0,
    };
    assert_eq!(
        protocol::decode_inherited_fd_metadata(
            protocol::encode_inherited_fd_metadata(metadata).unwrap()
        ),
        Some(metadata)
    );
    assert_eq!(
        protocol::inherited_fd_kind_requires_handle(metadata.kind),
        Some(true)
    );
}

#[test]
fn datagram_subtype_is_preserved_by_exec_metadata_without_private_open_flags() {
    let metadata = protocol::InheritedFdMetadata {
        kind: protocol::INHERITED_FD_KIND_DATAGRAM,
        open_flags: 2,
        descriptor_flags: protocol::INHERITED_FD_DESCRIPTOR_CLOEXEC,
    };
    let encoded = protocol::encode_inherited_fd_metadata(metadata).unwrap();
    assert_eq!(protocol::decode_inherited_fd_metadata(encoded), Some(metadata));
    assert_eq!(protocol::inherited_fd_kind_requires_handle(metadata.kind), Some(true));
}

#[test]
fn poll_readiness_distinguishes_eof_from_write_failure_and_never_reports_priority() {
    use mochios_posix_client::socket::poll_events;
    assert_eq!(poll_events(wire::READY_WRITE, 0x7fff), 4);
    assert_eq!(
        poll_events(
            wire::READY_READ | wire::READ_CLOSED | wire::READY_WRITE,
            0x7fff
        ),
        0x45
    );
    assert_eq!(
        poll_events(
            wire::READY_READ
                | wire::READ_CLOSED
                | wire::WRITE_CLOSED
                | wire::WRITE_ERROR
                | wire::ERROR_PENDING,
            0
        ),
        0x18
    );
    assert_eq!(poll_events(wire::WRITE_CLOSED, 4), 4);
    assert_eq!(poll_events(wire::WRITE_CLOSED, 0), 0);
    assert_eq!(poll_events(wire::WRITE_CLOSED | wire::WRITE_ERROR, 4), 4);
    assert_eq!(poll_events(wire::ERROR_PENDING, 0), 8);
    assert_eq!(poll_events(wire::READY_READ | wire::READY_WRITE, 2), 0);
    assert_eq!(poll_events(0, 0x7fff), 0);
}

#[test]
fn readiness_decoder_accepts_pending_errors_and_rejects_unknown_bits() {
    use mochios_posix_client::socket::decode_readiness;
    for bits in [0u32, wire::ERROR_PENDING, wire::READINESS_MASK] {
        assert_eq!(decode_readiness(&bits.to_le_bytes()), Ok(bits));
    }
    for bits in [64u32, u32::MAX] {
        assert_eq!(decode_readiness(&bits.to_le_bytes()), Err(-5));
    }
    assert_eq!(decode_readiness(&[]), Err(-5));
    assert_eq!(decode_readiness(&[0; 5]), Err(-5));
}
