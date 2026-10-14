use mnu_abi::provider;
use mochios_posix_protocol::socket::{self as wire, Create, Domain, Kind};
use posix_service::{
    AuthenticatedProcess, PeerIdentity, PosixService, socket::Streams,
    socket_provider::handle_provider_request,
};

fn fixture() -> (Streams, [u64; 2]) {
    let mut service = PosixService::<u32>::new();
    service
        .initialize_bootstrap_process(
            AuthenticatedProcess {
                handle: 1,
                process_id: 1,
            },
            501,
            20,
            &[],
        )
        .unwrap();
    let mut streams = Streams::new();
    let ids = service
        .create_socket_pair(
            PeerIdentity {
                process_id: 1,
                effective_uid: 0,
                effective_gid: 0,
            },
            Create {
                domain: Domain::Unix,
                kind: Kind::Stream,
                protocol: 0,
                options: 0,
            },
            &mut streams,
        )
        .unwrap();
    (streams, ids)
}

fn frame(opcode: u16, object_id: u64, basis: u64, length: u32, payload: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0; provider::REQUEST_HEADER_LEN + payload.len()];
    provider::RequestHeader {
        opcode,
        object_id,
        argument: 0,
        basis,
        length,
        data_length: payload.len() as u32,
    }
    .encode(payload, &mut bytes)
    .unwrap();
    bytes
}

fn call(
    streams: &mut Streams,
    frame: &[u8],
    flags: u32,
    attachments: u32,
) -> (provider::ResponseHeader, Vec<u8>) {
    let mut output = vec![0; provider::RESPONSE_HEADER_LEN + provider::MAX_DATA_LEN];
    let length = handle_provider_request(streams, frame, flags, attachments, &mut output)
        .unwrap()
        .unwrap();
    let (header, data) = provider::ResponseHeader::decode(&output[..length]).unwrap();
    (header, data.to_vec())
}

#[test]
fn native_read_write_frames_preserve_stream_data_and_return_backpressure() {
    let (mut streams, [a, b]) = fixture();
    let flags = mnu_abi::IPC_DELIVERY_NATIVE_OBJECT;
    let write = frame(provider::OP_WRITE, a, 0, 3, b"abc");
    let (response, data) = call(&mut streams, &write, flags, 0);
    assert_eq!(
        (
            response.opcode,
            response.object_id,
            response.status,
            response.value
        ),
        (provider::OP_WRITE, a, 0, 3)
    );
    assert!(data.is_empty());
    let read = frame(provider::OP_READ, b, 0, 2, &[]);
    assert_eq!(call(&mut streams, &read, flags, 0).1, b"ab");
    assert_eq!(call(&mut streams, &read, flags, 0).1, b"c");
    let (response, data) = call(&mut streams, &read, flags, 0);
    assert_eq!((response.status, response.value), (-11, 0));
    assert!(data.is_empty());
}

#[test]
fn ordinary_ipc_and_attached_handles_cannot_forge_object_operations_or_release() {
    let (mut streams, [a, b]) = fixture();
    let flags = mnu_abi::IPC_DELIVERY_NATIVE_OBJECT;
    for opcode in [provider::OP_WRITE, provider::OP_RELEASE] {
        let (payload, length): (&[u8], u32) = if opcode == provider::OP_WRITE {
            (b"x", 1)
        } else {
            (&[], 0)
        };
        let request = frame(opcode, a, 0, length, payload);
        for delivery in [
            0,
            mnu_abi::IPC_DELIVERY_ENDPOINT_HANDLE,
            flags | mnu_abi::IPC_DELIVERY_ENDPOINT_HANDLE,
        ] {
            let (response, data) = call(&mut streams, &request, delivery, 0);
            assert_eq!(response.status, -13);
            assert!(data.is_empty());
        }
        assert_eq!(call(&mut streams, &request, flags, 1).0.status, -22);
        assert_eq!(streams.options(a), Ok(0));
    }
    let read = frame(provider::OP_READ, b, 0, 1, &[]);
    assert_eq!(call(&mut streams, &read, flags, 0).0.status, -11);
}

#[test]
fn control_flags_half_close_and_readiness_are_separate_from_kernel_abi() {
    let (mut streams, [a, b]) = fixture();
    let flags = mnu_abi::IPC_DELIVERY_NATIVE_OBJECT;
    let set = frame(
        provider::OP_CONTROL,
        a,
        wire::CONTROL_SET_OPTIONS,
        0,
        &wire::NONBLOCKING.to_le_bytes(),
    );
    assert_eq!(call(&mut streams, &set, flags, 0).0.status, 0);
    let get = frame(provider::OP_CONTROL, a, wire::CONTROL_GET_OPTIONS, 4, &[]);
    assert_eq!(
        call(&mut streams, &get, flags, 0).1,
        wire::NONBLOCKING.to_le_bytes()
    );
    let shut = frame(
        provider::OP_CONTROL,
        a,
        wire::CONTROL_SHUTDOWN,
        0,
        &wire::SHUTDOWN_WRITE.to_le_bytes(),
    );
    assert_eq!(call(&mut streams, &shut, flags, 0).0.status, 0);
    let ready = frame(provider::OP_CONTROL, b, wire::CONTROL_READINESS, 4, &[]);
    assert_eq!(
        call(&mut streams, &ready, flags, 0).1,
        (wire::READY_READ | wire::READY_WRITE | wire::READ_CLOSED).to_le_bytes()
    );
    let read = frame(provider::OP_READ, b, 0, 1, &[]);
    assert_eq!(call(&mut streams, &read, flags, 0).0.value, 0);
    let write = frame(provider::OP_WRITE, a, 0, 1, b"x");
    assert_eq!(call(&mut streams, &write, flags, 0).0.status, -32);
}

#[test]
fn insufficient_reply_capacity_does_not_consume_data_write_or_shutdown() {
    let (mut streams, [a, b]) = fixture();
    let flags = mnu_abi::IPC_DELIVERY_NATIVE_OBJECT;
    streams.write(a, b"abc").unwrap();
    let read = frame(provider::OP_READ, b, 0, 3, &[]);
    let mut output = vec![0; provider::RESPONSE_HEADER_LEN + 2];
    assert_eq!(
        handle_provider_request(&mut streams, &read, flags, 0, &mut output),
        Err(-22)
    );
    assert_eq!(call(&mut streams, &read, flags, 0).1, b"abc");
    output.truncate(provider::RESPONSE_HEADER_LEN - 1);
    let write = frame(provider::OP_WRITE, a, 0, 1, b"x");
    assert_eq!(
        handle_provider_request(&mut streams, &write, flags, 0, &mut output),
        Err(-22)
    );
    let shut = frame(
        provider::OP_CONTROL,
        a,
        wire::CONTROL_SHUTDOWN,
        0,
        &wire::SHUTDOWN_BOTH.to_le_bytes(),
    );
    assert_eq!(
        handle_provider_request(&mut streams, &shut, flags, 0, &mut output),
        Err(-22)
    );
    assert!(!streams.readiness(a).unwrap().write_closed);
    assert_eq!(call(&mut streams, &read, flags, 0).0.status, -11);
}

#[test]
fn malformed_controls_and_positional_operations_fail_without_mutation() {
    let (mut streams, [a, b]) = fixture();
    let flags = mnu_abi::IPC_DELIVERY_NATIVE_OBJECT;
    for (tag, length, payload) in [
        (wire::CONTROL_GET_OPTIONS, 0, Vec::new()),
        (wire::CONTROL_GET_OPTIONS, 4, vec![0]),
        (wire::CONTROL_SET_OPTIONS, 0, vec![0; 3]),
        (wire::CONTROL_SET_OPTIONS, 0, 2u32.to_le_bytes().to_vec()),
        (wire::CONTROL_SHUTDOWN, 0, 3u32.to_le_bytes().to_vec()),
        (wire::CONTROL_SHUTDOWN, 4, 0u32.to_le_bytes().to_vec()),
        (wire::CONTROL_READINESS, 3, Vec::new()),
    ] {
        assert_eq!(
            call(
                &mut streams,
                &frame(provider::OP_CONTROL, a, tag, length, &payload),
                flags,
                0
            )
            .0
            .status,
            -22
        );
    }
    assert_eq!(streams.options(a), Ok(0));
    assert!(!streams.readiness(b).unwrap().read_closed);
    let seek = frame(provider::OP_SEEK, a, mnu_abi::HANDLE_SEEK_START, 0, &[]);
    assert_eq!(call(&mut streams, &seek, flags, 0).0.status, -29);
    let read_at = frame(provider::OP_READ_AT, a, 1, 1, &[]);
    assert_eq!(call(&mut streams, &read_at, flags, 0).0.status, -29);
    let unknown = frame(provider::OP_CONTROL, a, 999, 0, &[]);
    assert_eq!(call(&mut streams, &unknown, flags, 0).0.status, -95);
    let mut invalid = frame(provider::OP_WRITE, a, 0, 1, b"x");
    invalid[40] = 1;
    assert_eq!(
        handle_provider_request(&mut streams, &invalid, flags, 0, &mut [0; 100]),
        Err(-22)
    );
    assert_eq!(streams.read(b, &mut [0]), Err(-11));
}

#[test]
fn final_native_release_has_no_reply_and_preserves_peer_data_before_eof() {
    let (mut streams, [a, b]) = fixture();
    let flags = mnu_abi::IPC_DELIVERY_NATIVE_OBJECT;
    streams.write(a, b"x").unwrap();
    let release = frame(provider::OP_RELEASE, a, 0, 0, &[]);
    assert_eq!(
        handle_provider_request(&mut streams, &release, flags, 0, &mut []),
        Ok(None)
    );
    assert_eq!(streams.options(a), Err(-9));
    let read = frame(provider::OP_READ, b, 0, 1, &[]);
    assert_eq!(call(&mut streams, &read, flags, 0).1, b"x");
    assert_eq!(call(&mut streams, &read, flags, 0).0.value, 0);
    assert_eq!(
        handle_provider_request(&mut streams, &release, flags, 0, &mut []),
        Err(-9)
    );
}

#[test]
fn socket_handle_authority_excludes_seek_and_mapping() {
    assert_eq!(
        wire::descriptor_rights(),
        mnu_abi::HANDLE_RIGHT_READ
            | mnu_abi::HANDLE_RIGHT_WRITE
            | mnu_abi::HANDLE_RIGHT_CONTROL
            | mnu_abi::HANDLE_RIGHT_WAIT
            | mnu_abi::HANDLE_RIGHT_DUPLICATE
            | mnu_abi::HANDLE_RIGHT_TRANSFER
    );
    assert_eq!(
        wire::descriptor_rights() & (mnu_abi::HANDLE_RIGHT_MAP | mnu_abi::HANDLE_RIGHT_SEEK),
        0
    );
}

#[test]
fn native_wait_signals_include_terminal_completion_without_conflating_half_close() {
    use posix_service::{socket::Readiness, socket_provider::native_signals};
    for read_closed in [false, true] {
        for write_closed in [false, true] {
            let ready = Readiness {
                readable: read_closed,
                writable: !write_closed,
                read_closed,
                write_closed,
            };
            let signals = native_signals(ready);
            assert_eq!(signals & mnu_abi::HANDLE_SIGNAL_READABLE != 0, read_closed);
            assert_ne!(signals & mnu_abi::HANDLE_SIGNAL_WRITABLE, 0);
            assert_eq!(
                signals & mnu_abi::HANDLE_SIGNAL_PEER_CLOSED != 0,
                read_closed && write_closed
            );
        }
    }
    assert_eq!(
        native_signals(Readiness {
            readable: false,
            writable: false,
            read_closed: false,
            write_closed: false
        }),
        0
    );
}
