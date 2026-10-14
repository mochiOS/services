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
fn socket_kind_and_listener_state_are_read_only_native_queries() {
    let (mut streams, [a, _]) = fixture();
    let flags = mnu_abi::IPC_DELIVERY_NATIVE_OBJECT;
    for (tag, value) in [(wire::CONTROL_KIND, 1u32), (wire::CONTROL_ACCEPTING, 0)] {
        let query = frame(provider::OP_CONTROL, a, tag, 4, &[]);
        let (reply, bytes) = call(&mut streams, &query, flags, 0);
        assert_eq!((reply.status, reply.value), (0, 4));
        assert_eq!(bytes, value.to_le_bytes());
        assert_eq!(call(&mut streams, &query, 0, 0).0.status, -13);
        assert_eq!(call(&mut streams, &query, flags, 1).0.status, -22);
        for (length, payload) in [
            (0, b"".as_slice()),
            (4, b"x".as_slice()),
            (8, b"".as_slice()),
        ] {
            let invalid = frame(provider::OP_CONTROL, a, tag, length, payload);
            assert_eq!(call(&mut streams, &invalid, flags, 0).0.status, -22);
        }
        let invalid = frame(provider::OP_CONTROL, u64::MAX, tag, 4, &[]);
        assert_eq!(call(&mut streams, &invalid, flags, 0).0.status, -9);
    }
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
    let listener = service
        .create_socket(
            PeerIdentity {
                process_id: 1,
                effective_uid: 501,
                effective_gid: 20,
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
    let query = frame(
        provider::OP_CONTROL,
        listener,
        wire::CONTROL_ACCEPTING,
        4,
        &[],
    );
    assert_eq!(call(&mut streams, &query, flags, 0).1, 0u32.to_le_bytes());
    streams.listen(listener, 3).unwrap();
    assert_eq!(call(&mut streams, &query, flags, 0).1, 1u32.to_le_bytes());
    let client = service
        .create_socket(
            PeerIdentity {
                process_id: 1,
                effective_uid: 501,
                effective_gid: 20,
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
    let accepted = streams.connect(client, listener).unwrap();
    let ticket = streams.begin_accept(listener).unwrap();
    streams.commit_accept(ticket, (501, 20), 0).unwrap();
    let query = frame(
        provider::OP_CONTROL,
        accepted,
        wire::CONTROL_ACCEPTING,
        4,
        &[],
    );
    assert_eq!(call(&mut streams, &query, flags, 0).1, 0u32.to_le_bytes());
}

#[test]
fn libc_socket_option_tags_and_values_do_not_leak_wire_numbers() {
    use mochios_posix_client::socket::{newlib_getsockopt_tag, newlib_getsockopt_value};
    assert_eq!(newlib_getsockopt_tag(1, 3), Ok(wire::CONTROL_KIND));
    assert_eq!(newlib_getsockopt_tag(1, 30), Ok(wire::CONTROL_ACCEPTING));
    assert_eq!(newlib_getsockopt_tag(1, 4), Ok(wire::CONTROL_TAKE_ERROR));
    for (level, option) in [(0, 3), (1, 999)] {
        assert_eq!(newlib_getsockopt_tag(level, option), Err(-92));
    }
    for (kind, native) in [(1u32, 1), (2, 2), (3, 5)] {
        assert_eq!(
            newlib_getsockopt_value(wire::CONTROL_KIND, &kind.to_le_bytes()),
            Ok(native)
        );
    }
    for tag in [wire::CONTROL_KIND, wire::CONTROL_ACCEPTING] {
        assert_eq!(newlib_getsockopt_value(tag, &[]), Err(-5));
        assert_eq!(newlib_getsockopt_value(tag, &[0; 5]), Err(-5));
        assert_eq!(newlib_getsockopt_value(tag, &99u32.to_le_bytes()), Err(-5));
    }
    assert_eq!(
        newlib_getsockopt_value(wire::CONTROL_ACCEPTING, &1u32.to_le_bytes()),
        Ok(1)
    );
    assert_eq!(
        newlib_getsockopt_value(wire::CONTROL_ACCEPTING, &[0; 4]),
        Ok(0)
    );
    assert_eq!(
        newlib_getsockopt_value(wire::CONTROL_TAKE_ERROR, &[0; 4]),
        Ok(0)
    );
    assert_eq!(
        newlib_getsockopt_value(wire::CONTROL_TAKE_ERROR, &104u32.to_le_bytes()),
        Ok(104)
    );
    assert_eq!(
        newlib_getsockopt_value(wire::CONTROL_TAKE_ERROR, &u32::MAX.to_le_bytes()),
        Err(-5)
    );
}

#[test]
fn timeout_frames_are_authenticated_and_validate_lengths_before_mutation() {
    for (set_tag, get_tag) in [
        (
            wire::CONTROL_SET_RECEIVE_TIMEOUT,
            wire::CONTROL_GET_RECEIVE_TIMEOUT,
        ),
        (
            wire::CONTROL_SET_SEND_TIMEOUT,
            wire::CONTROL_GET_SEND_TIMEOUT,
        ),
    ] {
        let (mut streams, [a, _]) = fixture();
        let flags = mnu_abi::IPC_DELIVERY_NATIVE_OBJECT;
        let set = frame(
            provider::OP_CONTROL,
            a,
            set_tag,
            0,
            &50_000_000u64.to_le_bytes(),
        );
        assert_eq!(call(&mut streams, &set, 0, 0).0.status, -13);
        assert_eq!(call(&mut streams, &set, flags, 1).0.status, -22);
        assert_eq!(
            handle_provider_request(&mut streams, &set, flags, 0, &mut []),
            Err(-22)
        );
        for (length, payload) in [(0, vec![]), (0, vec![0; 4]), (8, vec![0; 8])] {
            let invalid = frame(provider::OP_CONTROL, a, set_tag, length, &payload);
            assert_eq!(call(&mut streams, &invalid, flags, 0).0.status, -22);
        }
        assert_eq!(streams.receive_timeout(a), Ok(0));
        assert_eq!(call(&mut streams, &set, flags, 0).0.status, 0);
        let get = frame(provider::OP_CONTROL, a, get_tag, 8, &[]);
        assert_eq!(
            call(&mut streams, &get, flags, 0).1,
            50_000_000u64.to_le_bytes()
        );
    }
}

#[test]
fn receive_timeval_conversion_rejects_invalid_fields_and_keeps_one_deadline() {
    use mochios_posix_client::socket::{
        socket_deadline as receive_deadline,
        socket_timeout_nanoseconds as receive_timeout_nanoseconds,
    };
    assert_eq!(receive_timeout_nanoseconds(1, 123456), Ok(1_123_456_000));
    assert_eq!(receive_timeout_nanoseconds(0, 0), Ok(0));
    for (seconds, micros) in [(-1, 0), (0, -1), (0, 1_000_000), (i64::MAX, 0)] {
        assert_eq!(receive_timeout_nanoseconds(seconds, micros), Err(-22));
    }
    assert_eq!(receive_deadline(100, 0), u64::MAX);
    assert_eq!(receive_deadline(100, 50), 150);
    assert_eq!(receive_deadline(u64::MAX - 5, 100), u64::MAX - 1);
    let mut calls = 0;
    assert_eq!(
        mochios_posix_client::socket::receive(4, true, |_, _| {
            calls += 1;
            if calls == 1 { Ok(2) } else { Err(11) }
        }),
        Ok(2)
    );
}

#[test]
fn send_capacity_controls_require_handle_authority_and_validate_frames() {
    let (mut streams, [a, b]) = fixture();
    let flags = mnu_abi::IPC_DELIVERY_NATIVE_OBJECT;
    let set = frame(
        provider::OP_CONTROL,
        a,
        wire::CONTROL_SET_SEND_CAPACITY,
        0,
        &512u32.to_le_bytes(),
    );
    assert_eq!(call(&mut streams, &set, 0, 0).0.status, -13);
    assert_eq!(call(&mut streams, &set, flags, 1).0.status, -22);
    for (length, payload) in [(0, vec![]), (0, vec![0; 3]), (4, vec![0; 4])] {
        let invalid = frame(
            provider::OP_CONTROL,
            a,
            wire::CONTROL_SET_SEND_CAPACITY,
            length,
            &payload,
        );
        assert_eq!(call(&mut streams, &invalid, flags, 0).0.status, -22);
    }
    assert_eq!(
        handle_provider_request(&mut streams, &set, flags, 0, &mut []),
        Err(-22)
    );
    assert_eq!(
        streams.send_capacity(a),
        Ok(posix_service::socket::SEND_CAPACITY)
    );
    assert_eq!(call(&mut streams, &set, flags, 0).0.status, 0);
    let get = frame(
        provider::OP_CONTROL,
        a,
        wire::CONTROL_GET_SEND_CAPACITY,
        4,
        &[],
    );
    assert_eq!(call(&mut streams, &get, flags, 0).1, 512u32.to_le_bytes());
    assert_eq!(streams.write(a, &[0; 1024]), Ok(512));
    assert_eq!(streams.write(b, &[0; 1024]), Ok(1024));
}

#[test]
fn libc_send_capacity_tags_preserve_validation_and_reject_negative_limits() {
    use mochios_posix_client::socket::{
        newlib_getsockopt_tag, newlib_getsockopt_value, newlib_setsockopt,
    };
    assert_eq!(
        newlib_getsockopt_tag(1, 7),
        Ok(wire::CONTROL_GET_SEND_CAPACITY)
    );
    assert_eq!(
        newlib_setsockopt(1, 7, 512),
        Ok((wire::CONTROL_SET_SEND_CAPACITY, 512u32.to_le_bytes()))
    );
    assert_eq!(newlib_setsockopt(1, 7, -1), Err(-22));
    assert_eq!(
        newlib_getsockopt_value(wire::CONTROL_GET_SEND_CAPACITY, &512u32.to_le_bytes()),
        Ok(512)
    );
    assert_eq!(
        newlib_getsockopt_value(wire::CONTROL_GET_SEND_CAPACITY, &[0; 4]),
        Err(-5)
    );
    assert_eq!(
        newlib_getsockopt_value(wire::CONTROL_GET_SEND_CAPACITY, &[0; 3]),
        Err(-5)
    );
}

#[test]
fn receive_capacity_controls_require_native_authority_and_validate_before_mutation() {
    let (mut streams, [a, b]) = fixture();
    let flags = mnu_abi::IPC_DELIVERY_NATIVE_OBJECT;
    let set = frame(
        provider::OP_CONTROL,
        b,
        wire::CONTROL_SET_RECEIVE_CAPACITY,
        0,
        &512u32.to_le_bytes(),
    );
    assert_eq!(call(&mut streams, &set, 0, 0).0.status, -13);
    assert_eq!(call(&mut streams, &set, flags, 1).0.status, -22);
    assert_eq!(
        streams.receive_capacity(b),
        Ok(posix_service::socket::RECEIVE_CAPACITY)
    );
    for (length, payload) in [(0, vec![]), (0, vec![0; 3]), (4, vec![0; 4])] {
        let invalid = frame(
            provider::OP_CONTROL,
            b,
            wire::CONTROL_SET_RECEIVE_CAPACITY,
            length,
            &payload,
        );
        assert_eq!(call(&mut streams, &invalid, flags, 0).0.status, -22);
    }
    assert_eq!(
        handle_provider_request(&mut streams, &set, flags, 0, &mut []),
        Err(-22)
    );
    assert_eq!(call(&mut streams, &set, flags, 0).0.status, 0);
    let get = frame(
        provider::OP_CONTROL,
        b,
        wire::CONTROL_GET_RECEIVE_CAPACITY,
        4,
        &[],
    );
    assert_eq!(call(&mut streams, &get, flags, 0).1, 512u32.to_le_bytes());
    assert_eq!(streams.write(a, &[0; 1024]), Ok(512));
}

#[test]
fn libc_receive_capacity_options_reject_negative_requests_and_invalid_replies() {
    use mochios_posix_client::socket::{
        newlib_getsockopt_tag, newlib_getsockopt_value, newlib_setsockopt,
    };
    assert_eq!(
        newlib_getsockopt_tag(1, 8),
        Ok(wire::CONTROL_GET_RECEIVE_CAPACITY)
    );
    assert_eq!(
        newlib_setsockopt(1, 8, 512),
        Ok((wire::CONTROL_SET_RECEIVE_CAPACITY, 512u32.to_le_bytes()))
    );
    assert_eq!(newlib_setsockopt(1, 8, -1), Err(-22));
    assert_eq!(newlib_setsockopt(1, 3, 1), Err(-92));
    assert_eq!(newlib_setsockopt(0, 8, 1), Err(-92));
    assert_eq!(
        newlib_getsockopt_value(wire::CONTROL_GET_RECEIVE_CAPACITY, &512u32.to_le_bytes()),
        Ok(512)
    );
    assert_eq!(
        newlib_getsockopt_value(wire::CONTROL_GET_RECEIVE_CAPACITY, &[0; 4]),
        Err(-5)
    );
    assert_eq!(
        newlib_getsockopt_value(wire::CONTROL_GET_RECEIVE_CAPACITY, &u32::MAX.to_le_bytes()),
        Err(-5)
    );
}

#[test]
fn reset_error_is_shared_and_consumed_once_without_discarding_received_bytes() {
    let (mut streams, [a, b]) = fixture();
    streams.write(a, b"unread by peer").unwrap();
    streams.write(b, b"reply").unwrap();
    streams.release(b).unwrap();
    assert_eq!(streams.pending_error(a), Ok(104));
    let query = frame(provider::OP_CONTROL, a, wire::CONTROL_TAKE_ERROR, 4, &[]);
    for (flags, count, error) in [(0, 0, -13), (mnu_abi::IPC_DELIVERY_NATIVE_OBJECT, 1, -22)] {
        assert_eq!(call(&mut streams, &query, flags, count).0.status, error);
        assert_eq!(streams.pending_error(a), Ok(104));
    }
    assert_eq!(
        handle_provider_request(
            &mut streams,
            &query,
            mnu_abi::IPC_DELIVERY_NATIVE_OBJECT,
            0,
            &mut [0; provider::RESPONSE_HEADER_LEN]
        ),
        Err(-22)
    );
    assert_eq!(streams.pending_error(a), Ok(104));
    let flags = mnu_abi::IPC_DELIVERY_NATIVE_OBJECT;
    let ready = frame(provider::OP_CONTROL, a, wire::CONTROL_READINESS, 4, &[]);
    let bits = u32::from_le_bytes(call(&mut streams, &ready, flags, 0).1.try_into().unwrap());
    assert_ne!(bits & wire::ERROR_PENDING, 0);
    for expected in [104u32, 0] {
        let (reply, data) = call(&mut streams, &query, flags, 0);
        assert_eq!((reply.status, reply.value), (0, 4));
        assert_eq!(data, expected.to_le_bytes());
    }
    let bits = u32::from_le_bytes(call(&mut streams, &ready, flags, 0).1.try_into().unwrap());
    assert_eq!(bits & wire::ERROR_PENDING, 0);
    let mut data = [0; 5];
    assert_eq!(streams.read(a, &mut data), Ok(5));
    assert_eq!(&data, b"reply");
    assert_eq!(streams.read(a, &mut data), Ok(0));
}

#[test]
fn read_consumes_reset_only_after_buffered_data_and_orderly_close_has_no_error() {
    for unread in [false, true] {
        let (mut streams, [a, b]) = fixture();
        if unread {
            streams.write(a, b"lost").unwrap();
        }
        streams.write(b, b"kept").unwrap();
        streams.release(b).unwrap();
        assert_eq!(streams.read(a, &mut []), Ok(0));
        assert_eq!(streams.pending_error(a), Ok(if unread { 104 } else { 0 }));
        assert_eq!(streams.read(a, &mut [0; 4]), Ok(4));
        assert_eq!(
            streams.read(a, &mut [0]),
            if unread { Err(-104) } else { Ok(0) }
        );
        assert_eq!(streams.take_error(a), Ok(0));
        assert_eq!(streams.read(a, &mut [0]), Ok(0));
    }
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
fn socket_stat_control_checks_authentication_shape_and_exact_reply_capacity() {
    let (mut streams, [a, _]) = fixture();
    let flags = mnu_abi::IPC_DELIVERY_NATIVE_OBJECT;
    let request = frame(
        provider::OP_CONTROL,
        a,
        wire::CONTROL_STAT,
        mochios_posix_protocol::FILE_STATUS_LEN as u32,
        &[],
    );
    let (header, bytes) = call(&mut streams, &request, flags, 0);
    assert_eq!(header.status, 0);
    assert_eq!(header.value, mochios_posix_protocol::FILE_STATUS_LEN as u64);
    let status = mochios_posix_protocol::decode_file_status(&bytes).unwrap();
    assert_eq!(status, streams.status(a).unwrap());
    assert_eq!(call(&mut streams, &request, 0, 0).0.status, -13);
    assert_eq!(call(&mut streams, &request, flags, 1).0.status, -22);
    for (length, payload) in [
        (0, Vec::new()),
        (111, Vec::new()),
        (113, Vec::new()),
        (112, vec![0]),
    ] {
        assert_eq!(
            call(
                &mut streams,
                &frame(
                    provider::OP_CONTROL,
                    a,
                    wire::CONTROL_STAT,
                    length,
                    &payload
                ),
                flags,
                0
            )
            .0
            .status,
            -22
        );
    }
    let mut short =
        vec![0; provider::RESPONSE_HEADER_LEN + mochios_posix_protocol::FILE_STATUS_LEN - 1];
    assert_eq!(
        handle_provider_request(&mut streams, &request, flags, 0, &mut short),
        Err(-22)
    );
    streams.release(a).unwrap();
    assert_eq!(call(&mut streams, &request, flags, 0).0.status, -9);
}

#[test]
fn socket_pair_names_are_unnamed_and_remain_available_after_peer_release() {
    let (mut streams, [a, b]) = fixture();
    let flags = mnu_abi::IPC_DELIVERY_NATIVE_OBJECT;
    for tag in [wire::CONTROL_LOCAL_ADDRESS, wire::CONTROL_PEER_ADDRESS] {
        let request = frame(
            provider::OP_CONTROL,
            a,
            tag,
            wire::MAX_ADDRESS_LEN as u32,
            &[],
        );
        let (header, bytes) = call(&mut streams, &request, flags, 0);
        assert_eq!(
            (header.status, header.value),
            (0, wire::ADDRESS_HEADER_LEN as u64)
        );
        assert_eq!(
            wire::Address::decode(&bytes),
            Ok(wire::Address::UnixUnnamed)
        );
        assert_eq!(call(&mut streams, &request, 0, 0).0.status, -13);
        assert_eq!(call(&mut streams, &request, flags, 1).0.status, -22);
        for length in [0, 7] {
            assert_eq!(
                call(
                    &mut streams,
                    &frame(provider::OP_CONTROL, a, tag, length, &[]),
                    flags,
                    0
                )
                .0
                .status,
                -22
            );
        }
        assert_eq!(
            call(
                &mut streams,
                &frame(provider::OP_CONTROL, a, tag, 8, &[0]),
                flags,
                0
            )
            .0
            .status,
            -22
        );
    }
    streams.release(b).unwrap();
    assert_eq!(streams.address(a), Ok(wire::Address::UnixUnnamed));
    assert_eq!(streams.address(b), Err(-9));
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
                write_error: false,
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
            write_closed: false,
            write_error: false,
        }),
        0
    );
    assert_ne!(
        native_signals(Readiness {
            readable: false,
            writable: false,
            read_closed: false,
            write_closed: true,
            write_error: true,
        }) & mnu_abi::HANDLE_SIGNAL_PEER_CLOSED,
        0
    );
}
