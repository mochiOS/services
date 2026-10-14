use mochios_posix_protocol::socket::{Create, Domain, Kind, NONBLOCKING};
use posix_service::{
    AuthenticatedProcess, PeerIdentity, PosixService,
    socket::{MAX_ENDPOINTS, RECEIVE_CAPACITY, Shutdown, Streams},
};

fn fixture() -> (PosixService<u32>, PeerIdentity, Streams, Create) {
    let mut service = PosixService::new();
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
    (
        service,
        PeerIdentity {
            process_id: 1,
            effective_uid: 0,
            effective_gid: 0,
        },
        Streams::new(),
        Create {
            domain: Domain::Unix,
            kind: Kind::Stream,
            protocol: 0,
            options: 0,
        },
    )
}

#[test]
fn receive_timeout_is_shared_policy_and_accepted_sockets_snapshot_it() {
    let (service, peer, mut streams, request) = fixture();
    let listener = service.create_socket(peer, request, &mut streams).unwrap();
    let client = service.create_socket(peer, request, &mut streams).unwrap();
    assert_eq!(streams.receive_timeout(listener), Ok(0));
    streams.listen(listener, 2).unwrap();
    streams.set_receive_timeout(listener, 50_000_000).unwrap();
    streams.set_send_timeout(listener, 70_000_000).unwrap();
    let accepted = streams.connect(client, listener).unwrap();
    streams.set_receive_timeout(listener, 100_000_000).unwrap();
    streams.set_send_timeout(listener, 120_000_000).unwrap();
    let ticket = streams.begin_accept(listener).unwrap();
    streams.commit_accept(ticket, (501, 20), 0).unwrap();
    assert_eq!(streams.receive_timeout(accepted), Ok(50_000_000));
    assert_eq!(streams.send_timeout(accepted), Ok(70_000_000));
    assert_eq!(streams.send_timeout(client), Ok(0));
    assert_eq!(streams.set_send_timeout(accepted, 1), Err(-22));
    assert_eq!(streams.send_timeout(accepted), Ok(70_000_000));
    assert_eq!(streams.receive_timeout(client), Ok(0));
    assert_eq!(streams.set_receive_timeout(accepted, 1), Err(-22));
    assert_eq!(streams.receive_timeout(accepted), Ok(50_000_000));
    // The provider stays nonblocking; client-owned wait deadlines apply policy.
    assert_eq!(streams.read(accepted, &mut [0; 1]), Err(-11));
    assert_eq!(streams.write(client, b"x"), Ok(1));
    assert_eq!(streams.read(accepted, &mut [0; 1]), Ok(1));
}

#[test]
fn send_limit_controls_queued_bytes_and_readiness_without_discarding_data() {
    let (service, peer, mut streams, request) = fixture();
    let [a, b] = service
        .create_socket_pair(peer, request, &mut streams)
        .unwrap();
    streams.set_send_capacity(a, 1024).unwrap();
    assert_eq!(streams.send_capacity(a), Ok(1024));
    assert_eq!(streams.write(a, &[b'x'; 2048]), Ok(1024));
    assert!(!streams.readiness(a).unwrap().writable);
    streams.set_send_capacity(a, 256).unwrap();
    assert_eq!(streams.write(a, b"!"), Err(-11));
    assert_eq!(streams.read(b, &mut [0; 769]), Ok(769));
    assert!(streams.readiness(a).unwrap().writable);
    assert_eq!(streams.write(a, b"!!"), Ok(1));
    assert_eq!(streams.write(a, b"!"), Err(-11));
    streams.set_send_capacity(a, 512).unwrap();
    assert!(streams.readiness(a).unwrap().writable);
    let mut bytes = [0; 256];
    assert_eq!(streams.read(b, &mut bytes), Ok(256));
    assert_eq!(&bytes[..255], &[b'x'; 255]);
    assert_eq!(bytes[255], b'!');
    // The other direction and the receiver's setting are independent.
    assert_eq!(
        streams.send_capacity(b),
        Ok(posix_service::socket::SEND_CAPACITY)
    );
    assert_eq!(streams.receive_capacity(b), Ok(RECEIVE_CAPACITY));
    streams.set_receive_capacity(b, 256).unwrap();
    assert_eq!(streams.write(a, &[0; 512]), Ok(256));
    streams.set_send_capacity(a, 0).unwrap();
    assert_eq!(streams.send_capacity(a), Ok(256));
    assert_eq!(streams.set_send_capacity(a, u32::MAX), Err(-22));
    assert_eq!(streams.send_capacity(a), Ok(256));
    assert_eq!(streams.set_send_capacity(u64::MAX, 512), Err(-9));
}

#[test]
fn queued_connections_snapshot_listener_send_limit_before_accept() {
    let (service, peer, mut streams, request) = fixture();
    let listener = service.create_socket(peer, request, &mut streams).unwrap();
    let client = service.create_socket(peer, request, &mut streams).unwrap();
    streams.listen(listener, 2).unwrap();
    streams.set_send_capacity(listener, 512).unwrap();
    let accepted = streams.connect(client, listener).unwrap();
    streams.set_send_capacity(listener, 1024).unwrap();
    let ticket = streams.begin_accept(listener).unwrap();
    streams.commit_accept(ticket, (501, 20), 0).unwrap();
    assert_eq!(streams.send_capacity(accepted), Ok(512));
    assert_eq!(streams.write(accepted, &[0; 1024]), Ok(512));
    assert_eq!(streams.write(accepted, b"x"), Err(-11));
    assert_eq!(
        streams.send_capacity(client),
        Ok(posix_service::socket::SEND_CAPACITY)
    );
}

#[test]
fn creation_uses_registered_credentials_and_rejects_unknown_sender() {
    let (service, peer, mut streams, request) = fixture();
    assert_eq!(
        service.create_socket_pair(
            PeerIdentity {
                process_id: 2,
                ..peer
            },
            request,
            &mut streams
        ),
        Err(-1)
    );
    let [a, b] = service
        .create_socket_pair(peer, request, &mut streams)
        .unwrap();
    assert_eq!([a, b], [1, 2]);
    assert_eq!(streams.credentials(a), Ok((501, 20)));
    assert_eq!(streams.credentials(b), Ok((501, 20)));
    let status = streams.status(a).unwrap();
    assert_eq!(
        (status.uid, status.gid, status.inode, status.mode),
        (501, 20, a, 0o140600)
    );
    assert_eq!(status.link_count, 0);
    assert_ne!(streams.status(b).unwrap().inode, status.inode);
}

#[test]
fn receive_limit_shrink_preserves_queued_bytes_and_blocks_until_below_limit() {
    let (service, peer, mut streams, request) = fixture();
    let [sender, receiver] = service
        .create_socket_pair(peer, request, &mut streams)
        .unwrap();
    assert_eq!(streams.receive_capacity(receiver), Ok(RECEIVE_CAPACITY));
    streams.set_receive_capacity(receiver, 1024).unwrap();
    let data = [b'x'; 1024];
    assert_eq!(streams.write(sender, &data), Ok(1024));
    assert!(!streams.readiness(sender).unwrap().writable);
    streams.set_receive_capacity(receiver, 256).unwrap();
    assert_eq!(streams.write(sender, b"!"), Err(-11));
    let mut prefix = [0; 769];
    assert_eq!(streams.read(receiver, &mut prefix), Ok(prefix.len()));
    assert_eq!(prefix, [b'x'; 769]);
    assert!(streams.readiness(sender).unwrap().writable);
    assert_eq!(streams.write(sender, b"!more"), Ok(1));
    assert!(!streams.readiness(sender).unwrap().writable);
    let mut suffix = [0; 256];
    assert_eq!(streams.read(receiver, &mut suffix), Ok(suffix.len()));
    assert_eq!(&suffix[..255], &[b'x'; 255]);
    assert_eq!(suffix[255], b'!');
    assert!(streams.readiness(sender).unwrap().writable);
    assert_eq!(streams.receive_capacity(sender), Ok(RECEIVE_CAPACITY));
}

#[test]
fn receive_capacity_is_bounded_and_growth_reenables_writes_without_reading() {
    let (service, peer, mut streams, request) = fixture();
    let [a, b] = service
        .create_socket_pair(peer, request, &mut streams)
        .unwrap();
    streams.set_receive_capacity(b, 0).unwrap();
    assert_eq!(
        streams.receive_capacity(b),
        Ok(posix_service::socket::MIN_RECEIVE_CAPACITY)
    );
    assert_eq!(streams.write(a, &[0; 256]), Ok(256));
    assert!(!streams.readiness(a).unwrap().writable);
    streams.set_receive_capacity(b, 512).unwrap();
    assert!(streams.readiness(a).unwrap().writable);
    streams.set_receive_capacity(b, i32::MAX as u32).unwrap();
    assert_eq!(streams.receive_capacity(b), Ok(RECEIVE_CAPACITY));
    assert_eq!(streams.set_receive_capacity(b, u32::MAX), Err(-22));
    assert_eq!(streams.receive_capacity(b), Ok(RECEIVE_CAPACITY));
    assert_eq!(streams.set_receive_capacity(u64::MAX, 512), Err(-9));
}

#[test]
fn queued_connections_inherit_listener_capacity_before_accept_not_on_later_changes() {
    let (service, peer, mut streams, request) = fixture();
    let listener = service.create_socket(peer, request, &mut streams).unwrap();
    let client = service.create_socket(peer, request, &mut streams).unwrap();
    streams.listen(listener, 2).unwrap();
    streams.set_receive_capacity(listener, 512).unwrap();
    let accepted = streams.connect(client, listener).unwrap();
    assert_eq!(streams.write(client, &[0; 1024]), Ok(512));
    streams.set_receive_capacity(listener, 1024).unwrap();
    let ticket = streams.begin_accept(listener).unwrap();
    streams.commit_accept(ticket, (501, 20), 0).unwrap();
    assert_eq!(streams.receive_capacity(accepted), Ok(512));
    assert_eq!(streams.write(client, b"x"), Err(-11));
    assert_eq!(streams.receive_capacity(client), Ok(RECEIVE_CAPACITY));
}

#[test]
fn socket_status_is_identity_not_queued_file_bytes_or_callers_identity() {
    let (service, peer, mut streams, request) = fixture();
    let [a, b] = service
        .create_socket_pair(peer, request, &mut streams)
        .unwrap();
    let original = streams.status(b).unwrap();
    streams.write(a, b"queued bytes").unwrap();
    let status = streams.status(b).unwrap();
    assert_eq!(status, original);
    assert_eq!((status.size, status.blocks), (0, 0));
    streams.release(a).unwrap();
    assert_eq!(streams.status(b), Ok(original));
    assert_eq!(streams.status(a), Err(-9));
    streams.release(b).unwrap();
    let [next, _] = service
        .create_socket_pair(peer, request, &mut streams)
        .unwrap();
    assert_ne!(streams.status(next).unwrap().inode, original.inode);
}

#[test]
fn independent_bidirectional_queues_preserve_order_and_partial_reads() {
    let (service, peer, mut streams, request) = fixture();
    let [a, b] = service
        .create_socket_pair(peer, request, &mut streams)
        .unwrap();
    let mut bytes = [0; 4];
    assert_eq!(streams.read(a, &mut bytes), Err(-11));
    assert_eq!(streams.write(a, b"hello"), Ok(5));
    assert_eq!(streams.write(b, b"1234"), Ok(4));
    assert_eq!(streams.read(a, &mut bytes), Ok(4));
    assert_eq!(&bytes, b"1234");
    assert_eq!(streams.read(b, &mut bytes), Ok(4));
    assert_eq!(&bytes, b"hell");
    assert_eq!(streams.write(a, b"!"), Ok(1));
    assert_eq!(streams.read(b, &mut bytes), Ok(2));
    assert_eq!(&bytes[..2], b"o!");
    assert_eq!(streams.read(b, &mut bytes), Err(-11));
}

#[test]
fn full_queue_applies_backpressure_and_recovers_after_read() {
    let (service, peer, mut streams, request) = fixture();
    let [a, b] = service
        .create_socket_pair(peer, request, &mut streams)
        .unwrap();
    let bytes = vec![7; RECEIVE_CAPACITY + 10];
    assert_eq!(streams.write(a, &bytes), Ok(RECEIVE_CAPACITY));
    assert!(!streams.readiness(a).unwrap().writable);
    assert!(streams.readiness(b).unwrap().readable);
    assert_eq!(streams.write(a, b"x"), Err(-11));
    assert_eq!(streams.write(b, b"y"), Ok(1));
    let mut output = [0; 3];
    assert_eq!(streams.read(b, &mut output), Ok(3));
    assert_eq!(output, [7; 3]);
    assert!(streams.readiness(a).unwrap().writable);
    assert_eq!(streams.write(a, b"abcd"), Ok(3));
    let mut output = vec![0; RECEIVE_CAPACITY];
    assert_eq!(streams.read(b, &mut output), Ok(RECEIVE_CAPACITY));
    assert!(output[..RECEIVE_CAPACITY - 3].iter().all(|byte| *byte == 7));
    assert_eq!(&output[RECEIVE_CAPACITY - 3..], b"abc");
}

#[test]
fn half_close_drains_data_before_eof_and_preserves_reverse_direction() {
    let (service, peer, mut streams, request) = fixture();
    let [a, b] = service
        .create_socket_pair(peer, request, &mut streams)
        .unwrap();
    streams.write(a, b"data").unwrap();
    streams.shutdown(a, Shutdown::Write).unwrap();
    streams.shutdown(a, Shutdown::Write).unwrap();
    assert!(!streams.readiness(a).unwrap().write_error);
    let ready = streams.readiness(b).unwrap();
    assert!(ready.readable && ready.read_closed && ready.writable && !ready.write_closed);
    assert_eq!(streams.write(a, b"x"), Err(-32));
    assert_eq!(streams.write(b, b"reply"), Ok(5));
    let mut output = [0; 8];
    assert_eq!(streams.read(b, &mut output), Ok(4));
    assert_eq!(&output[..4], b"data");
    assert_eq!(streams.read(b, &mut output), Ok(0));
    streams.shutdown(a, Shutdown::Read).unwrap();
    assert_eq!(streams.read(a, &mut output), Ok(0));
    assert_eq!(streams.write(b, b"x"), Err(-32));
    assert!(streams.readiness(b).unwrap().write_closed);
    assert!(streams.readiness(b).unwrap().write_error);
}

#[test]
fn final_release_preserves_peer_queue_then_eof_and_never_reuses_ids() {
    let (service, peer, mut streams, request) = fixture();
    let [a, b] = service
        .create_socket_pair(peer, request, &mut streams)
        .unwrap();
    streams.write(a, b"data").unwrap();
    streams.release(a).unwrap();
    assert_eq!(streams.write(b, b"x"), Err(-32));
    let mut output = [0; 8];
    assert_eq!(streams.read(b, &mut output), Ok(4));
    assert_eq!(&output[..4], b"data");
    assert_eq!(streams.read(b, &mut output), Ok(0));
    streams.release(b).unwrap();
    assert_eq!(streams.release(b), Err(-9));
    assert_eq!(
        service.create_socket_pair(peer, request, &mut streams),
        Ok([3, 4])
    );
    assert_eq!(streams.read(a, &mut output), Err(-9));
}

#[test]
fn description_flags_are_shared_by_alias_not_by_peer_or_another_pair() {
    let (service, peer, mut streams, request) = fixture();
    let [a, b] = service
        .create_socket_pair(
            peer,
            Create {
                options: NONBLOCKING,
                ..request
            },
            &mut streams,
        )
        .unwrap();
    let [c, _] = service
        .create_socket_pair(peer, request, &mut streams)
        .unwrap();
    let alias = a;
    streams.set_options(alias, 0).unwrap();
    assert_eq!(streams.options(a), Ok(0));
    assert_eq!(streams.options(b), Ok(NONBLOCKING));
    assert_eq!(streams.options(c), Ok(0));
    assert_eq!(streams.set_options(a, 2), Err(-22));
    assert_eq!(streams.options(a), Ok(0));
}

#[test]
fn invalid_creation_and_capacity_limits_do_not_publish_partial_pairs() {
    let (service, peer, mut streams, request) = fixture();
    for (invalid, error) in [
        (
            Create {
                options: 2,
                ..request
            },
            -22,
        ),
        (
            Create {
                domain: Domain::Ipv4,
                ..request
            },
            -95,
        ),
        (
            Create {
                domain: Domain::Ipv6,
                ..request
            },
            -95,
        ),
        (
            Create {
                kind: Kind::Datagram,
                ..request
            },
            -95,
        ),
        (
            Create {
                kind: Kind::SequencedPacket,
                ..request
            },
            -95,
        ),
        (
            Create {
                protocol: 1,
                ..request
            },
            -93,
        ),
    ] {
        assert_eq!(
            service.create_socket_pair(peer, invalid, &mut streams),
            Err(error)
        );
    }
    let mut pairs = Vec::new();
    for index in 0..MAX_ENDPOINTS / 2 {
        let ids = service
            .create_socket_pair(peer, request, &mut streams)
            .unwrap();
        assert_eq!(ids, [(index * 2 + 1) as u64, (index * 2 + 2) as u64]);
        pairs.push(ids);
    }
    assert_eq!(
        service.create_socket_pair(peer, request, &mut streams),
        Err(-23)
    );
    streams.release(pairs[0][0]).unwrap();
    assert_eq!(
        service.create_socket_pair(peer, request, &mut streams),
        Err(-23)
    );
    streams.release(pairs[0][1]).unwrap();
    assert_eq!(
        service.create_socket_pair(peer, request, &mut streams),
        Ok([MAX_ENDPOINTS as u64 + 1, MAX_ENDPOINTS as u64 + 2])
    );
}

#[test]
fn zero_length_operations_do_not_consume_data_and_still_validate_ids() {
    let (service, peer, mut streams, request) = fixture();
    let [a, b] = service
        .create_socket_pair(peer, request, &mut streams)
        .unwrap();
    assert_eq!(streams.write(a, &[]), Ok(0));
    assert_eq!(streams.read(a, &mut []), Ok(0));
    assert_eq!(streams.write(9999, &[]), Err(-9));
    assert_eq!(streams.read(9999, &mut []), Err(-9));
    assert_eq!(streams.readiness(9999), Err(-9));
    assert_eq!(streams.shutdown(9999, Shutdown::Both), Err(-9));
    streams.write(a, b"x").unwrap();
    assert_eq!(streams.read(b, &mut []), Ok(0));
    let mut output = [0];
    assert_eq!(streams.read(b, &mut output), Ok(1));
    assert_eq!(output, [b'x']);
    streams.shutdown(a, Shutdown::Both).unwrap();
    assert_eq!(streams.write(a, &[]), Ok(0));
    assert_eq!(streams.read(a, &mut []), Ok(0));
}
