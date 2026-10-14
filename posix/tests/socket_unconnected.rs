use mochios_posix_protocol::socket::{Address, Create, Domain, Kind, NONBLOCKING};
use posix_service::{
    AuthenticatedProcess, PeerIdentity, PosixService,
    socket::{MAX_ENDPOINTS, Shutdown, Streams},
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
            options: NONBLOCKING,
        },
    )
}

#[test]
fn listening_changes_readiness_and_bounds_backlog_without_changing_status_options() {
    let (service, peer, mut streams, request) = fixture();
    let id = service.create_socket(peer, request, &mut streams).unwrap();
    assert_eq!(streams.listening_backlog(id), Ok(None));
    streams.listen(id, 0).unwrap();
    assert_eq!(streams.listening_backlog(id), Ok(Some(1)));
    assert_eq!(streams.options(id), Ok(NONBLOCKING));
    let ready = streams.readiness(id).unwrap();
    assert!(
        !ready.readable
            && !ready.writable
            && !ready.read_closed
            && !ready.write_closed
            && !ready.write_error
    );
    assert_eq!(posix_service::socket_provider::native_signals(ready), 0);
    streams.listen(id, u32::MAX).unwrap();
    assert_eq!(
        streams.listening_backlog(id),
        Ok(Some(posix_service::socket::MAX_BACKLOG))
    );
    streams.listen(id, 2).unwrap();
    assert_eq!(streams.listening_backlog(id), Ok(Some(2)));
    let mut bytes = [0];
    assert_eq!(streams.read(id, &mut bytes), Err(-107));
    assert_eq!(streams.write(id, b"x"), Err(-107));
    streams.release(id).unwrap();
    assert_eq!(streams.listen(id, 1), Err(-9));
}

#[test]
fn connected_descriptions_cannot_be_replaced_with_listener_state() {
    let (service, peer, mut streams, request) = fixture();
    let [a, b] = service
        .create_socket_pair(peer, request, &mut streams)
        .unwrap();
    assert_eq!(streams.listen(a, 5), Err(-22));
    assert_eq!(streams.listening_backlog(a), Ok(None));
    assert_eq!(streams.write(a, b"x"), Ok(1));
    let mut bytes = [0];
    assert_eq!(streams.read(b, &mut bytes), Ok(1));
    assert_eq!(bytes, *b"x");
}

#[test]
fn never_connected_socket_has_real_identity_but_no_peer_or_data() {
    let (service, peer, mut streams, request) = fixture();
    assert_eq!(
        service.create_socket(
            PeerIdentity {
                process_id: 2,
                ..peer
            },
            request,
            &mut streams
        ),
        Err(-1)
    );
    let id = service.create_socket(peer, request, &mut streams).unwrap();
    assert_eq!(id, 1);
    assert_eq!(streams.credentials(id), Ok((501, 20)));
    assert_eq!(streams.options(id), Ok(NONBLOCKING));
    assert_eq!(streams.address(id), Ok(Address::UnixUnnamed));
    assert_eq!(streams.peer_address(id), Err(-107));
    assert_eq!(streams.read(id, &mut [0; 1]), Err(-107));
    assert_eq!(streams.write(id, b"x"), Err(-107));
    for how in [Shutdown::Read, Shutdown::Write, Shutdown::Both] {
        assert_eq!(streams.shutdown(id, how), Err(-107));
    }
    assert_eq!(streams.read(id, &mut []), Ok(0));
    assert_eq!(streams.write(id, &[]), Ok(0));
    assert_eq!(streams.peer_address(id), Err(-107));
    assert_eq!(streams.status(id).unwrap().inode, id);
    streams.release(id).unwrap();
    assert_eq!(streams.status(id), Err(-9));
}

#[test]
fn single_and_pair_allocations_share_quota_without_partial_pair_or_id_reuse() {
    let (service, peer, mut streams, request) = fixture();
    let mut ids = Vec::new();
    for _ in 0..MAX_ENDPOINTS - 1 {
        ids.push(service.create_socket(peer, request, &mut streams).unwrap());
    }
    assert_eq!(
        service.create_socket_pair(peer, request, &mut streams),
        Err(-23)
    );
    let last = service.create_socket(peer, request, &mut streams).unwrap();
    assert_eq!(last, MAX_ENDPOINTS as u64);
    assert_eq!(service.create_socket(peer, request, &mut streams), Err(-23));
    streams.release(ids[0]).unwrap();
    streams.release(ids[1]).unwrap();
    let [a, b] = service
        .create_socket_pair(peer, request, &mut streams)
        .unwrap();
    assert_eq!([a, b], [last + 1, last + 2]);
    streams.write(a, b"pair").unwrap();
    let mut bytes = [0; 4];
    assert_eq!(streams.read(b, &mut bytes), Ok(4));
    assert_eq!(&bytes, b"pair");
    streams.release(a).unwrap();
    assert_eq!(streams.peer_address(b), Ok(Address::UnixUnnamed));
    assert_eq!(streams.read(b, &mut bytes), Ok(0));
    assert_eq!(streams.write(b, b"x"), Err(-32));
}
