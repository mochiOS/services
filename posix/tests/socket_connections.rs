use mochios_posix_protocol::socket::{Create, Domain, Kind, NONBLOCKING};
use posix_service::{
    AuthenticatedProcess, PeerIdentity, PosixService,
    socket::{MAX_ENDPOINTS, Streams},
};

fn fixture(backlog: u32, clients: usize) -> (Streams, u64, Vec<u64>) {
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
    let peer = PeerIdentity {
        process_id: 1,
        effective_uid: 0,
        effective_gid: 0,
    };
    let request = Create {
        domain: Domain::Unix,
        kind: Kind::Stream,
        protocol: 0,
        options: NONBLOCKING,
    };
    let mut streams = Streams::new();
    let listener = service.create_socket(peer, request, &mut streams).unwrap();
    streams.listen(listener, backlog).unwrap();
    let clients = (0..clients)
        .map(|_| service.create_socket(peer, request, &mut streams).unwrap())
        .collect();
    (streams, listener, clients)
}

#[test]
fn queued_connections_are_fifo_and_can_buffer_data_before_accept() {
    let (mut streams, listener, clients) = fixture(2, 2);
    let first = streams.connect(clients[0], listener).unwrap();
    let second = streams.connect(clients[1], listener).unwrap();
    assert!(streams.readiness(listener).unwrap().readable);
    assert_eq!(streams.write(clients[0], b"before accept"), Ok(13));
    let ticket = streams.begin_accept(listener).unwrap();
    assert_eq!(ticket.endpoint(), first);
    assert_eq!(streams.commit_accept(ticket, (600, 30), 0), Ok(first));
    assert_eq!(streams.options(first), Ok(0));
    assert_eq!(streams.credentials(first), Ok((600, 30)));
    let mut data = [0; 32];
    assert_eq!(streams.read(first, &mut data), Ok(13));
    assert_eq!(&data[..13], b"before accept");
    assert_eq!(streams.write(first, b"reply"), Ok(5));
    assert_eq!(streams.read(clients[0], &mut data), Ok(5));
    let ticket = streams.begin_accept(listener).unwrap();
    assert_eq!(ticket.endpoint(), second);
    assert_eq!(
        streams.commit_accept(ticket, (601, 31), NONBLOCKING),
        Ok(second)
    );
    assert!(!streams.readiness(listener).unwrap().readable);
    assert_eq!(streams.begin_accept(listener), Err(-11));
}

#[test]
fn backlog_full_and_shrink_do_not_create_half_connections_or_discard_pending_ones() {
    let (mut streams, listener, clients) = fixture(1, 3);
    streams.connect(clients[0], listener).unwrap();
    assert_eq!(streams.connect(clients[1], listener), Err(-11));
    assert_eq!(streams.write(clients[1], b"x"), Err(-107));
    streams.listen(listener, 2).unwrap();
    streams.connect(clients[1], listener).unwrap();
    streams.listen(listener, 1).unwrap();
    assert_eq!(streams.connect(clients[2], listener), Err(-11));
    let ticket = streams.begin_accept(listener).unwrap();
    streams.commit_accept(ticket, (501, 20), 0).unwrap();
    assert_eq!(streams.connect(clients[2], listener), Err(-11));
    let ticket = streams.begin_accept(listener).unwrap();
    streams.commit_accept(ticket, (501, 20), 0).unwrap();
    assert!(streams.connect(clients[2], listener).is_ok());
}

#[test]
fn aborted_accept_preserves_data_and_retires_the_failed_provider_identity() {
    let (mut streams, listener, clients) = fixture(1, 1);
    let old = streams.connect(clients[0], listener).unwrap();
    streams.write(clients[0], b"keep").unwrap();
    let ticket = streams.begin_accept(listener).unwrap();
    assert_eq!(streams.begin_accept(listener), Err(-16));
    assert_eq!(streams.commit_accept(ticket, (700, 40), 2), Err(-22));
    let replacement = streams.abort_accept(ticket).unwrap();
    assert_ne!(old, replacement);
    // A delayed final release from the failed temporary native Handle cannot
    // erase the request now waiting under its fresh identity.
    assert_eq!(streams.release(old), Err(-9));
    assert_eq!(streams.commit_accept(ticket, (700, 40), 0), Err(-9));
    assert_eq!(streams.abort_accept(ticket), Err(-9));
    assert_eq!(streams.write(clients[0], b"!"), Ok(1));
    let retry = streams.begin_accept(listener).unwrap();
    assert_eq!(retry.endpoint(), replacement);
    streams.commit_accept(retry, (700, 40), 0).unwrap();
    let mut data = [0; 5];
    assert_eq!(streams.read(replacement, &mut data), Ok(5));
    assert_eq!(&data, b"keep!");
}

#[test]
fn listener_close_aborts_only_unaccepted_peers_and_identifies_all_waiters() {
    let (mut streams, listener, clients) = fixture(2, 3);
    let accepted = streams.connect(clients[0], listener).unwrap();
    let ticket = streams.begin_accept(listener).unwrap();
    streams.commit_accept(ticket, (501, 20), 0).unwrap();
    let pending = [
        streams.connect(clients[1], listener).unwrap(),
        streams.connect(clients[2], listener).unwrap(),
    ];
    let observers = streams.release_observers(listener).unwrap();
    assert_eq!(
        observers.iter().collect::<Vec<_>>(),
        [listener, clients[1], clients[2]]
    );
    streams.release(listener).unwrap();
    for (client, server) in clients[1..].iter().zip(pending) {
        assert_eq!(streams.options(server), Err(-9));
        assert_eq!(streams.write(*client, b"x"), Err(-32));
        assert_eq!(streams.read(*client, &mut [0]), Ok(0));
        let ready = streams.readiness(*client).unwrap();
        assert!(ready.read_closed && ready.write_closed && ready.write_error);
    }
    assert_eq!(streams.write(clients[0], b"live"), Ok(4));
    let mut data = [0; 4];
    assert_eq!(streams.read(accepted, &mut data), Ok(4));
    assert_eq!(&data, b"live");
}

#[test]
fn client_close_before_accept_keeps_its_queued_bytes_and_eof() {
    let (mut streams, listener, clients) = fixture(1, 1);
    let server = streams.connect(clients[0], listener).unwrap();
    streams.write(clients[0], b"last").unwrap();
    streams.release(clients[0]).unwrap();
    assert!(streams.readiness(listener).unwrap().readable);
    let ticket = streams.begin_accept(listener).unwrap();
    assert_eq!(streams.commit_accept(ticket, (501, 20), 0), Ok(server));
    let mut data = [0; 4];
    assert_eq!(streams.read(server, &mut data), Ok(4));
    assert_eq!(&data, b"last");
    assert_eq!(streams.read(server, &mut data), Ok(0));
    assert_eq!(streams.write(server, b"x"), Err(-32));
}

#[test]
fn connection_quota_failure_does_not_change_client_or_listener_state() {
    let (mut streams, listener, clients) = fixture(1, MAX_ENDPOINTS - 1);
    assert_eq!(streams.connect(clients[0], listener), Err(-23));
    assert_eq!(streams.begin_accept(listener), Err(-11));
    assert_eq!(streams.write(clients[0], b"x"), Err(-107));
    streams.release(*clients.last().unwrap()).unwrap();
    assert!(streams.connect(clients[0], listener).is_ok());
}

#[test]
fn invalid_state_transitions_leave_existing_connections_intact() {
    let (mut streams, listener, clients) = fixture(1, 2);
    assert_eq!(streams.connect(listener, listener), Err(-22));
    assert_eq!(streams.connect(clients[0], clients[1]), Err(-111));
    assert_eq!(streams.begin_accept(clients[0]), Err(-22));
    let server = streams.connect(clients[0], listener).unwrap();
    assert_eq!(streams.connect(clients[0], listener), Err(-106));
    assert_eq!(streams.listen(clients[0], 2), Err(-22));
    assert_eq!(streams.write(clients[0], b"x"), Ok(1));
    assert_eq!(streams.read(server, &mut [0]), Ok(1));
}
