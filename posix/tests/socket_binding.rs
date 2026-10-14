use mochios_filesystem_protocol as fs;
use mochios_posix_protocol::socket::{Create, Domain, Kind};
use posix_service::socket::Streams;
use posix_service::socket_binding::{Bindings, Filesystem, NODE_RIGHTS};
use posix_service::{AuthenticatedProcess, OpenedObject, PeerIdentity, PosixService};

struct Backend {
    next: u32,
    status: fs::NodeStatus,
    rights: u64,
    error: Option<i32>,
    calls: Vec<Vec<u8>>,
    lookups: Vec<Vec<u8>>,
    closed: Vec<u32>,
}
impl Default for Backend {
    fn default() -> Self {
        Self {
            next: 40,
            status: fs::NodeStatus {
                node_id: 10,
                kind: fs::NODE_TYPE_SOCKET,
                link_count: 1,
                ..Default::default()
            },
            rights: NODE_RIGHTS,
            error: None,
            calls: Vec::new(),
            lookups: Vec::new(),
            closed: Vec::new(),
        }
    }
}
impl Filesystem<u32> for Backend {
    fn create_socket(&mut self, path: &[u8]) -> Result<(OpenedObject<u32>, fs::NodeStatus), i32> {
        self.calls.push(path.to_vec());
        if let Some(error) = self.error {
            return Err(error);
        }
        let handle = self.next;
        self.next += 1;
        Ok((
            OpenedObject {
                handle,
                rights: self.rights,
            },
            self.status,
        ))
    }
    fn open_socket(&mut self, path: &[u8]) -> Result<(OpenedObject<u32>, fs::NodeStatus), i32> {
        self.lookups.push(path.to_vec());
        if let Some(error) = self.error {
            return Err(error);
        }
        let handle = self.next;
        self.next += 1;
        Ok((
            OpenedObject {
                handle,
                rights: self.rights,
            },
            self.status,
        ))
    }
    fn close(&mut self, handle: u32) {
        self.closed.push(handle);
    }
}
fn fixture() -> (Streams, [u64; 2], Bindings<u32>, Backend) {
    fixture_kind(Kind::Stream)
}
fn fixture_kind(kind: Kind) -> (Streams, [u64; 2], Bindings<u32>, Backend) {
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
        kind,
        protocol: 0,
        options: 0,
    };
    let mut streams = Streams::new();
    let ids = [
        service.create_socket(peer, request, &mut streams).unwrap(),
        service.create_socket(peer, request, &mut streams).unwrap(),
    ];
    (streams, ids, Bindings::new(), Backend::default())
}

#[test]
fn datagram_connect_uses_authorized_inode_not_spelling_and_has_no_accept_queue() {
    let (mut streams, [server, client], mut bindings, mut backend) = fixture_kind(Kind::Datagram);
    bindings
        .bind_path(&streams, server, b"/server", &mut backend)
        .unwrap();
    backend.status.node_id = 11;
    bindings
        .bind_path(&streams, client, b"/client", &mut backend)
        .unwrap();
    backend.status.node_id = 10;
    assert_eq!(
        bindings.connect_datagram_path(&mut streams, client, b"/alias", &mut backend),
        Ok(server)
    );
    assert_eq!(backend.lookups, [b"/alias".to_vec()]);
    assert_eq!(backend.closed, [42]);
    assert_eq!(streams.listening_backlog(server), Ok(None));
    assert_eq!(streams.peer_address(server), Err(-107));
    use mochios_posix_protocol::socket::Address;
    assert_eq!(streams.address(client), Ok(Address::UnixPath(b"/client")));
    assert_eq!(
        streams.peer_address(client),
        Ok(Address::UnixPath(b"/server"))
    );
    assert_eq!(
        streams.record_observers(server).collect::<Vec<_>>(),
        [client]
    );
    for failure in [-13, -2, -20] {
        backend.error = Some(failure);
        assert_eq!(
            bindings.connect_datagram_path(&mut streams, client, b"/changed", &mut backend),
            Err(failure)
        );
        assert_eq!(
            streams.peer_address(client),
            Ok(Address::UnixPath(b"/server"))
        );
        assert_eq!(backend.closed, [42]);
    }
    backend.error = None;
    backend.status.node_id = 99;
    assert_eq!(
        bindings.connect_datagram_path(&mut streams, client, b"/replaced", &mut backend),
        Err(-111)
    );
    assert_eq!(backend.closed, [42, 43]);
    assert_eq!(
        streams.peer_address(client),
        Ok(Address::UnixPath(b"/server"))
    );
}

#[test]
fn datagram_lookup_type_and_metadata_failures_preserve_connection_and_close_refs() {
    for case in 0..5 {
        let (mut streams, [server, client], mut bindings, mut backend) =
            fixture_kind(Kind::Datagram);
        bindings
            .bind_path(&streams, server, b"/server", &mut backend)
            .unwrap();
        let error = match case {
            0 => {
                backend.rights = mnu_abi::HANDLE_RIGHT_ALL;
                -5
            }
            1 => {
                backend.status.node_id = 0;
                -5
            }
            2 => {
                backend.status.kind = fs::NODE_TYPE_DIRECTORY;
                -111
            }
            3 => {
                backend.status.device = 1;
                -111
            }
            _ => {
                streams.release(server).unwrap();
                -111
            }
        };
        assert_eq!(
            bindings.connect_datagram_path(&mut streams, client, b"/server", &mut backend),
            Err(error)
        );
        assert_eq!(streams.peer_address(client), Err(-107));
        assert_eq!(backend.closed, [41]);
    }
    let (mut streams, [server, client], mut bindings, mut backend) = fixture();
    bindings
        .bind_path(&streams, server, b"/stream", &mut backend)
        .unwrap();
    assert_eq!(
        bindings.connect_datagram_path(&mut streams, client, b"/stream", &mut backend),
        Err(-91)
    );
    assert!(backend.lookups.is_empty());
}

#[test]
fn binding_owns_one_inode_reference_until_final_provider_release() {
    let (mut streams, [a, b], mut bindings, mut backend) = fixture();
    bindings
        .bind_path(&streams, a, b"/socket", &mut backend)
        .unwrap();
    assert_eq!(bindings.address(a), Some(b"/socket".as_slice()));
    assert_eq!(bindings.retained_file(a), Some(40));
    // The pathname can be unlinked and recreated with a different retained inode.
    backend.status.node_id = 11;
    bindings
        .bind_path(&streams, b, b"/socket", &mut backend)
        .unwrap();
    assert_eq!(bindings.retained_file(b), Some(41));
    assert!(backend.closed.is_empty());
    bindings.release(a, &mut backend);
    streams.release(a).unwrap();
    assert_eq!(backend.closed, [40]);
    assert_eq!(bindings.address(b), Some(b"/socket".as_slice()));
    bindings.release(a, &mut backend);
    bindings.release(b, &mut backend);
    streams.release(b).unwrap();
    assert_eq!(backend.closed, [40, 41]);
}

#[test]
fn invalid_or_already_bound_sockets_do_not_mutate_the_filesystem() {
    let (streams, [a, _], mut bindings, mut backend) = fixture();
    assert_eq!(
        bindings.bind_path(&streams, 999, b"/socket", &mut backend),
        Err(-9)
    );
    for path in [b"".as_slice(), b"bad\0name".as_slice(), &[b'x'; 108]] {
        assert_eq!(
            bindings.bind_path(&streams, a, path, &mut backend),
            Err(-22)
        );
    }
    assert!(backend.calls.is_empty());
    bindings
        .bind_path(&streams, a, b"relative", &mut backend)
        .unwrap();
    assert_eq!(
        bindings.bind_path(&streams, a, b"other", &mut backend),
        Err(-22)
    );
    assert_eq!(backend.calls.len(), 1);
    bindings.release(a, &mut backend);
}

#[test]
fn filesystem_errors_are_propagated_without_publishing_a_binding() {
    let (streams, [a, _], mut bindings, mut backend) = fixture();
    for (error, expected) in [(-17, -98), (-13, -13), (-2, -2), (-12, -12)] {
        backend.error = Some(error);
        assert_eq!(
            bindings.bind_path(&streams, a, b"/socket", &mut backend),
            Err(expected)
        );
        assert_eq!(bindings.retained_file(a), None);
    }
    assert!(backend.closed.is_empty());
}

#[test]
fn malformed_created_nodes_are_closed_and_never_published() {
    for case in 0..5 {
        let (streams, [a, _], mut bindings, mut backend) = fixture();
        match case {
            0 => backend.rights |= mnu_abi::HANDLE_RIGHT_READ,
            1 => backend.rights &= !mnu_abi::HANDLE_RIGHT_TRANSFER,
            2 => backend.status.kind = fs::NODE_TYPE_REGULAR,
            3 => backend.status.node_id = 0,
            _ => backend.status.link_count = 0,
        }
        assert_eq!(
            bindings.bind_path(&streams, a, b"/socket", &mut backend),
            Err(-5)
        );
        assert_eq!(bindings.address(a), None);
        assert_eq!(backend.closed, [40]);
    }
}

#[test]
fn the_same_inode_cannot_be_registered_to_two_socket_descriptions() {
    let (streams, [a, b], mut bindings, mut backend) = fixture();
    bindings
        .bind_path(&streams, a, b"/socket", &mut backend)
        .unwrap();
    assert_eq!(
        bindings.bind_path(&streams, b, b"/alias", &mut backend),
        Err(-5)
    );
    assert_eq!(backend.closed, [41]);
    assert_eq!(bindings.retained_file(a), Some(40));
    bindings.release(a, &mut backend);
}

#[test]
fn connection_matches_authorized_inode_not_the_lookup_spelling_and_closes_the_temporary_handle() {
    let (mut streams, [listener, client], mut bindings, mut backend) = fixture();
    bindings
        .bind_path(&streams, listener, b"/server", &mut backend)
        .unwrap();
    streams.listen(listener, 1).unwrap();
    backend.status.node_id = 11;
    bindings
        .bind_path(&streams, client, b"/client", &mut backend)
        .unwrap();
    backend.status.node_id = 10;
    let (matched, accepted) = bindings
        .connect_path(&mut streams, client, b"/hard-link-alias", &mut backend)
        .unwrap();
    assert_eq!(matched, listener);
    assert_eq!(backend.closed, [42]);
    assert_eq!(backend.lookups, [b"/hard-link-alias".to_vec()]);
    let ticket = streams.begin_accept(listener).unwrap();
    assert_eq!(ticket.endpoint(), accepted);
    streams.commit_accept(ticket, (501, 20), 0).unwrap();
    use mochios_posix_protocol::socket::Address;
    assert_eq!(streams.address(client), Ok(Address::UnixPath(b"/client")));
    assert_eq!(
        streams.peer_address(client),
        Ok(Address::UnixPath(b"/server"))
    );
    assert_eq!(streams.address(accepted), Ok(Address::UnixPath(b"/server")));
    bindings.release(client, &mut backend);
    streams.release(client).unwrap();
    bindings.release(listener, &mut backend);
    streams.release(listener).unwrap();
    assert_eq!(
        streams.peer_address(accepted),
        Ok(Address::UnixPath(b"/client"))
    );
    assert_eq!(streams.address(accepted), Ok(Address::UnixPath(b"/server")));
    assert_eq!(backend.closed, [42, 41, 40]);
}

#[test]
fn stopped_or_missing_listeners_never_publish_connections_and_release_lookup_handles() {
    for stopped in [false, true] {
        let (mut streams, [listener, client], mut bindings, mut backend) = fixture();
        bindings
            .bind_path(&streams, listener, b"/server", &mut backend)
            .unwrap();
        if stopped {
            streams.listen(listener, 1).unwrap();
            bindings.release(listener, &mut backend);
            streams.release(listener).unwrap();
        }
        assert_eq!(
            bindings.connect_path(&mut streams, client, b"/server", &mut backend),
            Err(-111)
        );
        assert_eq!(streams.write(client, b"x"), Err(-107));
        assert_eq!(backend.closed.last(), Some(&41));
        bindings.release(listener, &mut backend);
    }
}

#[test]
fn rejected_lookup_metadata_does_not_leak_handles_or_fill_the_listener_queue() {
    for case in 0..5 {
        let (mut streams, [listener, client], mut bindings, mut backend) = fixture();
        bindings
            .bind_path(&streams, listener, b"/server", &mut backend)
            .unwrap();
        streams.listen(listener, 1).unwrap();
        let expected = match case {
            0 => {
                backend.rights |= mnu_abi::HANDLE_RIGHT_READ;
                -5
            }
            1 => {
                backend.status.node_id = 0;
                -5
            }
            2 => {
                backend.status.kind = fs::NODE_TYPE_REGULAR;
                -111
            }
            3 => {
                backend.status.device = 99;
                -111
            }
            _ => {
                backend.status.node_id = 99;
                -111
            }
        };
        assert_eq!(
            bindings.connect_path(&mut streams, client, b"/server", &mut backend),
            Err(expected)
        );
        assert_eq!(backend.closed, [41]);
        assert_eq!(streams.begin_accept(listener), Err(-11));
        bindings.release(listener, &mut backend);
    }
}

#[test]
fn lookup_failures_and_invalid_clients_preserve_existing_binding_references() {
    let (mut streams, [listener, client], mut bindings, mut backend) = fixture();
    bindings
        .bind_path(&streams, listener, b"/server", &mut backend)
        .unwrap();
    streams.listen(listener, 1).unwrap();
    assert_eq!(
        bindings.connect_path(&mut streams, 999, b"/server", &mut backend),
        Err(-9)
    );
    assert!(backend.lookups.is_empty());
    for (error, expected) in [(-13, -13), (-2, -2), (-88, -111)] {
        backend.error = Some(error);
        assert_eq!(
            bindings.connect_path(&mut streams, client, b"/server", &mut backend),
            Err(expected)
        );
        assert!(backend.closed.is_empty());
        assert_eq!(bindings.retained_file(listener), Some(40));
    }
    bindings.release(listener, &mut backend);
}

fn extra_socket(streams: &mut Streams) -> u64 {
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
    service
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
            streams,
        )
        .unwrap()
}

#[test]
fn backlog_retry_retains_the_original_target_instead_of_reopening_a_replaced_path() {
    let (mut streams, [listener, first], mut bindings, mut backend) = fixture();
    let waiting = extra_socket(&mut streams);
    let replacement = extra_socket(&mut streams);
    bindings
        .bind_path(&streams, listener, b"/server", &mut backend)
        .unwrap();
    streams.listen(listener, 1).unwrap();
    bindings
        .connect_path(&mut streams, first, b"/server", &mut backend)
        .unwrap();
    let target = bindings
        .prepare_connect(&streams, waiting, b"/server", &mut backend)
        .unwrap();
    assert_eq!((target.client(), target.listener()), (waiting, listener));
    assert_eq!(bindings.try_connect(&mut streams, &target), Err(-11));
    assert_eq!(backend.closed, [41]);
    // Model unlink/recreate: subsequent pathname lookups return a new inode.
    backend.status.node_id = 11;
    bindings
        .bind_path(&streams, replacement, b"/server", &mut backend)
        .unwrap();
    streams.listen(replacement, 1).unwrap();
    let ticket = streams.begin_accept(listener).unwrap();
    streams.commit_accept(ticket, (501, 20), 0).unwrap();
    let (matched, accepted) = bindings.try_connect(&mut streams, &target).unwrap();
    assert_eq!(matched, listener);
    assert_eq!(streams.begin_accept(replacement), Err(-11));
    assert_eq!(backend.lookups.len(), 2);
    assert_eq!(streams.write(waiting, b"original"), Ok(8));
    assert_eq!(streams.read(accepted, &mut [0; 8]), Ok(8));
    target.release_with(|handle| backend.close(handle));
    assert_eq!(backend.closed, [41, 42]);
    bindings.release(listener, &mut backend);
    bindings.release(replacement, &mut backend);
    assert_eq!(backend.closed, [41, 42, 40, 43]);
}

#[test]
fn retired_listener_cannot_be_replaced_even_with_the_same_inode_identity() {
    let (mut streams, [listener, client], mut bindings, mut backend) = fixture();
    let replacement = extra_socket(&mut streams);
    bindings
        .bind_path(&streams, listener, b"/server", &mut backend)
        .unwrap();
    streams.listen(listener, 1).unwrap();
    let target = bindings
        .prepare_connect(&streams, client, b"/alias", &mut backend)
        .unwrap();
    bindings.release(listener, &mut backend);
    streams.release(listener).unwrap();
    // Even an untrusted backend recycling its identity cannot redirect a job.
    bindings
        .bind_path(&streams, replacement, b"/server", &mut backend)
        .unwrap();
    streams.listen(replacement, 1).unwrap();
    assert_eq!(bindings.try_connect(&mut streams, &target), Err(-111));
    assert_eq!(streams.begin_accept(replacement), Err(-11));
    assert_eq!(backend.lookups.len(), 1);
    target.release_with(|handle| backend.close(handle));
    assert_eq!(backend.closed, [40, 41]);
    bindings.release(replacement, &mut backend);
}

#[test]
fn cancelling_or_losing_a_client_releases_the_lookup_without_publishing_a_connection() {
    for lost_client in [false, true] {
        let (mut streams, [listener, client], mut bindings, mut backend) = fixture();
        bindings
            .bind_path(&streams, listener, b"/server", &mut backend)
            .unwrap();
        streams.listen(listener, 1).unwrap();
        let target = bindings
            .prepare_connect(&streams, client, b"/server", &mut backend)
            .unwrap();
        if lost_client {
            streams.release(client).unwrap();
            assert_eq!(bindings.try_connect(&mut streams, &target), Err(-9));
        }
        target.release_with(|handle| backend.close(handle));
        assert_eq!(backend.closed, [41]);
        assert_eq!(streams.begin_accept(listener), Err(-11));
        bindings.release(listener, &mut backend);
        assert_eq!(backend.closed, [41, 40]);
    }
}
