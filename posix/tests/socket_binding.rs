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
    fn close(&mut self, handle: u32) {
        self.closed.push(handle);
    }
}
fn fixture() -> (Streams, [u64; 2], Bindings<u32>, Backend) {
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
