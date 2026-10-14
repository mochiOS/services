use mochios_filesystem_protocol as fs;
use mochios_posix_protocol::{
    socket::{Address, Create, Domain, Kind},
    socket_record::{Operation, Request, MAX_REPLY_LEN},
    socket_route as wire,
};
use posix_service::{
    socket::Streams,
    socket_binding::{Bindings, Filesystem, NODE_RIGHTS},
    socket_record_io::RecordBuffer,
    socket_route::{job_id, object_id, Routes},
    AuthenticatedProcess, OpenedObject, PeerIdentity, PosixService,
};

struct Backend {
    node: u64,
    next: u32,
    closed: Vec<u32>,
    lookups: usize,
}
impl Filesystem<u32> for Backend {
    fn create_socket(&mut self, _: &[u8]) -> Result<(OpenedObject<u32>, fs::NodeStatus), i32> {
        self.open_socket(b"")
    }
    fn open_socket(&mut self, _: &[u8]) -> Result<(OpenedObject<u32>, fs::NodeStatus), i32> {
        self.lookups += 1;
        let handle = self.next;
        self.next += 1;
        Ok((
            OpenedObject {
                handle,
                rights: NODE_RIGHTS,
            },
            fs::NodeStatus {
                node_id: self.node,
                kind: fs::NODE_TYPE_SOCKET,
                link_count: 1,
                ..Default::default()
            },
        ))
    }
    fn close(&mut self, handle: u32) {
        self.closed.push(handle);
    }
}
struct Buffer(Vec<u8>, bool);
impl RecordBuffer for Buffer {
    fn extent(&self) -> Result<u64, i32> {
        Ok(self.0.len() as u64)
    }
    fn read(&mut self, offset: u64, output: &mut [u8]) -> Result<(), i32> {
        if self.1 {
            return Err(-5);
        }
        output.copy_from_slice(&self.0[offset as usize..offset as usize + output.len()]);
        Ok(())
    }
    fn write(&mut self, offset: u64, input: &[u8]) -> Result<(), i32> {
        self.0[offset as usize..offset as usize + input.len()].copy_from_slice(input);
        Ok(())
    }
}
fn fixture() -> (Streams, [u64; 2], Bindings<u32>, Backend) {
    let mut service = PosixService::new();
    service
        .initialize_bootstrap_process(
            AuthenticatedProcess {
                handle: 1u32,
                process_id: 1,
            },
            501,
            20,
            &[],
        )
        .unwrap();
    let peer = PeerIdentity {
        process_id: 1,
        effective_uid: 501,
        effective_gid: 20,
    };
    let create = Create {
        domain: Domain::Unix,
        kind: Kind::Datagram,
        protocol: 0,
        options: 0,
    };
    let mut streams = Streams::new();
    let client = service.create_socket(peer, create, &mut streams).unwrap();
    let server = service.create_socket(peer, create, &mut streams).unwrap();
    let mut bindings = Bindings::new();
    let mut backend = Backend {
        node: 10,
        next: 40,
        closed: vec![],
        lookups: 0,
    };
    bindings
        .bind_path(&streams, server, b"/server", &mut backend)
        .unwrap();
    (streams, [client, server], bindings, backend)
}
fn request(length: u32) -> Request {
    Request {
        operation: Operation::SendRoute,
        offset: 0,
        length,
        peek: false,
    }
}

#[test]
fn route_codec_and_private_namespaces_reject_malformed_or_mixed_authority() {
    let mut bytes = [0x55; wire::MAX_REQUEST_LEN];
    for length in [0, 1, 65536] {
        let count = wire::encode(length, Address::UnixPath(b"/server"), &mut bytes).unwrap();
        assert_eq!(
            wire::decode(&bytes[..count]),
            Ok((length, Address::UnixPath(b"/server")))
        );
        for size in 0..count {
            assert!(wire::decode(&bytes[..size]).is_err());
        }
        for index in [0, 4, 6, 12] {
            let mut bad = bytes;
            bad[index] ^= 0x80;
            assert!(wire::decode(&bad[..count]).is_err());
        }
    }
    assert!(wire::encode(65537, Address::UnixPath(b"/server"), &mut bytes).is_err());
    assert!(wire::encode(0, Address::UnixAbstract(b"name"), &mut bytes).is_err());
    assert_eq!(job_id(object_id(1).unwrap()), Ok(1));
    for id in [
        0,
        1,
        (1 << 61) | 1,
        (1 << 62) | 1,
        (1 << 60) | (1 << 61) | 1,
    ] {
        assert_eq!(job_id(id), Err(-9));
    }
}

#[test]
fn route_is_single_use_binds_size_preserves_peer_and_closes_both_leases() {
    let (mut streams, [client, server], bindings, mut backend) = fixture();
    let target = bindings
        .prepare_datagram_target(&streams, client, b"/alias", &mut backend)
        .unwrap();
    let mut routes = Routes::new();
    let id = routes.start(&streams, target, 3, 777).ok().unwrap();
    let mut buffer = Buffer(b"abc".to_vec(), true);
    let mut response = [0; MAX_REPLY_LEN];
    assert_eq!(
        routes.transfer(&mut streams, id, request(2), &mut buffer, &mut response),
        Err(-22)
    );
    assert_eq!(
        routes.transfer(&mut streams, id, request(3), &mut buffer, &mut response),
        Err(-5)
    );
    buffer.1 = false;
    routes
        .transfer(&mut streams, id, request(3), &mut buffer, &mut response)
        .unwrap();
    assert_eq!(streams.peer_address(client), Err(-107));
    assert_eq!(
        routes.transfer(&mut streams, id, request(3), &mut buffer, &mut response),
        Err(-114)
    );
    let receive = Request {
        operation: Operation::Receive,
        ..request(3)
    };
    streams
        .transfer_record(server, receive, &mut buffer, &mut response)
        .unwrap();
    assert_eq!(buffer.0, b"abc");
    assert_eq!(
        streams.transfer_record(server, receive, &mut buffer, &mut response),
        Err(-11)
    );
    let mut closed = vec![];
    routes
        .release(
            id,
            |handle| closed.push(handle),
            |handle| backend.close(handle),
        )
        .unwrap();
    assert_eq!(closed, [777]);
    assert_eq!(backend.closed, [41]);
    assert_eq!(backend.lookups, 2); // one bind and one authorization, no retries
}

#[test]
fn waiting_route_never_reopens_path_and_retired_target_is_not_replaced() {
    let (mut streams, [client, server], mut bindings, mut backend) = fixture();
    let mut routes = Routes::new();
    let mut buffer = Buffer(vec![1; 65536], false);
    let mut response = [0; MAX_REPLY_LEN];
    let target = bindings
        .prepare_datagram_target(&streams, client, b"/server", &mut backend)
        .unwrap();
    let first = routes.start(&streams, target, 65536, 800).ok().unwrap();
    routes
        .transfer(
            &mut streams,
            first,
            request(65536),
            &mut buffer,
            &mut response,
        )
        .unwrap();
    routes
        .release(first, |_| (), |handle| backend.close(handle))
        .unwrap();
    let target = bindings
        .prepare_datagram_target(&streams, client, b"/server", &mut backend)
        .unwrap();
    let pending = routes.start(&streams, target, 30000, 801).ok().unwrap();
    routes.pump(&streams, |id, ready| {
        assert_eq!(id, pending);
        assert!(!ready);
    });
    assert_eq!(
        routes.transfer(
            &mut streams,
            pending,
            request(30000),
            &mut buffer,
            &mut response
        ),
        Err(-11)
    );
    let calls = backend.lookups;
    backend.node = 99; // namespace now resolves elsewhere, never consulted again
    bindings.release(server, &mut backend);
    streams.release(server).unwrap();
    routes.pump(&streams, |id, ready| {
        assert_eq!(id, pending);
        assert!(ready);
    });
    assert_eq!(
        routes.transfer(
            &mut streams,
            pending,
            request(30000),
            &mut buffer,
            &mut response
        ),
        Err(-111)
    );
    assert_eq!(backend.lookups, calls);
    routes
        .release(pending, |_| (), |handle| backend.close(handle))
        .unwrap();
    assert_eq!(backend.closed, [41, 40, 42]);
}

#[test]
fn cancellation_reclaims_route_quota_without_sending_and_retains_monotonic_ids() {
    let (streams, [client, _], bindings, mut backend) = fixture();
    let mut routes = Routes::new();
    let mut last = 0;
    let mut sources = 0;
    for _ in 0..1100 {
        let target = bindings
            .prepare_datagram_target(&streams, client, b"/server", &mut backend)
            .unwrap();
        let id = routes.start(&streams, target, 0, 777).ok().unwrap();
        assert!(id > last);
        last = id;
        routes
            .release(id, |_| sources += 1, |handle| backend.close(handle))
            .unwrap();
    }
    assert_eq!((sources, backend.closed.len()), (1100, 1100));
    assert_eq!(streams.peer_address(client), Err(-107));
}
