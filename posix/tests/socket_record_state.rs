use mochios_posix_protocol::{
    socket::{Create, Domain, Kind},
    socket_record::{Operation, Request, MAX_REPLY_LEN},
};
use posix_service::{
    socket::{Shutdown, Streams},
    socket_record_io::RecordBuffer,
    AuthenticatedProcess, PeerIdentity, PosixService,
};

struct Buffer(Vec<u8>);
impl RecordBuffer for Buffer {
    fn extent(&self) -> Result<u64, i32> {
        Ok(self.0.len() as u64)
    }
    fn read(&mut self, offset: u64, output: &mut [u8]) -> Result<(), i32> {
        output.copy_from_slice(&self.0[offset as usize..offset as usize + output.len()]);
        Ok(())
    }
    fn write(&mut self, offset: u64, input: &[u8]) -> Result<(), i32> {
        self.0[offset as usize..offset as usize + input.len()].copy_from_slice(input);
        Ok(())
    }
}

#[test]
fn datagram_descriptions_use_record_transport_and_preserve_peer_lifetime() {
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
        effective_uid: 0,
        effective_gid: 0,
    };
    let create = Create {
        domain: Domain::Unix,
        kind: Kind::Datagram,
        protocol: 0,
        options: 0,
    };
    let mut streams = Streams::new();
    let [a, b] = service
        .create_socket_pair(peer, create, &mut streams)
        .unwrap();
    assert_eq!(streams.kind(a), Ok(Kind::Datagram));
    assert_eq!(streams.write(a, b"bad"), Err(-95));
    assert_eq!(streams.read(b, &mut [0; 8]), Err(-95));
    assert_eq!(streams.peek(b, 0, &mut [0; 8]), Err(-95));
    assert_eq!(streams.listen(a, 1), Err(-95));
    let send = Request {
        operation: Operation::Send,
        offset: 0,
        length: 3,
        peek: false,
    };
    let receive = Request {
        operation: Operation::Receive,
        ..send
    };
    let mut buffer = Buffer(b"abc".to_vec());
    let mut response = [0; MAX_REPLY_LEN];
    streams
        .transfer_record(a, send, &mut buffer, &mut response)
        .unwrap();
    assert!(streams.readiness(b).unwrap().readable);
    // Release of the writer must not discard an already committed datagram.
    streams.release(a).unwrap();
    buffer.0.fill(0);
    streams
        .transfer_record(b, receive, &mut buffer, &mut response)
        .unwrap();
    assert_eq!(buffer.0, b"abc");
    assert_eq!(
        streams.transfer_record(b, receive, &mut buffer, &mut response),
        Err(-11)
    );
    assert!(!streams.readiness(b).unwrap().read_closed);
    assert_eq!(
        streams.transfer_record(b, send, &mut buffer, &mut response),
        Err(-111)
    );
    streams.release(b).unwrap();
    assert_eq!(streams.kind(b), Err(-9));
}

#[test]
fn shutdown_discards_only_its_own_queue_and_streams_reject_record_requests() {
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
        effective_uid: 0,
        effective_gid: 0,
    };
    let mut streams = Streams::new();
    let create = Create {
        domain: Domain::Unix,
        kind: Kind::Datagram,
        protocol: 0,
        options: 0,
    };
    let [a, b] = service
        .create_socket_pair(peer, create, &mut streams)
        .unwrap();
    let send = Request {
        operation: Operation::Send,
        offset: 0,
        length: 1,
        peek: false,
    };
    let receive = Request {
        operation: Operation::Receive,
        ..send
    };
    let mut buffer = Buffer(vec![1]);
    let mut response = [0; MAX_REPLY_LEN];
    streams
        .transfer_record(a, send, &mut buffer, &mut response)
        .unwrap();
    streams
        .transfer_record(b, send, &mut buffer, &mut response)
        .unwrap();
    streams.shutdown(b, Shutdown::Read).unwrap();
    assert!(streams.readiness(b).unwrap().read_closed);
    assert_eq!(
        streams.transfer_record(a, send, &mut buffer, &mut response),
        Err(-111)
    );
    streams
        .transfer_record(a, receive, &mut buffer, &mut response)
        .unwrap();
    let [stream, _] = service
        .create_socket_pair(
            peer,
            Create {
                kind: Kind::Stream,
                ..create
            },
            &mut streams,
        )
        .unwrap();
    assert_eq!(
        streams.transfer_record(stream, send, &mut buffer, &mut response),
        Err(-95)
    );
}

#[test]
fn atomic_send_wait_ignores_small_free_prefix_and_releases_its_write_lease() {
    use posix_service::socket_receive_wait::ReceiveWaits;
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
        effective_uid: 0,
        effective_gid: 0,
    };
    let mut streams = Streams::new();
    let [a, b] = service
        .create_socket_pair(
            peer,
            Create {
                domain: Domain::Unix,
                kind: Kind::Datagram,
                protocol: 0,
                options: 0,
            },
            &mut streams,
        )
        .unwrap();
    let mut buffer = Buffer(vec![0; 40000]);
    let mut response = [0; MAX_REPLY_LEN];
    let send = Request {
        operation: Operation::Send,
        offset: 0,
        length: 40000,
        peek: false,
    };
    streams
        .transfer_record(a, send, &mut buffer, &mut response)
        .unwrap();
    assert!(streams.readiness(a).unwrap().writable);
    assert_eq!(streams.record_send_ready(a, 30000), Ok(false));
    let mut waits = ReceiveWaits::new();
    let job = waits.start_send(&streams, a, 30000, 42).unwrap();
    waits.pump(&streams, |_| {
        panic!("ordinary POLLOUT must not wake a large record")
    });
    assert_eq!(waits.ready(job), Ok(false));
    streams
        .transfer_record(
            b,
            Request {
                operation: Operation::Receive,
                ..send
            },
            &mut buffer,
            &mut response,
        )
        .unwrap();
    waits.pump(&streams, |ready| assert_eq!(ready, job));
    assert_eq!(waits.ready(job), Ok(true));
    streams
        .transfer_record(a, send, &mut buffer, &mut response)
        .unwrap();
    assert_eq!(streams.record_send_ready(a, 30000), Ok(false));
    waits.pump(&streams, |ready| assert_eq!(ready, job));
    let mut closed = vec![];
    waits.release(job, |handle| closed.push(handle)).unwrap();
    assert_eq!(closed, [42]);
    // Repeated timed-out/cancelled jobs cannot accumulate registrations.
    for lease in 0..1100 {
        let job = waits.start_send(&streams, a, 30000, lease).unwrap();
        waits
            .release(job, |handle| assert_eq!(handle, lease))
            .unwrap();
    }
    assert_eq!(waits.start_send(&streams, a, usize::MAX, 0), Err(-90));
}
