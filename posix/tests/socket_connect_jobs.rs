use mochios_filesystem_protocol as fs;
use mochios_posix_protocol::socket::{Create, Domain, Kind};
use posix_service::{
    AuthenticatedProcess, OpenedObject, PeerIdentity, PosixService,
    socket::Streams,
    socket_binding::{Bindings, Filesystem, NODE_RIGHTS},
    socket_connect::{Connections, Started},
};

#[derive(Default)]
struct Backend {
    next: u32,
    inode: u64,
    lookups: usize,
    closed: Vec<u32>,
}

impl Backend {
    fn opened(&mut self) -> (OpenedObject<u32>, fs::NodeStatus) {
        self.next += 1;
        (
            OpenedObject {
                handle: self.next,
                rights: NODE_RIGHTS,
            },
            fs::NodeStatus {
                node_id: self.inode,
                kind: fs::NODE_TYPE_SOCKET,
                link_count: 1,
                ..Default::default()
            },
        )
    }
}

impl Filesystem<u32> for Backend {
    fn create_socket(&mut self, _: &[u8]) -> Result<(OpenedObject<u32>, fs::NodeStatus), i32> {
        Ok(self.opened())
    }
    fn open_socket(&mut self, _: &[u8]) -> Result<(OpenedObject<u32>, fs::NodeStatus), i32> {
        self.lookups += 1;
        Ok(self.opened())
    }
    fn close(&mut self, handle: u32) {
        assert!(!self.closed.contains(&handle), "double close");
        self.closed.push(handle);
    }
}

struct Fixture {
    policy: PosixService<u32>,
    streams: Streams,
    bindings: Bindings<u32>,
    backend: Backend,
    jobs: Connections<u32>,
}

impl Fixture {
    fn new() -> Self {
        let mut policy = PosixService::new();
        policy
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
        Self {
            policy,
            streams: Streams::new(),
            bindings: Bindings::new(),
            backend: Backend {
                inode: 10,
                ..Default::default()
            },
            jobs: Connections::new(),
        }
    }
    fn socket(&mut self) -> u64 {
        self.policy
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
                &mut self.streams,
            )
            .unwrap()
    }
    fn listener(&mut self) -> u64 {
        let socket = self.socket();
        self.bindings
            .bind_path(&self.streams, socket, b"/server", &mut self.backend)
            .unwrap();
        self.streams.listen(socket, 1).unwrap();
        socket
    }
    fn start(&mut self, client: u64, nonblocking: bool) -> Result<Started, i32> {
        self.jobs.start(
            &mut self.streams,
            &self.bindings,
            client,
            b"/server",
            nonblocking,
            &mut self.backend,
        )
    }
    fn accept(&mut self, listener: u64) -> u64 {
        let ticket = self.streams.begin_accept(listener).unwrap();
        self.streams.commit_accept(ticket, (501, 20), 0).unwrap()
    }
    fn pump(&mut self) -> Vec<(u64, u64, Result<(u64, u64), i32>)> {
        let mut completed = Vec::new();
        self.jobs.pump(
            &mut self.streams,
            &self.bindings,
            |handle| self.backend.close(handle),
            |id, client, result| completed.push((id, client, result)),
        );
        completed
    }
    fn release(&mut self, job: u64) {
        self.jobs
            .release(job, |handle| self.backend.close(handle))
            .unwrap();
    }
}

fn waiting(started: Started) -> u64 {
    match started {
        Started::Waiting { job } => job,
        _ => panic!("expected backlog wait"),
    }
}

#[test]
fn fifo_waits_allow_accept_and_release_each_lookup_once() {
    let mut f = Fixture::new();
    let listener = f.listener();
    let clients = [f.socket(), f.socket(), f.socket()];
    assert!(matches!(
        f.start(clients[0], false),
        Ok(Started::Connected { .. })
    ));
    let first = waiting(f.start(clients[1], false).unwrap());
    let second = waiting(f.start(clients[2], false).unwrap());
    assert_eq!(f.jobs.status(first), Ok(None));
    assert!(f.jobs.is_pending(clients[1]));
    assert!(f.pump().is_empty());
    assert_eq!(f.backend.closed, [2]);
    f.accept(listener);
    let completed = f.pump();
    assert_eq!(completed.len(), 1);
    assert_eq!((completed[0].0, completed[0].1), (first, clients[1]));
    let (matched, accepted) = completed[0].2.unwrap();
    assert_eq!(matched, listener);
    assert!(!f.jobs.is_pending(clients[1]));
    assert_eq!(f.jobs.status(first), Ok(Some(Ok((listener, accepted)))));
    assert_eq!(
        provider_query(&mut f, first, mnu_abi::IPC_DELIVERY_NATIVE_OBJECT, 0),
        0
    );
    assert_eq!(
        provider_query(&mut f, first, mnu_abi::IPC_DELIVERY_NATIVE_OBJECT, 0),
        0
    );
    assert_eq!(f.jobs.status(second), Ok(None));
    f.release(first);
    assert_eq!(f.streams.write(clients[1], b"live"), Ok(4));
    assert_eq!(f.streams.read(accepted, &mut [0; 4]), Ok(4));
    assert_eq!(f.accept(listener), accepted);
    let completed = f.pump();
    assert_eq!(completed.len(), 1);
    assert_eq!(completed[0].0, second);
    assert!(f.pump().is_empty());
    f.release(second);
    assert_eq!(f.backend.lookups, 3);
    assert_eq!(f.backend.closed, [2, 3, 4]);
}

#[test]
fn duplicate_waits_do_not_lookup_and_cancelled_ids_cannot_cancel_a_retry() {
    let mut f = Fixture::new();
    let listener = f.listener();
    let first = f.socket();
    let client = f.socket();
    f.start(first, false).unwrap();
    let cancelled = waiting(f.start(client, false).unwrap());
    assert_eq!(f.start(client, false), Err(-114));
    assert_eq!(f.backend.lookups, 2);
    f.release(cancelled);
    assert!(!f.jobs.is_pending(client));
    assert_eq!(f.streams.write(client, b"x"), Err(-107));
    let retry = waiting(f.start(client, false).unwrap());
    assert_ne!(retry, cancelled);
    assert_eq!(
        f.jobs.release(cancelled, |_| panic!("stale close")),
        Err(-9)
    );
    assert!(f.jobs.is_pending(client));
    f.accept(listener);
    assert_eq!(f.pump()[0].0, retry);
    f.release(retry);
    assert_eq!(f.backend.closed, [2, 3, 4]);
}

#[test]
fn nonblocking_full_queue_does_not_publish_a_job_or_connect_later() {
    let mut f = Fixture::new();
    let listener = f.listener();
    let first = f.socket();
    let client = f.socket();
    f.start(first, false).unwrap();
    assert_eq!(f.start(client, true), Err(-11));
    assert!(!f.jobs.is_pending(client));
    f.accept(listener);
    assert!(f.pump().is_empty());
    assert_eq!(f.streams.write(client, b"x"), Err(-107));
    assert_eq!(f.backend.closed, [2, 3]);
}

#[test]
fn listener_or_client_retirement_completes_with_an_error_and_no_lease_leak() {
    for listener_closed in [false, true] {
        let mut f = Fixture::new();
        let listener = f.listener();
        let first = f.socket();
        let client = f.socket();
        f.start(first, false).unwrap();
        let job = waiting(f.start(client, false).unwrap());
        let expected = if listener_closed {
            f.bindings.release(listener, &mut f.backend);
            f.streams.release(listener).unwrap();
            -111
        } else {
            f.streams.release(client).unwrap();
            -9
        };
        assert_eq!(f.pump(), [(job, client, Err(expected))]);
        assert_eq!(f.jobs.status(job), Ok(Some(Err(expected))));
        assert!(f.pump().is_empty());
        f.release(job);
        assert!(f.backend.closed.contains(&3));
    }
}

#[test]
fn full_listener_does_not_stall_another_listener_and_backlog_growth_wakes_waiters() {
    let mut f = Fixture::new();
    let a = f.listener();
    let first_a = f.socket();
    let wait_a = f.socket();
    f.start(first_a, false).unwrap();
    let job_a = waiting(f.start(wait_a, false).unwrap());
    f.backend.inode = 11;
    let b = f.listener();
    let first_b = f.socket();
    let wait_b = f.socket();
    f.start(first_b, false).unwrap();
    let job_b = waiting(f.start(wait_b, false).unwrap());
    f.accept(b);
    let completed = f.pump();
    assert_eq!(completed.len(), 1);
    assert_eq!(completed[0].0, job_b);
    assert_eq!(f.jobs.status(job_a), Ok(None));
    f.streams.listen(a, 2).unwrap();
    assert_eq!(f.pump()[0].0, job_a);
    f.release(job_a);
    f.release(job_b);
}

#[test]
fn completed_jobs_are_bounded_and_releasing_one_recovers_capacity() {
    let mut f = Fixture::new();
    let listener = f.listener();
    let first = f.socket();
    f.start(first, false).unwrap();
    let mut retired = Vec::new();
    for _ in 0..posix_service::socket::MAX_ENDPOINTS {
        let client = f.socket();
        let job = waiting(f.start(client, false).unwrap());
        f.streams.release(client).unwrap();
        assert_eq!(f.pump(), [(job, client, Err(-9))]);
        retired.push(job);
    }
    let client = f.socket();
    let before = f.backend.closed.len();
    assert_eq!(f.start(client, false), Err(-23));
    assert_eq!(f.backend.closed.len(), before + 1);
    assert!(!f.jobs.is_pending(client));
    f.release(retired.remove(0));
    let retry = waiting(f.start(client, false).unwrap());
    f.accept(listener);
    assert_eq!(f.pump()[0].0, retry);
    f.release(retry);
    for job in retired {
        f.release(job);
    }
    assert_eq!(f.jobs.status(retry), Err(-9));
}

fn provider_query(f: &mut Fixture, job: u64, flags: u32, count: u32) -> i64 {
    use mnu_abi::provider;
    let mut request = [0; provider::REQUEST_HEADER_LEN];
    provider::RequestHeader {
        opcode: provider::OP_CONTROL,
        object_id: posix_service::socket_connect::object_id(job).unwrap(),
        argument: 0,
        data_length: 0,
        length: 0,
        basis: mochios_posix_protocol::socket::CONTROL_CONNECT_RESULT,
    }
    .encode(&[], &mut request)
    .unwrap();
    let mut response = [0; provider::RESPONSE_HEADER_LEN];
    let length = f
        .jobs
        .handle_provider_request(&request, flags, count, &mut response, |_| {
            panic!("query released target")
        })
        .unwrap()
        .unwrap();
    let (header, data) = provider::ResponseHeader::decode(&response[..length]).unwrap();
    assert_eq!(header.value, 0);
    assert!(data.is_empty());
    header.status
}

#[test]
fn job_provider_queries_require_native_authority_and_preserve_completed_errors() {
    let mut f = Fixture::new();
    let listener = f.listener();
    let first = f.socket();
    let client = f.socket();
    f.start(first, false).unwrap();
    let job = waiting(f.start(client, false).unwrap());
    assert_eq!(provider_query(&mut f, job, 0, 0), -13);
    assert_eq!(
        provider_query(&mut f, job, mnu_abi::IPC_DELIVERY_ENDPOINT_HANDLE, 0),
        -13
    );
    assert_eq!(
        provider_query(&mut f, job, mnu_abi::IPC_DELIVERY_NATIVE_OBJECT, 1),
        -22
    );
    assert_eq!(
        provider_query(&mut f, job, mnu_abi::IPC_DELIVERY_NATIVE_OBJECT, 0),
        -11
    );
    assert!(f.jobs.is_pending(client));
    f.bindings.release(listener, &mut f.backend);
    f.streams.release(listener).unwrap();
    f.pump();
    for _ in 0..2 {
        assert_eq!(
            provider_query(&mut f, job, mnu_abi::IPC_DELIVERY_NATIVE_OBJECT, 0),
            -111
        );
    }
    f.release(job);
    assert_eq!(
        provider_query(&mut f, job, mnu_abi::IPC_DELIVERY_NATIVE_OBJECT, 0),
        -9
    );
}

#[test]
fn only_native_final_release_cancels_a_job_and_late_release_is_harmless() {
    use mnu_abi::provider;
    let mut f = Fixture::new();
    let listener = f.listener();
    let first = f.socket();
    let client = f.socket();
    f.start(first, false).unwrap();
    let job = waiting(f.start(client, false).unwrap());
    let mut request = [0; provider::REQUEST_HEADER_LEN];
    provider::RequestHeader {
        opcode: provider::OP_RELEASE,
        object_id: posix_service::socket_connect::object_id(job).unwrap(),
        argument: 0,
        data_length: 0,
        length: 0,
        basis: 0,
    }
    .encode(&[], &mut request)
    .unwrap();
    let mut response = [0; provider::RESPONSE_HEADER_LEN];
    let result = f
        .jobs
        .handle_provider_request(&request, 0, 0, &mut response, |_| panic!("forged release"));
    assert!(result.unwrap().is_some());
    assert!(f.jobs.is_pending(client));
    assert_eq!(
        f.jobs.handle_provider_request(
            &request,
            mnu_abi::IPC_DELIVERY_NATIVE_OBJECT,
            0,
            &mut [],
            |handle| f.backend.close(handle)
        ),
        Ok(None)
    );
    assert!(!f.jobs.is_pending(client));
    assert_eq!(
        f.jobs.handle_provider_request(
            &request,
            mnu_abi::IPC_DELIVERY_NATIVE_OBJECT,
            0,
            &mut [],
            |_| panic!("double release")
        ),
        Err(-9)
    );
    f.accept(listener);
    assert!(f.pump().is_empty());
    assert_eq!(f.streams.write(client, b"x"), Err(-107));
    assert_eq!(f.backend.closed, [2, 3]);
}

#[test]
fn provider_identity_namespaces_do_not_overlap_or_exceed_native_range() {
    use posix_service::{
        socket::MAX_DESCRIPTION_ID,
        socket_connect::{job_id, object_id},
    };
    for job in [1, MAX_DESCRIPTION_ID] {
        let object = object_id(job).unwrap();
        assert!(object > MAX_DESCRIPTION_ID && object <= i64::MAX as u64);
        assert_eq!(job_id(object), Ok(job));
        assert_eq!(job_id(job), Err(-9));
    }
    assert_eq!(object_id(0), Err(-9));
    assert_eq!(object_id(MAX_DESCRIPTION_ID + 1), Err(-9));
    assert_eq!(job_id(1 << 62), Err(-9));
    assert_eq!(job_id(u64::MAX), Err(-9));
}
