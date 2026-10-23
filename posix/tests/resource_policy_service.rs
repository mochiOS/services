use mochios_posix_protocol as wire;
use posix_service::resource_policy::{Factory, Published};
use posix_service::{
    AttachedObject, AuthenticatedProcess, OpenedObject, PeerIdentity, PosixService, ProcessBackend,
    ProcessLifecycle,
};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicI32, AtomicUsize, Ordering},
};
use wire::resource_policy::{READER_RIGHTS, ResourcePolicy};

#[derive(Default)]
struct State {
    pages: Mutex<Vec<Arc<ResourcePolicy>>>,
    creates: AtomicUsize,
    drops: AtomicUsize,
    publishes: AtomicUsize,
    create_error: AtomicI32,
    delegate_error: AtomicI32,
    publish_error: AtomicI32,
}
struct Backend(Arc<State>);
struct Page {
    policy: Arc<ResourcePolicy>,
    state: Arc<State>,
}
impl std::fmt::Debug for Page {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TestPage")
    }
}
impl Drop for Page {
    fn drop(&mut self) {
        self.state.drops.fetch_add(1, Ordering::SeqCst);
    }
}
impl Published<u32> for Page {
    fn publish_record_locks(&self, held: bool) {
        self.policy.publish_record_locks(held);
    }
    fn publish(&self, resource: u32, limit: wire::ResourceLimit) -> Result<(), i32> {
        self.state.publishes.fetch_add(1, Ordering::SeqCst);
        match self.state.publish_error.load(Ordering::SeqCst) {
            0 => self.policy.publish(resource, limit).map_err(|_| -5),
            error => Err(error),
        }
    }
    fn delegate(&self) -> Result<OpenedObject<u32>, i32> {
        match self.state.delegate_error.load(Ordering::SeqCst) {
            0 => Ok(OpenedObject {
                handle: 900,
                rights: READER_RIGHTS,
            }),
            error => Err(error),
        }
    }
}
impl Factory<u32> for Backend {
    fn create(
        &mut self,
        limits: [wire::ResourceLimit; wire::RLIMIT_COUNT as usize],
    ) -> Result<Box<dyn Published<u32>>, i32> {
        self.0.creates.fetch_add(1, Ordering::SeqCst);
        let error = self.0.create_error.load(Ordering::SeqCst);
        if error != 0 {
            return Err(error);
        }
        let policy = Arc::new(ResourcePolicy::new(limits).unwrap());
        self.0.pages.lock().unwrap().push(Arc::clone(&policy));
        Ok(Box::new(Page {
            policy,
            state: Arc::clone(&self.0),
        }))
    }
}
fn peer(process_id: u64) -> PeerIdentity {
    PeerIdentity {
        process_id,
        effective_uid: 0,
        effective_gid: 0,
    }
}
fn service() -> PosixService {
    let mut service = PosixService::new();
    service
        .initialize_bootstrap_process(
            AuthenticatedProcess {
                process_id: 41,
                handle: 141,
            },
            0,
            0,
            &[],
        )
        .unwrap();
    service
}
fn request(
    service: &mut PosixService,
    backend: &mut Backend,
    owner: u64,
) -> posix_service::ObjectResponse<u32> {
    service.handle_resource_policy(
        peer(owner),
        wire::Header {
            opcode: wire::OP_RESOURCE_POLICY,
            request_id: 71,
            ..Default::default()
        },
        &[],
        &[],
        backend,
    )
}
fn limit(
    service: &mut PosixService,
    caller: u64,
    target: i64,
    resource: u32,
    replacement: Option<wire::ResourceLimit>,
) -> posix_service::Response {
    let mut payload = [0; wire::RESOURCE_LIMIT_REQUEST_LEN];
    wire::encode_resource_limit_request(
        wire::ResourceLimitRequest {
            process_id: target,
            resource,
            flags: if replacement.is_some() {
                wire::RESOURCE_LIMIT_SET
            } else {
                0
            },
            limit: replacement.unwrap_or_default(),
        },
        &mut payload,
    )
    .unwrap();
    service.handle(
        peer(caller),
        wire::Header {
            opcode: wire::OP_RESOURCE_LIMIT,
            ..Default::default()
        },
        &payload,
    )
}

#[test]
fn pages_start_from_authoritative_limits_and_updates_or_failures_stay_coherent() {
    let mut service = service();
    let state = Arc::new(State::default());
    let mut backend = Backend(Arc::clone(&state));
    let value = wire::ResourceLimit { soft: 7, hard: 17 };
    assert_eq!(
        limit(&mut service, 41, 0, wire::RLIMIT_NOFILE, Some(value))
            .header
            .status,
        0
    );
    let reply = request(&mut service, &mut backend, 41);
    assert_eq!(
        (
            reply.response.header.status,
            reply.response.header.request_id
        ),
        (0, 71)
    );
    assert!(reply.response.payload.is_empty());
    assert_eq!(
        reply.handles,
        [OpenedObject {
            handle: 900,
            rights: READER_RIGHTS
        }]
    );
    let policy = Arc::clone(&state.pages.lock().unwrap()[0]);
    assert_eq!(policy.read(wire::RLIMIT_NOFILE), Ok(value));
    assert_eq!(
        policy.read(wire::RLIMIT_AS),
        Ok(wire::ResourceLimit::INFINITY)
    );
    assert_eq!(
        request(&mut service, &mut backend, 41)
            .response
            .header
            .status,
        0
    );
    assert_eq!(state.creates.load(Ordering::SeqCst), 1);
    let changed = wire::ResourceLimit { soft: 9, hard: 19 };
    assert_eq!(
        limit(&mut service, 41, 0, wire::RLIMIT_NOFILE, Some(changed))
            .header
            .status,
        0
    );
    assert_eq!(policy.read(wire::RLIMIT_NOFILE), Ok(changed));
    state.publish_error.store(-11, Ordering::SeqCst);
    for resource in [wire::RLIMIT_NOFILE, wire::RLIMIT_CPU] {
        assert_eq!(
            limit(&mut service, 41, 0, resource, Some(value))
                .header
                .status,
            -11
        );
    }
    state.publish_error.store(0, Ordering::SeqCst);
    for (resource, expected) in [
        (wire::RLIMIT_NOFILE, changed),
        (wire::RLIMIT_CPU, wire::ResourceLimit::INFINITY),
    ] {
        let response = limit(&mut service, 41, 0, resource, None);
        assert_eq!(wire::decode_resource_limit(&response.payload), Ok(expected));
        assert_eq!(policy.read(resource), Ok(expected));
    }
}

#[test]
fn identity_and_credentials_are_not_supplied_by_the_request_or_peer_claims() {
    let mut service = service();
    service
        .initialize_process(
            peer(41),
            AuthenticatedProcess {
                process_id: 42,
                handle: 142,
            },
            505,
            24,
            &[],
        )
        .unwrap();
    let state = Arc::new(State::default());
    let mut backend = Backend(Arc::clone(&state));
    assert_eq!(
        request(&mut service, &mut backend, 43)
            .response
            .header
            .status,
        wire::STATUS_ESRCH
    );
    request(&mut service, &mut backend, 41);
    request(&mut service, &mut backend, 42);
    let pages = state.pages.lock().unwrap();
    let parent = Arc::clone(&pages[0]);
    let other = Arc::clone(&pages[1]);
    drop(pages);
    let value = wire::ResourceLimit { soft: 3, hard: 13 };
    assert_eq!(
        limit(&mut service, 42, 0, wire::RLIMIT_NOFILE, Some(value))
            .header
            .status,
        0
    );
    assert_eq!(other.read(wire::RLIMIT_NOFILE), Ok(value));
    assert_eq!(
        parent.read(wire::RLIMIT_NOFILE),
        Ok(wire::ResourceLimit::INFINITY)
    );
    let publishes = state.publishes.load(Ordering::SeqCst);
    assert_eq!(
        limit(&mut service, 42, 41, wire::RLIMIT_NOFILE, Some(value))
            .header
            .status,
        wire::STATUS_EPERM
    );
    assert_eq!(
        limit(
            &mut service,
            42,
            0,
            wire::RLIMIT_NOFILE,
            Some(wire::ResourceLimit { soft: 3, hard: 14 })
        )
        .header
        .status,
        wire::STATUS_EPERM
    );
    assert_eq!(state.publishes.load(Ordering::SeqCst), publishes);
    let header = wire::Header {
        opcode: wire::OP_RESOURCE_POLICY,
        ..Default::default()
    };
    for (header, payload, objects) in [
        (header, &41u64.to_le_bytes()[..], vec![]),
        (wire::Header { flags: 1, ..header }, &[][..], vec![]),
        (
            wire::Header {
                status: 1,
                ..header
            },
            &[][..],
            vec![],
        ),
        (
            header,
            &[][..],
            vec![AttachedObject {
                handle: 900,
                rights: READER_RIGHTS,
            }],
        ),
    ] {
        assert_eq!(
            service
                .handle_resource_policy(peer(42), header, payload, &objects, &mut backend)
                .response
                .header
                .status,
            -22
        );
    }
    assert_eq!(state.creates.load(Ordering::SeqCst), 2);
}

#[test]
fn allocation_or_first_delegation_failure_leaves_no_cached_publisher() {
    let mut service = service();
    let state = Arc::new(State::default());
    let mut backend = Backend(Arc::clone(&state));
    state.create_error.store(-12, Ordering::SeqCst);
    assert_eq!(
        request(&mut service, &mut backend, 41)
            .response
            .header
            .status,
        -12
    );
    state.create_error.store(0, Ordering::SeqCst);
    state.delegate_error.store(-5, Ordering::SeqCst);
    assert_eq!(
        request(&mut service, &mut backend, 41)
            .response
            .header
            .status,
        -5
    );
    assert_eq!(state.drops.load(Ordering::SeqCst), 1);
    state.delegate_error.store(0, Ordering::SeqCst);
    assert_eq!(
        request(&mut service, &mut backend, 41)
            .response
            .header
            .status,
        0
    );
    assert_eq!(state.creates.load(Ordering::SeqCst), 3);
    state.delegate_error.store(-5, Ordering::SeqCst);
    assert_eq!(
        request(&mut service, &mut backend, 41)
            .response
            .header
            .status,
        -5
    );
    assert_eq!(
        state.drops.load(Ordering::SeqCst),
        1,
        "existing readers must retain the same publisher"
    );
}

struct Processes(Result<ProcessLifecycle, i32>);
struct CpuProcesses;
impl ProcessBackend<u32> for CpuProcesses {
    fn status(&mut self, _: u32) -> Result<ProcessLifecycle, i32> {
        Ok(ProcessLifecycle::Running)
    }
    fn execution_usage(&mut self, _: u32) -> Result<mnu_abi::ProcessExecutionUsage, i32> {
        Ok(mnu_abi::ProcessExecutionUsage {
            user_ticks: 600,
            kernel_ticks: 0,
            ticks_per_second: 500,
            reserved: 0,
        })
    }
    fn suspend(&mut self, _: u32) -> Result<(), i32> {
        panic!("soft budget must not suspend")
    }
    fn terminate(&mut self, _: u32, _: u64) -> Result<(), i32> {
        panic!("hard budget not exceeded")
    }
    fn release(&mut self, _: u32) {
        panic!("live process must remain owned")
    }
}

#[test]
fn failed_cpu_policy_publication_preserves_the_soft_notification_interval() {
    let mut service = service();
    let state = Arc::new(State::default());
    let mut backend = Backend(Arc::clone(&state));
    request(&mut service, &mut backend, 41);
    let budget = wire::ResourceLimit { soft: 1, hard: 5 };
    assert_eq!(
        limit(&mut service, 41, 0, wire::RLIMIT_CPU, Some(budget))
            .header
            .status,
        0
    );
    assert_eq!(service.enforce_cpu_limits(&mut CpuProcesses), Ok(1));
    state.publish_error.store(-11, Ordering::SeqCst);
    assert_eq!(
        limit(&mut service, 41, 0, wire::RLIMIT_CPU, Some(budget))
            .header
            .status,
        -11
    );
    assert_eq!(service.enforce_cpu_limits(&mut CpuProcesses), Ok(0));
    state.publish_error.store(0, Ordering::SeqCst);
    assert_eq!(
        limit(&mut service, 41, 0, wire::RLIMIT_CPU, Some(budget))
            .header
            .status,
        0
    );
    assert_eq!(service.enforce_cpu_limits(&mut CpuProcesses), Ok(1));
}

impl ProcessBackend<u32> for Processes {
    fn status(&mut self, _: u32) -> Result<ProcessLifecycle, i32> {
        self.0
    }
    fn execution_usage(&mut self, _: u32) -> Result<mnu_abi::ProcessExecutionUsage, i32> {
        panic!()
    }
    fn suspend(&mut self, _: u32) -> Result<(), i32> {
        panic!()
    }
    fn terminate(&mut self, _: u32, _: u64) -> Result<(), i32> {
        panic!()
    }
    fn release(&mut self, _: u32) {
        panic!()
    }
}

#[test]
fn even_root_publishers_are_dropped_only_after_confirmed_native_exit() {
    let mut service = service();
    let state = Arc::new(State::default());
    let mut backend = Backend(Arc::clone(&state));
    request(&mut service, &mut backend, 41);
    assert!(service.child_lifecycle_handles().contains(&141));
    assert_eq!(
        service.refresh_child_exit_notifications(&mut Processes(Err(-5))),
        Err(-5)
    );
    assert_eq!(state.drops.load(Ordering::SeqCst), 0);
    assert_eq!(
        service.refresh_child_exit_notifications(&mut Processes(Ok(ProcessLifecycle::Running))),
        Ok(0)
    );
    assert_eq!(state.drops.load(Ordering::SeqCst), 0);
    assert_eq!(
        service.refresh_child_exit_notifications(&mut Processes(Ok(ProcessLifecycle::Exited {
            exit_code: 0
        }))),
        Ok(0)
    );
    assert_eq!(state.drops.load(Ordering::SeqCst), 1);
    assert!(!service.child_lifecycle_handles().contains(&141));
    assert_eq!(
        request(&mut service, &mut backend, 41)
            .response
            .header
            .status,
        wire::STATUS_ESRCH
    );
}

#[test]
fn lock_publication_tracks_lazy_discovery_conflicts_partial_unlock_and_exit() {
    use posix_service::record_lock::{FileKey, Kind, Range};
    let mut service = service();
    service
        .initialize_process(
            peer(41),
            AuthenticatedProcess {
                process_id: 42,
                handle: 142,
            },
            0,
            0,
            &[],
        )
        .unwrap();
    let state = Arc::new(State::default());
    let mut backend = Backend(Arc::clone(&state));
    let file = FileKey {
        device: 7,
        inode: 11,
    };
    let range = Range::normalize(0, 10, 20).unwrap();
    // A direct client can lock before libc discovers its shared page.
    service
        .record_locks(peer(41))
        .unwrap()
        .set(file, Kind::Write, range)
        .unwrap();
    assert_eq!(
        request(&mut service, &mut backend, 41)
            .response
            .header
            .status,
        0
    );
    assert_eq!(
        request(&mut service, &mut backend, 42)
            .response
            .header
            .status,
        0
    );
    let pages = state.pages.lock().unwrap();
    let parent = Arc::clone(&pages[0]);
    let child = Arc::clone(&pages[1]);
    drop(pages);
    assert_eq!(parent.read_record_locks(), Ok(true));
    assert_eq!(child.read_record_locks(), Ok(false));
    assert!(
        service
            .record_locks(peer(42))
            .unwrap()
            .set(file, Kind::Write, range)
            .is_err()
    );
    assert_eq!(child.read_record_locks(), Ok(false));
    service
        .record_locks(peer(41))
        .unwrap()
        .unlock(file, Range::normalize(0, 10, 5).unwrap())
        .unwrap();
    assert_eq!(parent.read_record_locks(), Ok(true));
    service.record_locks(peer(41)).unwrap().release_file(file);
    assert_eq!(parent.read_record_locks(), Ok(false));
    service
        .record_locks(peer(42))
        .unwrap()
        .set(file, Kind::Read, range)
        .unwrap();
    assert_eq!(parent.read_record_locks(), Ok(false));
    assert_eq!(child.read_record_locks(), Ok(true));
    service
        .refresh_child_exit_notifications(&mut Processes(Ok(ProcessLifecycle::Exited {
            exit_code: 0,
        })))
        .unwrap();
    assert_eq!(parent.read_record_locks(), Ok(false));
    assert_eq!(child.read_record_locks(), Ok(false));
}
