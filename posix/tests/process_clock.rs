use mochios_posix_client::{Client, ClientError, Transport, process_clock};
use mochios_posix_protocol::{self as wire, process_clock::Sample};
use posix_service::{
    AuthenticatedProcess, PeerIdentity, PosixService, ProcessBackend, ProcessLifecycle,
};
use std::cell::RefCell;

struct Backend {
    state: Result<ProcessLifecycle, i32>,
    usage: Result<mnu_abi::ProcessExecutionUsage, i32>,
    seen: Vec<u32>,
}
impl Default for Backend {
    fn default() -> Self {
        Self {
            state: Ok(ProcessLifecycle::Running),
            usage: Ok(mnu_abi::ProcessExecutionUsage {
                user_ticks: 1001,
                kernel_ticks: 2,
                ticks_per_second: 500,
                reserved: 0,
            }),
            seen: Vec::new(),
        }
    }
}
impl ProcessBackend<u32> for Backend {
    fn status(&mut self, h: u32) -> Result<ProcessLifecycle, i32> {
        self.seen.push(h);
        self.state
    }
    fn execution_usage(&mut self, h: u32) -> Result<mnu_abi::ProcessExecutionUsage, i32> {
        self.seen.push(h);
        self.usage
    }
    fn suspend(&mut self, _: u32) -> Result<(), i32> {
        panic!("no mutation authority")
    }
    fn terminate(&mut self, _: u32, _: u64) -> Result<(), i32> {
        panic!("no mutation authority")
    }
    fn release(&mut self, _: u32) {
        panic!("borrowed service owner")
    }
}
fn setup() -> (PosixService, PeerIdentity) {
    let mut service = PosixService::new();
    service
        .initialize_bootstrap_process(
            AuthenticatedProcess {
                process_id: 1,
                handle: 101,
            },
            0,
            0,
            &[],
        )
        .unwrap();
    let root = service.registered_peer(1).unwrap();
    for (pid, uid) in [(2, 501), (3, 501), (4, 502)] {
        service
            .initialize_process(
                root,
                AuthenticatedProcess {
                    process_id: pid,
                    handle: 100 + pid as u32,
                },
                uid,
                20,
                &[],
            )
            .unwrap();
    }
    let peer = service.registered_peer(2).unwrap();
    (service, peer)
}
fn header() -> wire::Header {
    wire::Header {
        opcode: wire::OP_PROCESS_CPU_CLOCK,
        request_id: 7,
        ..Default::default()
    }
}
fn observe(
    service: &PosixService,
    peer: PeerIdentity,
    pid: u64,
    backend: &mut Backend,
) -> Result<Sample, i32> {
    let response = service.handle_process_clock(peer, header(), &pid.to_le_bytes(), &[], backend);
    assert!(response.handles.is_empty());
    if response.response.header.status != 0 {
        return Err(response.response.header.status);
    }
    Ok(wire::process_clock::decode(&response.response.payload).unwrap())
}

#[test]
fn credentials_are_stored_and_native_reads_use_only_registered_object_owners() {
    let (service, peer) = setup();
    let mut backend = Backend::default();
    assert_eq!(
        observe(&service, peer, 0, &mut backend).unwrap().process_id,
        2
    );
    assert_eq!(backend.seen, [102, 102]);
    backend.seen.clear();
    assert_eq!(
        observe(&service, peer, 3, &mut backend).unwrap().user_ticks,
        1001
    );
    assert_eq!(backend.seen, [103, 103]);
    backend.seen.clear();
    let forged_root = PeerIdentity {
        effective_uid: 0,
        ..peer
    };
    assert_eq!(
        observe(&service, forged_root, 4, &mut backend),
        Err(wire::STATUS_EPERM)
    );
    assert_eq!(
        observe(&service, peer, 999, &mut backend),
        Err(wire::STATUS_ESRCH)
    );
    assert_eq!(
        observe(
            &service,
            PeerIdentity {
                process_id: 999,
                ..peer
            },
            2,
            &mut backend
        ),
        Err(wire::STATUS_ESRCH)
    );
    assert!(backend.seen.is_empty());
    assert_eq!(
        observe(
            &service,
            service.registered_peer(1).unwrap(),
            4,
            &mut backend
        )
        .unwrap()
        .process_id,
        4
    );
}

#[test]
fn exit_and_native_failures_are_not_replaced_with_zero_cpu_time() {
    let (service, peer) = setup();
    let mut backend = Backend::default();
    backend.state = Ok(ProcessLifecycle::Exited { exit_code: 0 });
    assert_eq!(
        observe(&service, peer, 3, &mut backend),
        Err(wire::STATUS_ESRCH)
    );
    assert_eq!(backend.seen, [103]);
    backend.state = Err(-13);
    assert_eq!(observe(&service, peer, 3, &mut backend), Err(-13));
    backend.state = Ok(ProcessLifecycle::Running);
    backend.usage = Err(-12);
    assert_eq!(observe(&service, peer, 3, &mut backend), Err(-12));
    for (rate, reserved) in [(0, 0), (500, 1)] {
        backend.usage = Ok(mnu_abi::ProcessExecutionUsage {
            ticks_per_second: rate,
            reserved,
            ..Default::default()
        });
        assert_eq!(
            observe(&service, peer, 3, &mut backend),
            Err(wire::STATUS_EIO)
        );
    }
}

#[test]
fn malformed_requests_and_object_attachments_never_reach_accounting() {
    let (service, peer) = setup();
    let mut backend = Backend::default();
    for payload in [
        vec![],
        vec![0; 7],
        vec![0; 9],
        u64::MAX.to_le_bytes().to_vec(),
    ] {
        assert_eq!(
            service
                .handle_process_clock(peer, header(), &payload, &[], &mut backend)
                .response
                .header
                .status,
            -22
        );
    }
    for bad in [
        wire::Header {
            flags: 1,
            ..header()
        },
        wire::Header {
            status: 1,
            ..header()
        },
    ] {
        assert_eq!(
            service
                .handle_process_clock(peer, bad, &3u64.to_le_bytes(), &[], &mut backend)
                .response
                .header
                .status,
            -22
        );
    }
    assert_eq!(
        service
            .handle_process_clock(
                peer,
                header(),
                &3u64.to_le_bytes(),
                &[posix_service::AttachedObject {
                    handle: 900,
                    rights: u64::MAX
                }],
                &mut backend
            )
            .response
            .header
            .status,
        -22
    );
    assert!(backend.seen.is_empty());
}

struct Link {
    service: PosixService,
    peer: PeerIdentity,
    backend: RefCell<Backend>,
    wrong_pid: bool,
}
impl Transport for Link {
    type Error = ();
    fn call(&self, input: &[u8], output: &mut [u8]) -> Result<usize, ()> {
        let (header, payload) = wire::decode(input).unwrap();
        let mut response = self
            .service
            .handle_process_clock(
                self.peer,
                header,
                payload,
                &[],
                &mut *self.backend.borrow_mut(),
            )
            .response;
        if self.wrong_pid && response.header.status == 0 {
            response.payload[..8].copy_from_slice(&99u64.to_le_bytes());
        }
        wire::encode(response.header, &response.payload, output).map_err(|_| ())
    }
}
#[test]
fn client_and_service_exchange_explicit_cpu_samples_and_reject_wrong_targets() {
    let (service, peer) = setup();
    let client = Client::new(Link {
        service,
        peer,
        backend: RefCell::new(Backend::default()),
        wrong_pid: false,
    });
    assert_eq!(client.process_cpu_clock(3).unwrap().process_id, 3);
    assert_eq!(
        client.process_cpu_clock(4),
        Err(ClientError::Remote(wire::STATUS_EPERM))
    );
    let (service, peer) = setup();
    let client = Client::new(Link {
        service,
        peer,
        backend: RefCell::new(Backend::default()),
        wrong_pid: true,
    });
    assert_eq!(
        client.process_cpu_clock(3),
        Err(ClientError::MismatchedResponse)
    );
}

#[test]
fn wire_and_clock_id_boundaries_and_tick_conversion_are_checked() {
    for pid in [1, 2, i32::MAX as u64] {
        let id = process_clock::clock_id(pid).unwrap();
        assert_eq!(process_clock::target(id), Some(pid));
        assert!(id < mochios_posix_client::thread_clock::FIRST_ID);
    }
    for id in [0, 2, process_clock::FIRST_ID, 1 << 32, u64::MAX] {
        assert_eq!(process_clock::target(id), None);
    }
    assert_eq!(process_clock::clock_id(0), None);
    assert_eq!(process_clock::clock_id(1 << 31), None);
    let sample = Sample {
        process_id: 3,
        user_ticks: 1001,
        kernel_ticks: 2,
        ticks_per_second: 500,
    };
    assert_eq!(process_clock::timespec(sample), Ok((2, 6_000_000)));
    assert_eq!(
        process_clock::timespec(Sample {
            user_ticks: u64::MAX,
            kernel_ticks: u64::MAX,
            ticks_per_second: 1,
            ..sample
        }),
        Err(mochios_posix_client::newlib_errno::EOVERFLOW)
    );
    let mut bytes = [0; wire::process_clock::SAMPLE_LEN];
    wire::process_clock::encode(sample, &mut bytes).unwrap();
    assert_eq!(wire::process_clock::decode(&bytes), Ok(sample));
    for length in 0..bytes.len() {
        assert!(wire::process_clock::decode(&bytes[..length]).is_err());
    }
    assert!(wire::process_clock::decode(&[bytes.as_slice(), &[0]].concat()).is_err());
    bytes[24..].fill(0);
    assert!(wire::process_clock::decode(&bytes).is_err());
}
