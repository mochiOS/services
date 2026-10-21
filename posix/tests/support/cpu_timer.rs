use super::*;
use protocol::interval_timer::{self, CpuClock, Value};

fn sample(user: u64, kernel: u64) -> mnu_abi::ProcessExecutionUsage {
    mnu_abi::ProcessExecutionUsage {
        user_ticks: user,
        kernel_ticks: kernel,
        ticks_per_second: 1_000,
        reserved: 0,
    }
}

thread_local! { static WALL: std::cell::Cell<u64> = const { std::cell::Cell::new(0) }; }
fn wall() -> Result<u64, i32> {
    Ok(WALL.get())
}

#[test]
fn elapsed_time_can_expire_without_consuming_either_cpu_timer() {
    let (service, _, _, owner, _, mut processes) = orphan_family();
    let mut service = service.with_monotonic_clock(wall);
    WALL.set(0);
    processes.usage.insert(142, Ok(sample(0, 0)));
    let timer = Value {
        interval_ns: 0,
        remaining_ns: 10_000_000,
    };
    for clock in [CpuClock::Virtual, CpuClock::Profile] {
        request_timer(&mut service, &mut processes, owner, clock, Some(timer)).unwrap();
    }
    assert_eq!(
        service
            .handle(
                owner,
                protocol::Header {
                    opcode: protocol::OP_ALARM,
                    ..Default::default()
                },
                &1u32.to_le_bytes()
            )
            .header
            .status,
        0
    );
    WALL.set(5_000_000_000);
    assert_eq!(service.expire_alarms(), Ok(1));
    service.expire_cpu_timers(&mut processes).unwrap();
    for clock in [CpuClock::Virtual, CpuClock::Profile] {
        assert_eq!(
            request_timer(&mut service, &mut processes, owner, clock, None),
            Ok(timer)
        );
    }
    assert_eq!(
        service.signal_state(owner.process_id).unwrap().pending(),
        1 << (protocol::SIGNAL_ALRM - 1)
    );
}

#[test]
fn disarmed_cpu_timer_configuration_is_owned_until_root_process_exit() {
    let owner = PeerIdentity {
        process_id: 700,
        effective_uid: 0,
        effective_gid: 0,
    };
    let mut service = PosixService::new();
    service
        .initialize_bootstrap_process(
            AuthenticatedProcess {
                handle: 70,
                process_id: 700,
            },
            0,
            0,
            &[],
        )
        .unwrap();
    let mut processes = RecordingProcesses::default();
    processes.states.insert(70, ProcessLifecycle::Running);
    assert!(!service.child_lifecycle_handles().contains(&70));
    request_timer(
        &mut service,
        &mut processes,
        owner,
        CpuClock::Virtual,
        Some(Value {
            interval_ns: 10,
            remaining_ns: 0,
        }),
    )
    .unwrap();
    assert!(!service.has_cpu_timers());
    assert!(service.child_lifecycle_handles().contains(&70));
    processes
        .states
        .insert(70, ProcessLifecycle::Exited { exit_code: 0 });
    service
        .refresh_child_exit_notifications(&mut processes)
        .unwrap();
    assert!(!service.child_lifecycle_handles().contains(&70));
    assert_eq!(
        request_timer(&mut service, &mut processes, owner, CpuClock::Virtual, None),
        Err(protocol::STATUS_ESRCH)
    );
}
fn request_timer(
    service: &mut PosixService,
    processes: &mut RecordingProcesses,
    peer: PeerIdentity,
    clock: CpuClock,
    replacement: Option<Value>,
) -> Result<Value, i32> {
    let mut payload = (clock as u32).to_le_bytes().to_vec();
    if let Some(value) = replacement {
        let mut encoded = [0; interval_timer::LEN];
        interval_timer::encode(value, &mut encoded).unwrap();
        payload.extend_from_slice(&encoded);
    }
    let reply = service.handle_cpu_timer_request(
        peer,
        protocol::Header {
            opcode: if replacement.is_some() {
                protocol::OP_CPU_TIMER_SET
            } else {
                protocol::OP_CPU_TIMER_GET
            },
            ..Default::default()
        },
        &payload,
        &[],
        processes,
    );
    assert!(reply.handles.is_empty());
    if reply.response.header.status != 0 {
        return Err(reply.response.header.status);
    }
    Ok(interval_timer::decode(&reply.response.payload).unwrap())
}

#[test]
fn cpu_timer_domains_count_process_cpu_not_wall_time_and_coalesce_periods() {
    let (mut service, _, _, owner, _, mut processes) = orphan_family();
    processes.usage.insert(142, Ok(sample(10, 20)));
    let timer = Value {
        interval_ns: 10_000_000,
        remaining_ns: 10_000_000,
    };
    for clock in [CpuClock::Virtual, CpuClock::Profile] {
        assert_eq!(
            request_timer(&mut service, &mut processes, owner, clock, Some(timer)),
            Ok(Value::default())
        );
    }
    assert!(service.has_cpu_timers());
    // Advancing kernel execution alone expires PROF but leaves VIRTUAL armed.
    processes.usage.insert(142, Ok(sample(10, 30)));
    assert_eq!(service.expire_cpu_timers(&mut processes), Ok(1));
    assert_eq!(
        service.signal_state(owner.process_id).unwrap().pending(),
        1 << (protocol::SIGNAL_PROF - 1)
    );
    assert_eq!(
        request_timer(&mut service, &mut processes, owner, CpuClock::Virtual, None),
        Ok(timer)
    );
    // Without additional execution no timer counts down, irrespective of polls.
    assert_eq!(service.expire_cpu_timers(&mut processes), Ok(1));
    assert_eq!(
        request_timer(&mut service, &mut processes, owner, CpuClock::Virtual, None),
        Ok(timer)
    );
    processes.usage.insert(142, Ok(sample(45, 30)));
    assert_eq!(service.expire_cpu_timers(&mut processes), Ok(1));
    assert_eq!(
        request_timer(&mut service, &mut processes, owner, CpuClock::Virtual, None)
            .unwrap()
            .remaining_ns,
        5_000_000
    );
    assert_eq!(
        request_timer(&mut service, &mut processes, owner, CpuClock::Profile, None)
            .unwrap()
            .remaining_ns,
        5_000_000
    );
    let pending = service.signal_state(owner.process_id).unwrap().pending();
    assert_eq!(
        pending,
        (1 << (protocol::SIGNAL_VTALRM - 1)) | (1 << (protocol::SIGNAL_PROF - 1))
    );
}

#[test]
fn invalid_cpu_samples_preserve_timer_and_do_not_block_other_owners() {
    let (mut service, _, parent, child, _, mut processes) = orphan_family();
    let timer = Value {
        interval_ns: 0,
        remaining_ns: 1_000_000,
    };
    processes.usage.insert(141, Ok(sample(10, 10)));
    processes.usage.insert(142, Ok(sample(10, 10)));
    for owner in [parent, child] {
        request_timer(
            &mut service,
            &mut processes,
            owner,
            CpuClock::Virtual,
            Some(timer),
        )
        .unwrap();
    }
    for invalid in [
        Err(protocol::STATUS_EIO),
        Ok(mnu_abi::ProcessExecutionUsage {
            reserved: 1,
            ..sample(11, 10)
        }),
        Ok(mnu_abi::ProcessExecutionUsage {
            ticks_per_second: 0,
            ..sample(11, 10)
        }),
        Ok(mnu_abi::ProcessExecutionUsage {
            ticks_per_second: 2_000,
            ..sample(11, 10)
        }),
        Ok(sample(9, 10)),
        Ok(sample(10, 9)),
    ] {
        processes.usage.insert(141, invalid);
        assert_eq!(
            request_timer(
                &mut service,
                &mut processes,
                parent,
                CpuClock::Virtual,
                Some(Value::default())
            ),
            Err(protocol::STATUS_EIO)
        );
        processes.usage.insert(142, Ok(sample(11, 10)));
        assert_eq!(
            service.expire_cpu_timers(&mut processes),
            Err(protocol::STATUS_EIO)
        );
        assert_eq!(
            service.signal_state(parent.process_id).unwrap().pending(),
            0
        );
        assert_eq!(
            service.signal_state(child.process_id).unwrap().pending(),
            1 << (protocol::SIGNAL_VTALRM - 1)
        );
    }
    processes.usage.insert(141, Ok(sample(10, 10)));
    assert_eq!(
        request_timer(
            &mut service,
            &mut processes,
            parent,
            CpuClock::Virtual,
            None
        ),
        Ok(timer)
    );
    processes.usage.insert(141, Ok(sample(11, 10)));
    service.expire_cpu_timers(&mut processes).unwrap();
    assert!(!service.has_cpu_timers());
}

#[test]
fn cpu_timer_uses_wide_totals_and_retains_interval_on_disarm() {
    let (mut service, _, _, owner, _, mut processes) = orphan_family();
    processes.usage.insert(
        142,
        Ok(mnu_abi::ProcessExecutionUsage {
            user_ticks: u64::MAX - 2,
            kernel_ticks: u64::MAX - 2,
            ticks_per_second: 1,
            reserved: 0,
        }),
    );
    let timer = Value {
        interval_ns: 10,
        remaining_ns: 1_000_000_000,
    };
    request_timer(
        &mut service,
        &mut processes,
        owner,
        CpuClock::Profile,
        Some(timer),
    )
    .unwrap();
    assert_eq!(
        request_timer(&mut service, &mut processes, owner, CpuClock::Profile, None),
        Ok(timer)
    );
    processes.usage.insert(
        142,
        Ok(mnu_abi::ProcessExecutionUsage {
            user_ticks: u64::MAX - 1,
            kernel_ticks: u64::MAX - 2,
            ticks_per_second: 1,
            reserved: 0,
        }),
    );
    service.expire_cpu_timers(&mut processes).unwrap();
    assert_eq!(
        request_timer(&mut service, &mut processes, owner, CpuClock::Profile, None)
            .unwrap()
            .remaining_ns,
        10
    );
    let disabled = Value {
        interval_ns: 10,
        remaining_ns: 0,
    };
    request_timer(
        &mut service,
        &mut processes,
        owner,
        CpuClock::Profile,
        Some(disabled),
    )
    .unwrap();
    assert!(!service.has_cpu_timers());
    assert_eq!(
        request_timer(&mut service, &mut processes, owner, CpuClock::Profile, None),
        Ok(disabled)
    );
}

#[test]
fn cpu_timer_is_not_forked_survives_image_start_and_is_reclaimed_on_exit() {
    let (mut service, _, parent, child, mut filesystem, mut processes) = orphan_family();
    let timer = Value {
        interval_ns: 50_000_000,
        remaining_ns: 10_000_000,
    };
    processes.usage.insert(141, Ok(sample(0, 0)));
    request_timer(
        &mut service,
        &mut processes,
        parent,
        CpuClock::Virtual,
        Some(timer),
    )
    .unwrap();
    assert_eq!(
        request_timer(&mut service, &mut processes, child, CpuClock::Virtual, None),
        Ok(Value::default())
    );
    let forked = PeerIdentity {
        process_id: 1500,
        ..parent
    };
    service
        .adopt_child(
            parent,
            AuthenticatedProcess {
                handle: 150,
                process_id: 1500,
            },
            &mut filesystem,
        )
        .unwrap();
    processes.states.insert(150, ProcessLifecycle::Running);
    assert_eq!(
        request_timer(
            &mut service,
            &mut processes,
            forked,
            CpuClock::Virtual,
            None
        ),
        Ok(Value::default())
    );
    assert_eq!(
        thread_signal_request(&mut service, parent, protocol::OP_SIGNAL_IMAGE_STARTED, &[])
            .header
            .status,
        0
    );
    assert_eq!(
        request_timer(
            &mut service,
            &mut processes,
            parent,
            CpuClock::Virtual,
            None
        ),
        Ok(timer)
    );
    processes
        .states
        .insert(141, ProcessLifecycle::Exited { exit_code: 0 });
    service
        .refresh_child_exit_notifications(&mut processes)
        .unwrap();
    assert!(!service.has_cpu_timers());
    assert_eq!(
        request_timer(
            &mut service,
            &mut processes,
            parent,
            CpuClock::Virtual,
            None
        ),
        Err(protocol::STATUS_ESRCH)
    );
}

#[test]
fn cpu_timer_request_validation_rejects_identity_and_authority_injection() {
    let (mut service, _, _, owner, _, mut processes) = orphan_family();
    for (opcode, flags, payload, handles) in [
        (protocol::OP_CPU_TIMER_GET, 1, vec![1, 0, 0, 0], vec![]),
        (protocol::OP_CPU_TIMER_GET, 0, vec![], vec![]),
        (protocol::OP_CPU_TIMER_GET, 0, vec![0; 4], vec![]),
        (protocol::OP_CPU_TIMER_GET, 0, vec![3, 0, 0, 0], vec![]),
        (protocol::OP_CPU_TIMER_GET, 0, vec![1, 0, 0, 0, 0], vec![]),
        (protocol::OP_CPU_TIMER_SET, 0, vec![1, 0, 0, 0], vec![]),
        (protocol::OP_CPU_TIMER_SET, 0, vec![1; 21], vec![]),
        (
            protocol::OP_CPU_TIMER_GET,
            0,
            vec![1, 0, 0, 0],
            vec![AttachedObject {
                handle: 999,
                rights: u64::MAX,
            }],
        ),
    ] {
        let response = service.handle_cpu_timer_request(
            owner,
            protocol::Header {
                opcode,
                flags,
                ..Default::default()
            },
            &payload,
            &handles,
            &mut processes,
        );
        assert_eq!(response.response.header.status, STATUS_EINVAL);
        assert!(response.handles.is_empty());
        assert!(!service.has_cpu_timers());
    }
    assert_eq!(
        request_timer(
            &mut service,
            &mut processes,
            PeerIdentity {
                process_id: 9999,
                ..owner
            },
            CpuClock::Virtual,
            None
        ),
        Err(protocol::STATUS_ESRCH)
    );
}

struct CpuTransport {
    peer: PeerIdentity,
    service: RefCell<PosixService>,
    processes: RefCell<RecordingProcesses>,
}
impl Transport for CpuTransport {
    type Error = ();
    fn call(&self, input: &[u8], output: &mut [u8]) -> Result<usize, ()> {
        let (header, payload) = protocol::decode(input).map_err(|_| ())?;
        let response = self.service.borrow_mut().handle_cpu_timer_request(
            self.peer,
            header,
            payload,
            &[],
            &mut *self.processes.borrow_mut(),
        );
        protocol::encode(response.response.header, &response.response.payload, output)
            .map_err(|_| ())
    }
}

#[test]
fn cpu_timer_client_roundtrips_both_domains() {
    let (service, _, _, peer, _, processes) = orphan_family();
    let client = Client::new(CpuTransport {
        peer,
        service: RefCell::new(service),
        processes: RefCell::new(processes),
    });
    for clock in [CpuClock::Virtual, CpuClock::Profile] {
        let value = Value {
            interval_ns: 123,
            remaining_ns: 456,
        };
        assert_eq!(
            client.set_cpu_timer(clock, value).unwrap(),
            Value::default()
        );
        assert_eq!(client.cpu_timer(clock).unwrap(), value);
    }
}
