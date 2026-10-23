use super::*;

#[path = "cpu_sleep.rs"]
mod cpu_sleep;

fn setup() -> (Client<TimerTransport>, Rc<RefCell<Environment>>) {
    let (client, environment) = super::setup();
    let root = PeerIdentity {
        process_id: 1,
        effective_uid: 0,
        effective_gid: 0,
    };
    let mut service = service_for(root);
    service
        .initialize_process(
            root,
            AuthenticatedProcess {
                process_id: 2901,
                handle: 2901,
            },
            501,
            20,
            &[],
        )
        .unwrap();
    environment.borrow_mut().service = service;
    (client, environment)
}

fn subject(environment: &Rc<RefCell<Environment>>, pid: u64, uid: u32) -> PeerIdentity {
    let mut state = environment.borrow_mut();
    let authority = state.service.registered_peer(1).unwrap();
    state
        .service
        .initialize_process(
            authority,
            AuthenticatedProcess {
                process_id: pid,
                handle: pid as u32,
            },
            uid,
            20,
            &[],
        )
        .unwrap();
    state
        .processes
        .states
        .insert(2901, ProcessLifecycle::Running);
    state
        .processes
        .states
        .insert(pid as u32, ProcessLifecycle::Running);
    state.service.registered_peer(pid).unwrap()
}
fn arm(client: &Client<TimerTransport>, id: u64, remaining_ns: u128) {
    client
        .timer_set(
            id,
            false,
            Value {
                remaining_ns,
                interval_ns: 0,
            },
        )
        .unwrap();
}

#[test]
fn process_subject_is_independent_of_notification_owner_and_credential_self_report() {
    let (client, environment) = setup();
    let other = subject(&environment, 2902, 501);
    subject(&environment, 2903, 502);
    CLOCKS.with(|c| c.borrow_mut().process_samples = vec![(2901, 10000), (2902, 100)]);
    let id = client
        .timer_create_for_process(2902, Notification::None)
        .unwrap();
    arm(&client, id, 50);
    CLOCKS.with(|c| {
        let mut c = c.borrow_mut();
        c.process_samples = vec![(2901, 999999), (2902, 120)];
        c.reads.clear();
    });
    assert_eq!(client.timer_value(id).unwrap().remaining_ns, 30);
    CLOCKS.with(|c| assert_eq!(c.borrow().reads, [(2902, Clock::ProcessCpu)]));
    assert_eq!(
        client.timer_create_for_process(2903, Notification::None),
        Err(ClientError::Remote(protocol::STATUS_EPERM))
    );
    assert_eq!(
        client.timer_create_for_process(9999, Notification::None),
        Err(ClientError::Remote(protocol::STATUS_ESRCH))
    );
    let mut state = environment.borrow_mut();
    let Environment { service, processes } = &mut *state;
    let image = service.capture_request_image(other).unwrap();
    assert_eq!(
        service
            .handle_process_timer_request(
                other,
                image,
                protocol::Header {
                    opcode: protocol::OP_TIMER_GET,
                    payload_len: 8,
                    ..Default::default()
                },
                &id.to_le_bytes(),
                &[],
                processes
            )
            .response
            .header
            .status,
        STATUS_EINVAL
    );
    let owner = client.transport().peer;
    let mut payload = [0; wire::PROCESS_CREATE_LEN];
    wire::encode_process_create(2903, Notification::None, &mut payload).unwrap();
    let image = service.capture_request_image(owner).unwrap();
    assert_eq!(
        service.create_process_timer_with_reply(
            PeerIdentity {
                effective_uid: 0,
                ..owner
            },
            image,
            None,
            protocol::Header {
                opcode: protocol::OP_TIMER_CREATE_PROCESS_CPU,
                payload_len: payload.len() as u32,
                ..Default::default()
            },
            &payload,
            &[],
            processes,
            |_| panic!("forged root cannot publish")
        ),
        Err(protocol::STATUS_EPERM)
    );
}

#[test]
fn reactor_caches_each_subject_and_delivers_foreign_cpu_expirations_to_the_owner() {
    let (client, environment) = setup();
    subject(&environment, 2902, 501);
    subject(&environment, 2903, 501);
    CLOCKS.with(|c| c.borrow_mut().process_samples = vec![(2901, 1000), (2902, 100), (2903, 200)]);
    let a = client
        .timer_create_for_process(2902, Notification::Default)
        .unwrap();
    let b = client
        .timer_create_for_process(2902, Notification::Default)
        .unwrap();
    let own = client
        .timer_create(Clock::ProcessCpu, Notification::Default)
        .unwrap();
    let same_own = client
        .timer_create_for_process(2901, Notification::Default)
        .unwrap();
    let other = client
        .timer_create_for_process(2903, Notification::Default)
        .unwrap();
    for id in [a, b, own, same_own, other] {
        arm(&client, id, 10);
    }
    CLOCKS.with(|c| {
        let mut c = c.borrow_mut();
        c.process_samples = vec![(2901, 1001), (2902, 111), (2903, 201)];
        c.reads.clear();
    });
    let mut state = environment.borrow_mut();
    let Environment { service, processes } = &mut *state;
    assert_eq!(service.observe_process_timers(processes), Ok(5));
    CLOCKS.with(|c| {
        let mut reads = c.borrow().reads.clone();
        reads.sort_by_key(|&(pid, _)| pid);
        assert_eq!(
            reads,
            [
                (2901, Clock::ProcessCpu),
                (2902, Clock::ProcessCpu),
                (2903, Clock::ProcessCpu)
            ]
        );
    });
    let owner = client.transport().peer;
    let pending: Vec<_> = service
        .process_timers(owner)
        .unwrap()
        .pending_notifications()
        .collect();
    assert_eq!(
        pending.iter().map(|p| p.timer.raw()).collect::<Vec<_>>(),
        [a, b]
    );
    assert!(
        service
            .process_timers(service.registered_peer(2902).unwrap())
            .unwrap()
            .pending_notifications()
            .next()
            .is_none()
    );
    CLOCKS.with(|c| c.borrow_mut().reads.clear());
    let image = service.capture_request_image(owner).unwrap();
    assert!(
        service
            .accept_timer_signal_with_reply(owner, image, pending[0], processes, |_| true)
            .unwrap()
            .is_some()
    );
    CLOCKS.with(|c| assert_eq!(c.borrow().reads, [(2902, Clock::ProcessCpu)]));
}

#[test]
fn subject_exec_keeps_clock_but_exit_retires_foreign_timers_and_lifecycle_watches() {
    let (client, environment) = setup();
    let other = subject(&environment, 17, 501);
    let id = client
        .timer_create_for_process(17, Notification::Default)
        .unwrap();
    arm(&client, id, 10);
    let regular = client
        .timer_create(Clock::Monotonic, Notification::None)
        .unwrap();
    let owner = client.transport().peer;
    {
        let mut state = environment.borrow_mut();
        let Environment { service, processes } = &mut *state;
        // Numeric thread/process identity collision must not retire this clock.
        service
            .retire_signal_thread(
                mnu_abi::ExecutionIdentity {
                    process_id: owner.process_id,
                    thread_id: 17,
                },
                Ok(mnu_abi::ThreadStatus {
                    process_id: owner.process_id,
                    thread_id: 17,
                    state: mnu_abi::THREAD_STATE_TERMINATED,
                    reserved: 0,
                }),
            )
            .unwrap();
        processes.images.insert(
            17,
            Ok(mnu_abi::ProcessStatus {
                process_id: 17,
                state: mnu_abi::PROCESS_STATE_RUNNING,
                image_revision: 1,
                ..Default::default()
            }),
        );
        service.refresh_image_state(other, processes).unwrap();
        assert!(service.child_lifecycle_handles().contains(&17));
    }
    assert_eq!(client.timer_value(id).unwrap().remaining_ns, 10);
    {
        let mut state = environment.borrow_mut();
        let Environment { service, processes } = &mut *state;
        CLOCKS.with(|c| c.borrow_mut().samples.process_cpu_ns = 20);
        assert_eq!(service.observe_process_timers(processes), Ok(1));
        assert!(
            service
                .signal_notification_processes()
                .any(|pid| pid == owner.process_id)
        );
        processes
            .states
            .insert(17, ProcessLifecycle::Exited { exit_code: 0 });
        service.refresh_child_exit_notifications(processes).unwrap();
        assert!(!service.child_lifecycle_handles().contains(&17));
        assert!(
            !service
                .signal_notification_processes()
                .any(|pid| pid == owner.process_id)
        );
    }
    assert_eq!(
        client.timer_value(id),
        Err(ClientError::Remote(STATUS_EINVAL))
    );
    assert!(client.timer_value(regular).is_ok());
}

#[test]
fn revoked_subject_visibility_does_not_consume_its_timer_or_starve_independent_clocks() {
    let (client, environment) = setup();
    let other = subject(&environment, 2902, 0);
    {
        let mut state = environment.borrow_mut();
        let mut ids = [0; protocol::CREDENTIAL_PAIR_PAYLOAD_LEN];
        protocol::encode_credential_pair(501, 0, &mut ids).unwrap();
        assert_eq!(
            state
                .service
                .handle(
                    other,
                    protocol::Header {
                        opcode: protocol::OP_SET_REAL_EFFECTIVE_UID,
                        ..Default::default()
                    },
                    &ids
                )
                .header
                .status,
            0
        );
    }
    let remote = client
        .timer_create_for_process(2902, Notification::Default)
        .unwrap();
    let local = client
        .timer_create(Clock::ProcessCpu, Notification::Default)
        .unwrap();
    arm(&client, remote, 10);
    arm(&client, local, 10);
    {
        let mut state = environment.borrow_mut();
        assert_eq!(
            state
                .service
                .handle(
                    other,
                    protocol::Header {
                        opcode: protocol::OP_SET_UID,
                        ..Default::default()
                    },
                    &502u32.to_le_bytes()
                )
                .header
                .status,
            0
        );
        CLOCKS.with(|c| {
            let mut c = c.borrow_mut();
            c.samples.process_cpu_ns = 20;
            c.reads.clear();
        });
        let Environment { service, processes } = &mut *state;
        assert_eq!(
            service.observe_process_timers(processes),
            Err(protocol::STATUS_EPERM)
        );
        let pending: Vec<_> = service
            .process_timers(client.transport().peer)
            .unwrap()
            .pending_notifications()
            .map(|p| p.timer.raw())
            .collect();
        assert_eq!(pending, [local]);
        CLOCKS.with(|c| assert_eq!(c.borrow().reads, [(2901, Clock::ProcessCpu)]));
    }
    assert_eq!(
        client.timer_value(remote),
        Err(ClientError::Remote(protocol::STATUS_EPERM))
    );
    assert_eq!(client.timer_delete(remote), Ok(()));
}

#[test]
fn selected_process_creation_frames_reject_invalid_targets_and_unpublished_ids_are_retired() {
    let (client, environment) = setup();
    subject(&environment, 2902, 501);
    let mut payload = [0; wire::PROCESS_CREATE_LEN];
    wire::encode_process_create(2902, Notification::None, &mut payload).unwrap();
    assert_eq!(
        wire::decode_process_create(&payload),
        Ok((2902, Notification::None))
    );
    for len in 0..payload.len() {
        assert!(wire::decode_process_create(&payload[..len]).is_err());
    }
    assert!(wire::decode_process_create(&[payload.as_slice(), &[0]].concat()).is_err());
    for pid in [0, (i32::MAX as u64) + 1, u64::MAX] {
        assert!(wire::encode_process_create(pid, Notification::None, &mut payload).is_err());
    }
    let mut state = environment.borrow_mut();
    let Environment { service, processes } = &mut *state;
    let owner = client.transport().peer;
    let image = service.capture_request_image(owner).unwrap();
    let header = protocol::Header {
        opcode: protocol::OP_TIMER_CREATE_PROCESS_CPU,
        payload_len: payload.len() as u32,
        ..Default::default()
    };
    let mut retired = 0;
    assert_eq!(
        service.create_process_timer_with_reply(
            owner,
            image,
            None,
            header,
            &payload,
            &[],
            processes,
            |id| {
                retired = id;
                false
            }
        ),
        Ok(false)
    );
    assert_eq!(
        service
            .handle_process_timer_request(
                owner,
                image,
                protocol::Header {
                    opcode: protocol::OP_TIMER_GET,
                    payload_len: 8,
                    ..Default::default()
                },
                &retired.to_le_bytes(),
                &[],
                processes
            )
            .response
            .header
            .status,
        STATUS_EINVAL
    );
    assert_eq!(
        service.create_process_timer_with_reply(
            owner,
            image,
            None,
            header,
            &payload,
            &[AttachedObject {
                handle: 2902,
                rights: mnu_abi::HANDLE_RIGHT_WAIT
            }],
            processes,
            |_| panic!("unexpected attachment")
        ),
        Err(STATUS_EINVAL)
    );
}
