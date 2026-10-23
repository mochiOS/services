use super::*;

fn create_as(
    service: &mut PosixService,
    processes: &mut RecordingProcesses,
    peer: PeerIdentity,
    sender: Option<mnu_abi::ExecutionIdentity>,
) -> Result<u64, i32> {
    service.refresh_image_state(peer, processes)?;
    let image = service.capture_request_image(peer)?;
    let mut input = [0; wire::CREATE_LEN];
    wire::encode_create(
        Clock::ThreadCpu,
        Notification::Signal {
            signal: 10,
            value: 71,
        },
        &mut input,
    )
    .unwrap();
    let mut created = None;
    let published = service.create_process_timer_with_reply(
        peer,
        image,
        sender,
        protocol::Header {
            opcode: protocol::OP_TIMER_CREATE,
            payload_len: wire::CREATE_LEN as u32,
            ..Default::default()
        },
        &input,
        &[],
        processes,
        |id| {
            created = Some(id);
            true
        },
    )?;
    assert!(published);
    Ok(created.unwrap())
}
fn identity(peer: PeerIdentity, thread_id: u64) -> mnu_abi::ExecutionIdentity {
    mnu_abi::ExecutionIdentity {
        process_id: peer.process_id,
        thread_id,
    }
}

#[test]
fn creation_binds_only_authenticated_registered_threads_and_rejects_no_identity() {
    let (client, environment) = setup();
    let peer = client.transport().peer;
    let mut environment = environment.borrow_mut();
    let Environment { service, processes } = &mut *environment;
    for sender in [
        None,
        Some(identity(peer, 0)),
        Some(mnu_abi::ExecutionIdentity {
            process_id: 99,
            thread_id: 17,
        }),
    ] {
        assert_eq!(
            create_as(service, processes, peer, sender),
            Err(protocol::STATUS_EPERM)
        );
    }
    assert_eq!(
        create_as(service, processes, peer, Some(identity(peer, 999))),
        Err(protocol::STATUS_ESRCH)
    );
    assert_eq!(
        service
            .process_timers(peer)
            .unwrap()
            .create(Clock::ThreadCpu, Notification::None),
        Err(STATUS_EINVAL)
    );
    assert!(service
        .process_timers(peer)
        .unwrap()
        .pending_notifications()
        .next()
        .is_none());
    assert!(create_as(service, processes, peer, Some(identity(peer, 17))).unwrap() > 0);
}

#[test]
fn thread_cpu_timers_ignore_process_cpu_and_cache_each_target_separately() {
    let (client, environment) = setup();
    let a = client
        .timer_create(Clock::ThreadCpu, Notification::Default)
        .unwrap();
    let b = client
        .timer_create(Clock::ThreadCpu, Notification::Default)
        .unwrap();
    let peer = client.transport().peer;
    let c = {
        let mut environment = environment.borrow_mut();
        let Environment { service, processes } = &mut *environment;
        create_as(service, processes, peer, Some(identity(peer, 18))).unwrap()
    };
    for id in [a, b, c] {
        client
            .timer_set(
                id,
                false,
                Value {
                    remaining_ns: 10,
                    interval_ns: 10,
                },
            )
            .unwrap();
    }
    CLOCKS.with(|state| {
        let mut state = state.borrow_mut();
        state.samples.process_cpu_ns = 1_000_000;
        state.samples.monotonic_ns = 1_000_000;
        state.thread_samples = vec![(2901, 17, 11), (2901, 18, 60)];
        state.thread_reads.clear();
        state.reads.clear();
    });
    {
        let mut environment = environment.borrow_mut();
        let Environment { service, processes } = &mut *environment;
        assert_eq!(service.observe_process_timers(processes), Ok(3));
        let events: Vec<_> = service
            .process_timers(peer)
            .unwrap()
            .pending_notifications()
            .collect();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].timer.raw(), c);
    }
    CLOCKS.with(|state| {
        let mut state = state.borrow_mut();
        assert!(state.reads.is_empty());
        assert_eq!(state.thread_reads, [(2901, 17), (2901, 18)]);
        state.thread_samples[0].2 = 32;
    });
    assert_eq!(
        client.timer_value(a).unwrap(),
        Value {
            remaining_ns: 10,
            interval_ns: 10
        }
    );
    assert_eq!(
        client.timer_value(b).unwrap(),
        Value {
            remaining_ns: 10,
            interval_ns: 10
        }
    );
    let mut environment = environment.borrow_mut();
    let events: Vec<_> = environment
        .service
        .process_timers(peer)
        .unwrap()
        .pending_notifications()
        .collect();
    assert_eq!(events.len(), 3);
    for event in events.iter().filter(|event| event.timer.raw() != c) {
        assert_eq!(event.overrun(), 2);
    }
}

#[test]
fn confirmed_thread_exit_retires_only_its_timers_and_image_replacement_retires_all() {
    let (client, environment) = setup();
    let a = client
        .timer_create(Clock::ThreadCpu, Notification::Default)
        .unwrap();
    let regular = client
        .timer_create(Clock::ProcessCpu, Notification::None)
        .unwrap();
    let peer = client.transport().peer;
    let mut state = environment.borrow_mut();
    let Environment { service, processes } = &mut *state;
    let b = create_as(service, processes, peer, Some(identity(peer, 18))).unwrap();
    let status = mnu_abi::ThreadStatus {
        process_id: peer.process_id,
        thread_id: 17,
        state: mnu_abi::THREAD_STATE_TERMINATED,
        reserved: 0,
    };
    assert_eq!(
        service.retire_signal_thread(identity(peer, 17), Err(protocol::STATUS_ESRCH)),
        Err(protocol::STATUS_ESRCH)
    );
    drop(state);
    assert!(client.timer_value(a).is_ok());
    assert!(environment
        .borrow_mut()
        .service
        .retire_signal_thread(identity(peer, 17), Ok(status))
        .unwrap());
    // Inspect through the actual scalar protocol so retired raw IDs remain opaque.
    assert!(matches!(
        client.timer_value(a),
        Err(mochios_posix_client::ClientError::Remote(STATUS_EINVAL))
    ));
    assert!(client.timer_value(b).is_ok());
    assert!(client.timer_value(regular).is_ok());
    CLOCKS.with(|state| state.borrow_mut().exec = true);
    assert!(client.timer_value(b).is_err());
    assert!(matches!(
        client.timer_value(regular),
        Err(mochios_posix_client::ClientError::Remote(STATUS_EINVAL))
    ));
}

#[test]
fn selected_signal_resamples_its_bound_thread_and_preserves_pending_on_failures() {
    let (client, environment) = setup();
    let id = client
        .timer_create(Clock::ThreadCpu, Notification::Default)
        .unwrap();
    client
        .timer_set(
            id,
            false,
            Value {
                remaining_ns: 10,
                interval_ns: 10,
            },
        )
        .unwrap();
    let peer = client.transport().peer;
    CLOCKS.with(|state| state.borrow_mut().thread_samples[0].2 = 12);
    let mut state = environment.borrow_mut();
    let Environment { service, processes } = &mut *state;
    assert_eq!(service.observe_process_timers(processes), Ok(1));
    let selected = service
        .process_timers(peer)
        .unwrap()
        .pending_notifications()
        .next()
        .unwrap();
    let image = service.capture_request_image(peer).unwrap();
    CLOCKS.with(|state| {
        let mut state = state.borrow_mut();
        state.thread_samples[0].2 = 52;
        state.samples.process_cpu_ns = u128::MAX;
    });
    assert_eq!(
        service
            .accept_timer_signal_with_reply(peer, image, selected, processes, |pending| {
                assert_eq!(pending.overrun(), 4);
                false
            })
            .unwrap(),
        None
    );
    CLOCKS.with(|state| state.borrow_mut().fail_clock = Some(Clock::ThreadCpu));
    assert_eq!(
        service.accept_timer_signal_with_reply(peer, image, selected, processes, |_| panic!(
            "unobserved clock cannot publish"
        )),
        Err(protocol::STATUS_EIO)
    );
    CLOCKS.with(|state| state.borrow_mut().fail_clock = None);
    assert_eq!(
        service
            .accept_timer_signal_with_reply(peer, image, selected, processes, |pending| {
                assert_eq!(pending.overrun(), 4);
                true
            })
            .unwrap()
            .unwrap()
            .overrun(),
        4
    );
    assert!(service
        .process_timers(peer)
        .unwrap()
        .pending_notifications()
        .next()
        .is_none());
    CLOCKS.with(|state| {
        let state = state.borrow();
        assert!(state.reads.is_empty());
        assert!(state
            .thread_reads
            .iter()
            .all(|&target| target == (2901, 17)));
    });
}

#[test]
fn unavailable_thread_clock_does_not_consume_its_timer_or_block_another_target() {
    let (client, environment) = setup();
    let a = client
        .timer_create(Clock::ThreadCpu, Notification::Default)
        .unwrap();
    let peer = client.transport().peer;
    let b = {
        let mut state = environment.borrow_mut();
        let Environment { service, processes } = &mut *state;
        create_as(service, processes, peer, Some(identity(peer, 18))).unwrap()
    };
    for id in [a, b] {
        client
            .timer_set(
                id,
                false,
                Value {
                    remaining_ns: 10,
                    interval_ns: 10,
                },
            )
            .unwrap();
    }
    CLOCKS.with(|state| state.borrow_mut().thread_samples = vec![(2901, 18, 90)]);
    let mut state = environment.borrow_mut();
    let Environment { service, processes } = &mut *state;
    assert_eq!(
        service.observe_process_timers(processes),
        Err(protocol::STATUS_ESRCH)
    );
    let pending: Vec<_> = service
        .process_timers(peer)
        .unwrap()
        .pending_notifications()
        .collect();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].timer.raw(), b);
    CLOCKS.with(|state| state.borrow_mut().thread_samples.push((2901, 17, 32)));
    assert_eq!(service.observe_process_timers(processes), Ok(2));
    let pending: Vec<_> = service
        .process_timers(peer)
        .unwrap()
        .pending_notifications()
        .collect();
    assert_eq!(pending.len(), 2);
    assert_eq!(
        pending
            .iter()
            .find(|event| event.timer.raw() == a)
            .unwrap()
            .overrun(),
        2
    );
}
