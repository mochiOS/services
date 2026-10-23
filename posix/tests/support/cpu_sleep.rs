use super::*;
use posix_service::cpu_sleep::{Completion, MAX_WAITS_PER_PROCESS, Registry};

#[derive(Default)]
struct ChannelState {
    closed: bool,
    busy: bool,
    failure: Option<i32>,
    attempts: usize,
    drops: usize,
    delivered: Vec<Result<(), i32>>,
}

struct Channel(Rc<RefCell<ChannelState>>);
impl Completion for Channel {
    fn peer_closed(&mut self) -> Result<bool, i32> {
        Ok(self.0.borrow().closed)
    }
    fn publish(&mut self, result: Result<(), i32>) -> Result<bool, i32> {
        let mut state = self.0.borrow_mut();
        state.attempts += 1;
        if let Some(error) = state.failure {
            return Err(error);
        }
        if state.busy {
            return Ok(false);
        }
        state.delivered.push(result);
        Ok(true)
    }
}
impl Drop for Channel {
    fn drop(&mut self) {
        self.0.borrow_mut().drops += 1;
    }
}
fn channel() -> (Channel, Rc<RefCell<ChannelState>>) {
    let state = Rc::new(RefCell::new(ChannelState::default()));
    (Channel(state.clone()), state)
}
fn begin(
    registry: &mut Registry<Channel>,
    environment: &Rc<RefCell<Environment>>,
    peer: PeerIdentity,
    pid: u64,
    absolute: bool,
    duration: u128,
    channel: Channel,
    reply: impl FnOnce(u128) -> bool,
) -> Result<bool, i32> {
    let mut environment = environment.borrow_mut();
    let Environment { service, processes } = &mut *environment;
    let image = service.capture_request_image(peer)?;
    registry.begin_with_reply(
        service, peer, image, pid, absolute, duration, channel, processes, reply,
    )
}
fn observe(
    registry: &mut Registry<Channel>,
    environment: &Rc<RefCell<Environment>>,
) -> Result<usize, i32> {
    let mut environment = environment.borrow_mut();
    let Environment { service, processes } = &mut *environment;
    registry.observe(service, processes)
}
fn clocks(samples: &[(u32, u128)]) {
    CLOCKS.with(|c| {
        let mut c = c.borrow_mut();
        c.process_samples = samples.to_vec();
        c.reads.clear();
    });
}

#[test]
fn waits_follow_the_selected_cpu_without_signal_or_timer_side_effects() {
    let (client, environment) = setup();
    subject(&environment, 2902, 501);
    let peer = client.transport().peer;
    clocks(&[(2901, 10_000), (2902, 100)]);
    let mut registry = Registry::new();
    let (channel, state) = channel();
    assert_eq!(
        begin(
            &mut registry,
            &environment,
            peer,
            2902,
            false,
            50,
            channel,
            |deadline| {
                assert_eq!(deadline, 150);
                true
            }
        ),
        Ok(true)
    );
    clocks(&[(2901, 1_000_000), (2902, 149)]);
    assert_eq!(observe(&mut registry, &environment), Ok(0));
    assert_eq!(state.borrow().attempts, 0);
    CLOCKS.with(|c| assert_eq!(c.borrow().reads, [(2902, Clock::ProcessCpu)]));
    clocks(&[(2901, 1_000_000), (2902, 150)]);
    assert_eq!(observe(&mut registry, &environment), Ok(1));
    assert!(registry.is_empty());
    assert_eq!(state.borrow().delivered, [Ok(())]);
    assert_eq!(state.borrow().drops, 1);
    assert!(!environment.borrow().service.has_observable_process_timers());
    assert!(
        !environment
            .borrow()
            .service
            .signal_notification_processes()
            .any(|_| true)
    );
}

#[test]
fn zero_and_past_absolute_deadlines_complete_instead_of_disarming() {
    let (client, environment) = setup();
    subject(&environment, 2902, 501);
    let peer = client.transport().peer;
    clocks(&[(2901, 100)]);
    for (absolute, duration, deadline) in [(false, 0, 100), (true, 0, 0), (true, 99, 99)] {
        let mut registry = Registry::new();
        let (channel, state) = channel();
        assert_eq!(
            begin(
                &mut registry,
                &environment,
                peer,
                0,
                absolute,
                duration,
                channel,
                |value| {
                    assert_eq!(value, deadline);
                    true
                }
            ),
            Ok(true)
        );
        assert_eq!(observe(&mut registry, &environment), Ok(1));
        assert_eq!(state.borrow().delivered, [Ok(())]);
    }
}

#[test]
fn admission_rejects_forged_credentials_invalid_targets_and_overflow_without_publication() {
    let (client, environment) = setup();
    subject(&environment, 2902, 502);
    let peer = PeerIdentity {
        effective_uid: 0,
        ..client.transport().peer
    };
    let mut registry = Registry::new();
    for (pid, duration, error) in [
        (2902, 1, protocol::STATUS_EPERM),
        (9999, 1, protocol::STATUS_ESRCH),
        (i32::MAX as u64 + 1, 1, STATUS_EINVAL),
        (
            0,
            protocol::process_timer::MAX_DURATION_NS + 1,
            STATUS_EINVAL,
        ),
    ] {
        let (channel, state) = channel();
        assert_eq!(
            begin(
                &mut registry,
                &environment,
                peer,
                pid,
                false,
                duration,
                channel,
                |_| panic!("invalid admission published")
            ),
            Err(error)
        );
        assert_eq!(state.borrow().drops, 1);
        assert!(registry.is_empty());
    }
    clocks(&[(2901, u128::MAX)]);
    let (channel, state) = channel();
    assert_eq!(
        begin(
            &mut registry,
            &environment,
            peer,
            0,
            false,
            1,
            channel,
            |_| panic!("overflow published")
        ),
        Err(protocol::STATUS_EOVERFLOW)
    );
    assert_eq!(state.borrow().drops, 1);
}

#[test]
fn failed_or_unwound_publication_releases_endpoints_and_does_not_use_quota() {
    let (client, environment) = setup();
    subject(&environment, 2902, 501);
    let peer = client.transport().peer;
    let mut registry = Registry::new();
    let (endpoint, state) = channel();
    assert_eq!(
        begin(
            &mut registry,
            &environment,
            peer,
            0,
            false,
            1,
            endpoint,
            |_| false
        ),
        Ok(false)
    );
    assert_eq!(state.borrow().drops, 1);
    let (endpoint, state) = channel();
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            begin(
                &mut registry,
                &environment,
                peer,
                0,
                false,
                1,
                endpoint,
                |_| panic!("reply"),
            )
        }))
        .is_err()
    );
    assert_eq!(state.borrow().drops, 1);
    assert!(registry.is_empty());
}

#[test]
fn completion_backpressure_retries_once_per_sweep_and_retains_terminal_result() {
    let (client, environment) = setup();
    subject(&environment, 2902, 501);
    let peer = client.transport().peer;
    clocks(&[(2901, 10)]);
    let mut registry = Registry::new();
    let (endpoint, state) = channel();
    state.borrow_mut().busy = true;
    begin(
        &mut registry,
        &environment,
        peer,
        0,
        true,
        10,
        endpoint,
        |_| true,
    )
    .unwrap();
    clocks(&[]);
    for _ in 0..3 {
        assert_eq!(observe(&mut registry, &environment), Ok(0));
    }
    CLOCKS.with(|c| assert!(c.borrow().reads.is_empty()));
    assert_eq!(state.borrow().attempts, 3);
    assert_eq!(registry.len(), 1);
    state.borrow_mut().busy = false;
    assert_eq!(observe(&mut registry, &environment), Ok(1));
    assert_eq!(state.borrow().attempts, 4);
    assert_eq!(state.borrow().delivered, [Ok(())]);
    assert_eq!(state.borrow().drops, 1);
}

#[test]
fn native_clock_failure_is_delivered_without_starving_other_waiters() {
    let (client, environment) = setup();
    subject(&environment, 2902, 501);
    let peer = client.transport().peer;
    clocks(&[(2901, 10), (2902, 20)]);
    let mut registry = Registry::new();
    let (a, a_state) = channel();
    let (b, b_state) = channel();
    a_state.borrow_mut().busy = true;
    begin(
        &mut registry,
        &environment,
        peer,
        2902,
        false,
        10,
        a,
        |_| true,
    )
    .unwrap();
    begin(&mut registry, &environment, peer, 0, false, 10, b, |_| true).unwrap();
    clocks(&[(2901, 20)]);
    CLOCKS.with(|c| c.borrow_mut().fail_owner = Some(2902));
    assert_eq!(observe(&mut registry, &environment), Ok(1));
    assert_eq!(b_state.borrow().delivered, [Ok(())]);
    CLOCKS.with(|c| c.borrow_mut().fail_owner = None);
    a_state.borrow_mut().busy = false;
    assert_eq!(observe(&mut registry, &environment), Ok(1));
    assert_eq!(a_state.borrow().delivered, [Err(protocol::STATUS_EIO)]);
}

#[test]
fn disconnected_waiters_are_released_without_sampling_or_cancel_requests() {
    let (client, environment) = setup();
    subject(&environment, 2902, 501);
    let peer = client.transport().peer;
    let mut registry = Registry::new();
    let (endpoint, state) = channel();
    begin(
        &mut registry,
        &environment,
        peer,
        0,
        false,
        10,
        endpoint,
        |_| true,
    )
    .unwrap();
    state.borrow_mut().closed = true;
    clocks(&[]);
    assert_eq!(observe(&mut registry, &environment), Ok(0));
    assert_eq!(state.borrow().drops, 1);
    assert_eq!(state.borrow().attempts, 0);
    CLOCKS.with(|c| assert!(c.borrow().reads.is_empty()));
    assert!(registry.is_empty());
}

#[test]
fn owner_exec_retires_even_backpressured_success_without_delivering_to_new_image() {
    let (client, environment) = setup();
    subject(&environment, 2902, 501);
    let peer = client.transport().peer;
    let mut registry = Registry::new();
    let (endpoint, state) = channel();
    state.borrow_mut().busy = true;
    begin(
        &mut registry,
        &environment,
        peer,
        0,
        false,
        0,
        endpoint,
        |_| true,
    )
    .unwrap();
    assert_eq!(observe(&mut registry, &environment), Ok(0));
    environment.borrow_mut().processes.images.insert(
        2901,
        Ok(mnu_abi::ProcessStatus {
            process_id: 2901,
            state: mnu_abi::PROCESS_STATE_RUNNING,
            image_revision: 1,
            ..Default::default()
        }),
    );
    state.borrow_mut().busy = false;
    assert_eq!(
        observe(&mut registry, &environment),
        Err(protocol::STATUS_ESRCH)
    );
    assert!(state.borrow().delivered.is_empty());
    assert_eq!(state.borrow().drops, 1);
    assert!(registry.is_empty());
}

#[test]
fn subject_exit_completes_with_error_but_subject_exec_preserves_cpu_lifetime() {
    let (client, environment) = setup();
    let other = subject(&environment, 2902, 501);
    let peer = client.transport().peer;
    let mut registry = Registry::new();
    let (endpoint, state) = channel();
    begin(
        &mut registry,
        &environment,
        peer,
        2902,
        false,
        10,
        endpoint,
        |_| true,
    )
    .unwrap();
    {
        let mut environment = environment.borrow_mut();
        let Environment { service, processes } = &mut *environment;
        processes.images.insert(
            2902,
            Ok(mnu_abi::ProcessStatus {
                process_id: 2902,
                state: mnu_abi::PROCESS_STATE_RUNNING,
                image_revision: 1,
                ..Default::default()
            }),
        );
        service.refresh_image_state(other, processes).unwrap();
    }
    assert_eq!(observe(&mut registry, &environment), Ok(0));
    environment
        .borrow_mut()
        .processes
        .states
        .insert(2902, ProcessLifecycle::Exited { exit_code: 0 });
    assert_eq!(observe(&mut registry, &environment), Ok(1));
    assert_eq!(state.borrow().delivered, [Err(protocol::STATUS_ESRCH)]);
}

#[test]
fn per_owner_quota_is_released_on_disconnect_and_registry_drop_closes_all_channels() {
    let (client, environment) = setup();
    subject(&environment, 2902, 501);
    let peer = client.transport().peer;
    let mut registry = Registry::new();
    let mut states = Vec::new();
    for _ in 0..MAX_WAITS_PER_PROCESS {
        let (endpoint, state) = channel();
        begin(
            &mut registry,
            &environment,
            peer,
            0,
            false,
            10,
            endpoint,
            |_| true,
        )
        .unwrap();
        states.push(state);
    }
    let (endpoint, state) = channel();
    assert_eq!(
        begin(
            &mut registry,
            &environment,
            peer,
            0,
            false,
            10,
            endpoint,
            |_| panic!("quota failure published")
        ),
        Err(protocol::STATUS_EAGAIN)
    );
    assert_eq!(state.borrow().drops, 1);
    states[0].borrow_mut().closed = true;
    assert_eq!(observe(&mut registry, &environment), Ok(0));
    let (endpoint, state) = channel();
    assert_eq!(
        begin(
            &mut registry,
            &environment,
            peer,
            0,
            false,
            10,
            endpoint,
            |_| true
        ),
        Ok(true)
    );
    states.push(state);
    drop(registry);
    assert!(states.iter().all(|state| state.borrow().drops == 1));
}

#[test]
fn exec_during_native_sampling_rejects_admission_and_releases_endpoint() {
    let (client, environment) = setup();
    subject(&environment, 2902, 501);
    let peer = client.transport().peer;
    CLOCKS.with(|c| c.borrow_mut().exec = true);
    let mut registry = Registry::new();
    let (endpoint, state) = channel();
    assert_eq!(
        begin(
            &mut registry,
            &environment,
            peer,
            0,
            false,
            10,
            endpoint,
            |_| panic!("old image cannot publish")
        ),
        Err(protocol::STATUS_ESRCH)
    );
    assert!(registry.is_empty());
    assert_eq!(state.borrow().drops, 1);
}

#[test]
fn owner_exec_during_observation_discards_even_an_error_completion() {
    let (client, environment) = setup();
    subject(&environment, 2902, 501);
    let peer = client.transport().peer;
    let mut registry = Registry::new();
    let (endpoint, state) = channel();
    begin(
        &mut registry,
        &environment,
        peer,
        0,
        false,
        10,
        endpoint,
        |_| true,
    )
    .unwrap();
    CLOCKS.with(|c| c.borrow_mut().exec = true);
    assert_eq!(
        observe(&mut registry, &environment),
        Err(protocol::STATUS_ESRCH)
    );
    assert!(state.borrow().delivered.is_empty());
    assert_eq!(state.borrow().drops, 1);
    assert!(registry.is_empty());
}

#[test]
fn lost_subject_permission_finishes_with_error_using_registered_credentials() {
    let (client, environment) = setup();
    let other = subject(&environment, 2902, 0);
    {
        let mut environment = environment.borrow_mut();
        let mut ids = [0; protocol::CREDENTIAL_PAIR_PAYLOAD_LEN];
        protocol::encode_credential_pair(501, 0, &mut ids).unwrap();
        assert_eq!(
            environment
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
    let peer = PeerIdentity {
        effective_uid: 0,
        ..client.transport().peer
    };
    let mut registry = Registry::new();
    let (endpoint, state) = channel();
    begin(
        &mut registry,
        &environment,
        peer,
        2902,
        false,
        10,
        endpoint,
        |_| true,
    )
    .unwrap();
    assert_eq!(
        environment
            .borrow_mut()
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
    clocks(&[]);
    assert_eq!(observe(&mut registry, &environment), Ok(1));
    assert_eq!(state.borrow().delivered, [Err(protocol::STATUS_EPERM)]);
    CLOCKS.with(|c| assert!(c.borrow().reads.is_empty()));
}

#[test]
fn failed_completion_publication_closes_only_that_waiter() {
    let (client, environment) = setup();
    subject(&environment, 2902, 501);
    let peer = client.transport().peer;
    let mut registry = Registry::new();
    let (a, a_state) = channel();
    let (b, b_state) = channel();
    a_state.borrow_mut().failure = Some(-32); // EPIPE from the native adapter.
    begin(&mut registry, &environment, peer, 0, false, 0, a, |_| true).unwrap();
    begin(&mut registry, &environment, peer, 0, false, 0, b, |_| true).unwrap();
    assert_eq!(observe(&mut registry, &environment), Err(-32));
    assert_eq!(a_state.borrow().drops, 1);
    assert!(a_state.borrow().delivered.is_empty());
    assert_eq!(b_state.borrow().delivered, [Ok(())]);
    assert_eq!(b_state.borrow().drops, 1);
    assert!(registry.is_empty());
}

#[test]
fn global_quota_prevents_unbounded_waiters_across_independent_owners() {
    use posix_service::cpu_sleep::MAX_WAITS;
    let (_, environment) = setup();
    let mut registry = Registry::new();
    for n in 0..MAX_WAITS / MAX_WAITS_PER_PROCESS {
        let peer = subject(&environment, 3000 + n as u64, 501);
        for _ in 0..MAX_WAITS_PER_PROCESS {
            let (endpoint, _) = channel();
            assert_eq!(
                begin(
                    &mut registry,
                    &environment,
                    peer,
                    0,
                    false,
                    10,
                    endpoint,
                    |_| true
                ),
                Ok(true)
            );
        }
    }
    assert_eq!(registry.len(), MAX_WAITS);
    let peer = subject(&environment, 4000, 501);
    let (endpoint, state) = channel();
    assert_eq!(
        begin(
            &mut registry,
            &environment,
            peer,
            0,
            false,
            10,
            endpoint,
            |_| panic!("global quota failure published")
        ),
        Err(protocol::STATUS_EAGAIN)
    );
    assert_eq!(state.borrow().drops, 1);
}

#[test]
fn ipc_admission_rejects_noncanonical_envelopes_and_attached_objects_before_publication() {
    let (client, environment) = setup();
    subject(&environment, 2902, 501);
    let peer = client.transport().peer;
    let mut registry = Registry::new();
    let mut payload = [0; protocol::cpu_sleep::REQUEST_LEN];
    protocol::cpu_sleep::encode_request(
        protocol::cpu_sleep::Request {
            process: 0,
            absolute: false,
            nanoseconds: 10,
        },
        &mut payload,
    )
    .unwrap();
    for case in 0..7 {
        let mut header = protocol::Header {
            opcode: protocol::OP_PROCESS_CPU_SLEEP,
            payload_len: payload.len() as u32,
            ..Default::default()
        };
        let mut bytes = payload;
        let mut attachments = Vec::new();
        match case {
            0 => header.opcode = u16::MAX,
            1 => header.flags = 1,
            2 => header.status = -5,
            3 => header.payload_len -= 1,
            4 => bytes[0] = 2,
            5 => attachments.push(AttachedObject {
                handle: 44,
                rights: mnu_abi::HANDLE_RIGHT_WAIT,
            }),
            6 => bytes[4] = 1,
            _ => unreachable!(),
        }
        let (endpoint, state) = channel();
        let mut environment = environment.borrow_mut();
        let Environment { service, processes } = &mut *environment;
        let image = service.capture_request_image(peer).unwrap();
        assert_eq!(
            registry.begin_request_with_reply(
                service,
                peer,
                image,
                header,
                &bytes,
                &attachments,
                endpoint,
                processes,
                |_| panic!("malformed IPC published")
            ),
            Err(if case == 0 {
                protocol::STATUS_ENOSYS
            } else {
                STATUS_EINVAL
            })
        );
        assert_eq!(state.borrow().drops, 1);
        assert!(registry.is_empty());
    }
}

#[test]
fn canonical_ipc_admission_publishes_the_sampled_deadline_and_then_completes() {
    let (client, environment) = setup();
    subject(&environment, 2902, 501);
    let peer = client.transport().peer;
    clocks(&[(2901, 100)]);
    let mut registry = Registry::new();
    let mut payload = [0; protocol::cpu_sleep::REQUEST_LEN];
    protocol::cpu_sleep::encode_request(
        protocol::cpu_sleep::Request {
            process: 0,
            absolute: false,
            nanoseconds: 10,
        },
        &mut payload,
    )
    .unwrap();
    let (endpoint, state) = channel();
    {
        let mut environment = environment.borrow_mut();
        let Environment { service, processes } = &mut *environment;
        let image = service.capture_request_image(peer).unwrap();
        assert_eq!(
            registry.begin_request_with_reply(
                service,
                peer,
                image,
                protocol::Header {
                    opcode: protocol::OP_PROCESS_CPU_SLEEP,
                    payload_len: payload.len() as u32,
                    ..Default::default()
                },
                &payload,
                &[],
                endpoint,
                processes,
                |deadline| {
                    assert_eq!(deadline, 110);
                    true
                }
            ),
            Ok(true)
        );
    }
    clocks(&[(2901, 110)]);
    assert_eq!(observe(&mut registry, &environment), Ok(1));
    assert_eq!(state.borrow().delivered, [Ok(())]);
}
