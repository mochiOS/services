//! Actual service dequeue and origin ownership, with controlled native
//! observations and publication outcomes. No native IPC execution is claimed.
use super::*;
use posix_service::Response;
const THREAD: u64 = 901;
const SIGNAL: u32 = protocol::SIGNAL_ALRM;
fn bit(signal: u32) -> u64 {
    1u64 << (signal - 1)
}
fn sender(peer: PeerIdentity, thread_id: u64) -> mnu_abi::ExecutionIdentity {
    mnu_abi::ExecutionIdentity {
        process_id: peer.process_id,
        thread_id,
    }
}
fn arm(service: &mut PosixService, peer: PeerIdentity) -> posix_service::process_timer::TimerId {
    arm_internal(
        service,
        peer,
        Clock::Monotonic,
        Notification::Signal {
            signal: SIGNAL,
            value: 0x12345678,
        },
        10,
        10,
        false,
    )
}
fn bytes(delivery: protocol::SignalDelivery) -> [u8; protocol::SIGNAL_DELIVERY_LEN] {
    let mut bytes = [0; protocol::SIGNAL_DELIVERY_LEN];
    protocol::encode_signal_delivery(delivery, &mut bytes).unwrap();
    bytes
}
fn epoch(service: &mut PosixService, peer: PeerIdentity) -> u64 {
    let response = service.handle_thread_signal_request(
        peer,
        sender(peer, THREAD),
        protocol::Header {
            opcode: protocol::OP_SIGNAL_THREAD_EPOCH,
            ..Default::default()
        },
        &[],
    );
    assert_eq!(response.header.status, 0);
    protocol::decode_signal_mask(&response.payload).unwrap()
}
fn origin_response(
    service: &mut PosixService,
    peer: PeerIdentity,
    thread: u64,
    delivery: protocol::SignalDelivery,
) -> Response {
    service.handle_thread_signal_request(
        peer,
        sender(peer, thread),
        protocol::Header {
            opcode: protocol::OP_SIGNAL_DELIVERY_ORIGIN,
            ..Default::default()
        },
        &bytes(delivery),
    )
}
fn take(
    service: &mut PosixService,
    peer: PeerIdentity,
    processes: &mut RecordingProcesses,
) -> protocol::SignalDelivery {
    let image = service.capture_request_image(peer).unwrap();
    service
        .dequeue_signal_with_timers(peer, image, sender(peer, THREAD), processes, |_| true)
        .unwrap()
        .unwrap()
}

#[test]
fn failed_timer_publication_retires_only_its_provisional_token_and_retry_resamples_origin() {
    let (client, environment) = setup();
    let peer = client.transport().peer;
    let mut environment = environment.borrow_mut();
    let Environment { service, processes } = &mut *environment;
    terminal_mask(service, peer, THREAD, 0);
    let id = arm(service, peer);
    service.observe_process_timers(processes).unwrap();
    CLOCKS.with(|clocks| clocks.borrow_mut().samples.monotonic_ns = 35);
    let image = service.capture_request_image(peer).unwrap();
    let mut attempted = None;
    assert_eq!(
        service.dequeue_signal_with_timers(
            peer,
            image,
            sender(peer, THREAD),
            processes,
            |delivery| {
                attempted = Some(delivery);
                false
            }
        ),
        Ok(None)
    );
    let rejected = attempted.unwrap();
    assert_eq!(epoch(service, peer), 0);
    assert_eq!(
        origin_response(service, peer, THREAD, rejected)
            .header
            .status,
        protocol::STATUS_EAGAIN
    );
    assert_eq!(service.process_timers(peer).unwrap().overrun(id), Ok(0));
    CLOCKS.with(|clocks| clocks.borrow_mut().samples.monotonic_ns = 55);
    let accepted = take(service, peer, processes);
    assert_ne!(rejected.token, accepted.token);
    assert_eq!(epoch(service, peer), 1);
    let response = origin_response(service, peer, THREAD, accepted);
    let origin = protocol::signal_origin::decode(&response.payload).unwrap();
    let timer = origin.timer.unwrap();
    assert_eq!(
        (timer.timer_id, timer.value_token, timer.overrun),
        (id.raw(), 0x12345678, 4)
    );
    assert_eq!(service.process_timers(peer).unwrap().overrun(id), Ok(4));
    assert_eq!(
        take(service, peer, processes),
        protocol::SignalDelivery {
            signal: 0,
            token: 0
        }
    );
    assert_eq!(epoch(service, peer), 1);
    assert_eq!(
        origin_response(service, peer, THREAD + 1, accepted)
            .header
            .status,
        protocol::STATUS_EAGAIN
    );
    service
        .complete_signal_delivery(peer, &bytes(accepted))
        .unwrap();
    assert_eq!(
        origin_response(service, peer, THREAD, accepted)
            .header
            .status,
        protocol::STATUS_EAGAIN
    );
}

#[test]
fn repeated_failed_normal_replies_do_not_exhaust_delivery_slots_or_advance_epochs() {
    for private in [false, true] {
        let (client, environment) = setup();
        let peer = client.transport().peer;
        let mut environment = environment.borrow_mut();
        let Environment { service, processes } = &mut *environment;
        terminal_mask(service, peer, THREAD, 0);
        if private {
            let mut payload = [0; protocol::SIGNAL_SEND_REQUEST_LEN];
            protocol::encode_signal_send_request(
                protocol::SignalSendRequest {
                    selector: 0,
                    signal: SIGNAL,
                },
                &mut payload,
            )
            .unwrap();
            assert_eq!(
                service
                    .handle_thread_signal_request(
                        peer,
                        sender(peer, THREAD),
                        protocol::Header {
                            opcode: protocol::OP_SIGNAL_THREAD_RAISE,
                            ..Default::default()
                        },
                        &payload
                    )
                    .header
                    .status,
                0
            );
        } else {
            send_signal(service, peer, peer, SIGNAL);
        }
        let image = service.capture_request_image(peer).unwrap();
        let mut tokens = Vec::new();
        for _ in 0..160 {
            assert_eq!(
                service.dequeue_signal_with_timers(
                    peer,
                    image,
                    sender(peer, THREAD),
                    processes,
                    |delivery| {
                        tokens.push(delivery.token);
                        false
                    }
                ),
                Ok(None)
            );
        }
        assert!(tokens.windows(2).all(|pair| pair[0] < pair[1]));
        assert_eq!(epoch(service, peer), 0);
        let accepted = take(service, peer, processes);
        assert_eq!(accepted.signal, SIGNAL);
        assert_eq!(epoch(service, peer), 1);
        assert_eq!(
            protocol::signal_origin::decode(
                &origin_response(service, peer, THREAD, accepted).payload
            )
            .unwrap()
            .source,
            protocol::signal_origin::USER
        );
        assert_eq!(take(service, peer, processes).signal, 0);
        CLOCKS.with(|clocks| assert!(clocks.borrow().reads.is_empty()));
    }
}

#[test]
fn joint_async_selection_prefers_private_then_equal_number_process_then_distinct_timers() {
    let (client, environment) = setup();
    let peer = client.transport().peer;
    let mut environment = environment.borrow_mut();
    let Environment { service, processes } = &mut *environment;
    terminal_mask(service, peer, THREAD, 0);
    let first = arm(service, peer);
    let second = arm(service, peer);
    service.observe_process_timers(processes).unwrap();
    send_signal(service, peer, peer, SIGNAL);
    let mut payload = [0; protocol::SIGNAL_SEND_REQUEST_LEN];
    protocol::encode_signal_send_request(
        protocol::SignalSendRequest {
            selector: 0,
            signal: 30,
        },
        &mut payload,
    )
    .unwrap();
    assert_eq!(
        service
            .handle_thread_signal_request(
                peer,
                sender(peer, THREAD),
                protocol::Header {
                    opcode: protocol::OP_SIGNAL_THREAD_RAISE,
                    ..Default::default()
                },
                &payload
            )
            .header
            .status,
        0
    );
    assert_eq!(take(service, peer, processes).signal, 30);
    let process = take(service, peer, processes);
    assert_eq!(process.signal, SIGNAL);
    assert_eq!(
        protocol::signal_origin::decode(&origin_response(service, peer, THREAD, process).payload)
            .unwrap()
            .source,
        protocol::signal_origin::USER
    );
    for id in [first, second] {
        let delivery = take(service, peer, processes);
        let origin = protocol::signal_origin::decode(
            &origin_response(service, peer, THREAD, delivery).payload,
        )
        .unwrap();
        assert_eq!(origin.timer.unwrap().timer_id, id.raw());
    }
    assert_eq!(take(service, peer, processes).signal, 0);
    assert_eq!(epoch(service, peer), 4);
}

#[test]
fn unwind_before_publication_rolls_back_provisional_authority_without_consuming_event() {
    let (client, environment) = setup();
    let peer = client.transport().peer;
    let mut environment = environment.borrow_mut();
    let Environment { service, processes } = &mut *environment;
    terminal_mask(service, peer, THREAD, 0);
    arm(service, peer);
    service.observe_process_timers(processes).unwrap();
    let image = service.capture_request_image(peer).unwrap();
    for _ in 0..80 {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            service.dequeue_signal_with_timers(peer, image, sender(peer, THREAD), processes, |_| {
                panic!("before reply")
            })
        }));
        assert!(result.is_err());
        assert_eq!(epoch(service, peer), 0);
    }
    assert_eq!(take(service, peer, processes).signal, SIGNAL);
}

#[test]
fn outstanding_capacity_failure_keeps_pending_timer_until_a_real_delivery_completes() {
    let (client, environment) = setup();
    let peer = client.transport().peer;
    let mut environment = environment.borrow_mut();
    let Environment { service, processes } = &mut *environment;
    terminal_mask(service, peer, THREAD, 0);
    let id = arm(service, peer);
    let mut active = Vec::new();
    for index in 1..=64 {
        CLOCKS.with(|clocks| clocks.borrow_mut().samples.monotonic_ns = index * 10);
        service.observe_process_timers(processes).unwrap();
        active.push(take(service, peer, processes));
    }
    CLOCKS.with(|clocks| clocks.borrow_mut().samples.monotonic_ns = 650);
    service.observe_process_timers(processes).unwrap();
    let image = service.capture_request_image(peer).unwrap();
    assert_eq!(
        service.dequeue_signal_with_timers(
            peer,
            image,
            sender(peer, THREAD),
            processes,
            |_| panic!("full publication")
        ),
        Err(protocol::STATUS_EAGAIN)
    );
    assert_eq!(epoch(service, peer), 64);
    assert_eq!(service.process_timers(peer).unwrap().overrun(id), Ok(0));
    service
        .complete_signal_delivery(peer, &bytes(active[0]))
        .unwrap();
    let delivered = take(service, peer, processes);
    assert!(active.iter().all(|old| old.token != delivered.token));
    assert_eq!(epoch(service, peer), 65);
}

#[test]
fn blocked_events_remain_pending_and_unblock_delivers_each_equal_number_timer_once() {
    let (client, environment) = setup();
    let peer = client.transport().peer;
    let mut environment = environment.borrow_mut();
    let Environment { service, processes } = &mut *environment;
    terminal_mask(service, peer, THREAD, bit(SIGNAL));
    let first = arm(service, peer);
    let second = arm(service, peer);
    service.observe_process_timers(processes).unwrap();
    assert_eq!(take(service, peer, processes).signal, 0);
    terminal_mask(service, peer, THREAD, 0);
    for id in [first, second] {
        let delivery = take(service, peer, processes);
        let origin = protocol::signal_origin::decode(
            &origin_response(service, peer, THREAD, delivery).payload,
        )
        .unwrap();
        assert_eq!(origin.timer.unwrap().timer_id, id.raw());
    }
    assert_eq!(take(service, peer, processes).signal, 0);
}

#[test]
fn invalid_identity_clock_failure_or_exec_never_publish_and_success_has_no_later_observation() {
    let (client, environment) = setup();
    let peer = client.transport().peer;
    let mut environment = environment.borrow_mut();
    let Environment { service, processes } = &mut *environment;
    terminal_mask(service, peer, THREAD, 0);
    arm(service, peer);
    service.observe_process_timers(processes).unwrap();
    let image = service.capture_request_image(peer).unwrap();
    CLOCKS.with(|clocks| clocks.borrow_mut().reads.clear());
    assert_eq!(
        service.dequeue_signal_with_timers(
            peer,
            image,
            sender(peer, THREAD + 1),
            processes,
            |_| panic!("unregistered thread")
        ),
        Err(protocol::STATUS_ESRCH)
    );
    let foreign = mnu_abi::ExecutionIdentity {
        process_id: peer.process_id + 1,
        thread_id: THREAD,
    };
    assert_eq!(
        service.dequeue_signal_with_timers(peer, image, foreign, processes, |_| panic!(
            "foreign caller"
        )),
        Err(protocol::STATUS_EPERM)
    );
    CLOCKS.with(|clocks| {
        let mut clocks = clocks.borrow_mut();
        assert!(clocks.reads.is_empty());
        clocks.fail = true;
    });
    assert_eq!(
        service.dequeue_signal_with_timers(
            peer,
            image,
            sender(peer, THREAD),
            processes,
            |_| panic!("clock failure")
        ),
        Err(protocol::STATUS_EIO)
    );
    assert_eq!(epoch(service, peer), 0);
    CLOCKS.with(|clocks| clocks.borrow_mut().fail = false);
    let delivery = service
        .dequeue_signal_with_timers(peer, image, sender(peer, THREAD), processes, |_| {
            CLOCKS.with(|clocks| clocks.borrow_mut().fail = true);
            true
        })
        .unwrap()
        .unwrap();
    assert_eq!(delivery.signal, SIGNAL);
    assert_eq!(epoch(service, peer), 1);
    CLOCKS.with(|clocks| {
        let mut clocks = clocks.borrow_mut();
        clocks.fail = false;
        clocks.samples.monotonic_ns = 20;
    });
    service.observe_process_timers(processes).unwrap();
    CLOCKS.with(|clocks| clocks.borrow_mut().exec = true);
    assert_eq!(
        service.dequeue_signal_with_timers(
            peer,
            image,
            sender(peer, THREAD),
            processes,
            |_| panic!("old image")
        ),
        Err(protocol::STATUS_ESRCH)
    );
}
