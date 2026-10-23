//! Actual service selection and acceptance with controlled native clock/image
//! observations. The main dispatcher routes both new and deferred waits here.
use super::*;
use posix_service::{RequestImage, SignalWaitCompletion};
const SIGNAL: u32 = protocol::SIGNAL_ALRM;
const THREAD: u64 = 901;
fn bit(signal: u32) -> u64 {
    1u64 << (signal - 1)
}
fn sender(peer: PeerIdentity) -> mnu_abi::ExecutionIdentity {
    mnu_abi::ExecutionIdentity {
        process_id: peer.process_id,
        thread_id: THREAD,
    }
}
fn arm(
    service: &mut PosixService,
    peer: PeerIdentity,
    signal: u32,
    value: u64,
) -> posix_service::process_timer::TimerId {
    arm_internal(
        service,
        peer,
        Clock::Monotonic,
        Notification::Signal { signal, value },
        10,
        10,
        false,
    )
}
fn take(
    service: &mut PosixService,
    peer: PeerIdentity,
    processes: &mut RecordingProcesses,
    mask: u64,
) -> protocol::signal_wait::Accepted {
    let image = service.capture_request_image(peer).unwrap();
    let mut received = None;
    assert_eq!(
        service.poll_wait_signal_info_with_timers(
            peer,
            image,
            sender(peer),
            mask,
            0,
            Some(0),
            100,
            processes,
            |accepted| {
                received = Some(accepted);
                true
            },
        ),
        Ok(SignalWaitCompletion::Replied)
    );
    received.unwrap()
}
fn action(service: &mut PosixService, peer: PeerIdentity, signal: u32, kind: u32) {
    let mut bytes = [0; protocol::SIGNAL_DISPOSITION_LEN];
    protocol::encode_signal_disposition(
        protocol::SignalDisposition {
            signal,
            kind,
            child_options: 0,
        },
        &mut bytes,
    )
    .unwrap();
    assert_eq!(
        service
            .handle(
                peer,
                protocol::Header {
                    opcode: protocol::OP_SIGNAL_DISPOSITION,
                    flags: protocol::SIGNAL_DISPOSITION_SET,
                    ..Default::default()
                },
                &bytes
            )
            .header
            .status,
        0
    );
}
fn poll(
    service: &mut PosixService,
    peer: PeerIdentity,
    image: RequestImage,
    processes: &mut RecordingProcesses,
    mask: u64,
) -> Result<SignalWaitCompletion, i32> {
    service.poll_wait_signal_info_with_timers(
        peer,
        image,
        sender(peer),
        mask,
        0,
        Some(0),
        100,
        processes,
        |_| panic!("unexpected publication"),
    )
}

#[test]
fn joint_wait_keeps_thread_priority_and_equal_number_process_and_timer_events_separate() {
    let (client, environment) = setup();
    let peer = client.transport().peer;
    let mut environment = environment.borrow_mut();
    let Environment { service, processes } = &mut *environment;
    let high = 30;
    terminal_mask(service, peer, THREAD, bit(SIGNAL) | bit(high));
    let first = arm(service, peer, SIGNAL, 111);
    let second = arm(service, peer, SIGNAL, 222);
    service.observe_process_timers(processes).unwrap();
    send_signal(service, peer, peer, SIGNAL);
    let mut bytes = [0; protocol::SIGNAL_SEND_REQUEST_LEN];
    protocol::encode_signal_send_request(
        protocol::SignalSendRequest {
            selector: 0,
            signal: high,
        },
        &mut bytes,
    )
    .unwrap();
    assert_eq!(
        service
            .handle_thread_signal_request(
                peer,
                sender(peer),
                protocol::Header {
                    opcode: protocol::OP_SIGNAL_THREAD_RAISE,
                    ..Default::default()
                },
                &bytes
            )
            .header
            .status,
        0
    );
    let own = take(service, peer, processes, bit(SIGNAL) | bit(high));
    assert_eq!(
        (own.signal, own.origin.source),
        (high, protocol::signal_origin::USER)
    );
    let ordinary = take(service, peer, processes, bit(SIGNAL));
    assert_eq!(ordinary.origin.source, protocol::signal_origin::USER);
    for (id, value) in [(first, 111), (second, 222)] {
        let accepted = take(service, peer, processes, bit(SIGNAL));
        let timer = accepted.origin.timer.unwrap();
        assert_eq!(
            (
                accepted.signal,
                timer.timer_id,
                timer.value_token,
                timer.overrun
            ),
            (SIGNAL, id.raw(), value, 0)
        );
    }
    let image = service.capture_request_image(peer).unwrap();
    assert_eq!(
        poll(service, peer, image, processes, bit(SIGNAL)),
        Err(protocol::STATUS_EAGAIN)
    );
    CLOCKS.with(|clocks| assert_eq!(clocks.borrow().reads.len(), 3)); // 1 cached clock read + 2 timer acceptances.
}

#[test]
fn lowest_signal_compares_process_and_timer_candidates_before_expired_wait() {
    for (process_signal, timer_signal) in [(10, 14), (14, 10)] {
        let (client, environment) = setup();
        let peer = client.transport().peer;
        let mut environment = environment.borrow_mut();
        let Environment { service, processes } = &mut *environment;
        let mask = bit(process_signal) | bit(timer_signal);
        terminal_mask(service, peer, THREAD, mask);
        arm(service, peer, timer_signal, 111);
        service.observe_process_timers(processes).unwrap();
        send_signal(service, peer, peer, process_signal);
        assert_eq!(take(service, peer, processes, mask).signal, 10);
        assert_eq!(take(service, peer, processes, mask).signal, 14);
    }
}

#[test]
fn failed_joint_wait_reply_retains_origin_counts_and_previous_overrun_until_retry() {
    let (client, environment) = setup();
    let peer = client.transport().peer;
    let mut environment = environment.borrow_mut();
    let Environment { service, processes } = &mut *environment;
    terminal_mask(service, peer, THREAD, bit(SIGNAL));
    let id = arm(service, peer, SIGNAL, 777);
    service.observe_process_timers(processes).unwrap();
    let image = service.capture_request_image(peer).unwrap();
    CLOCKS.with(|clocks| clocks.borrow_mut().samples.monotonic_ns = 35);
    assert_eq!(
        service.poll_wait_signal_info_with_timers(
            peer,
            image,
            sender(peer),
            bit(SIGNAL),
            0,
            None,
            0,
            processes,
            |accepted| {
                let timer = accepted.origin.timer.unwrap();
                assert_eq!(
                    (timer.timer_id, timer.value_token, timer.overrun),
                    (id.raw(), 777, 2)
                );
                false
            }
        ),
        Ok(SignalWaitCompletion::Undelivered)
    );
    assert_eq!(service.process_timers(peer).unwrap().overrun(id), Ok(0));
    CLOCKS.with(|clocks| clocks.borrow_mut().samples.monotonic_ns = 55);
    assert_eq!(
        take(service, peer, processes, bit(SIGNAL))
            .origin
            .timer
            .unwrap()
            .overrun,
        4
    );
    assert_eq!(service.process_timers(peer).unwrap().overrun(id), Ok(4));
    assert_eq!(
        poll(service, peer, image, processes, bit(SIGNAL)),
        Err(protocol::STATUS_EAGAIN)
    );
}

#[test]
fn invalid_thread_mask_and_unblocked_timer_interrupts_leave_the_event_pending() {
    let (client, environment) = setup();
    let peer = client.transport().peer;
    let mut environment = environment.borrow_mut();
    let Environment { service, processes } = &mut *environment;
    terminal_mask(service, peer, THREAD, bit(SIGNAL));
    arm(service, peer, SIGNAL, 777);
    service.observe_process_timers(processes).unwrap();
    CLOCKS.with(|clocks| clocks.borrow_mut().reads.clear());
    let image = service.capture_request_image(peer).unwrap();
    for identity in [
        mnu_abi::ExecutionIdentity {
            process_id: peer.process_id + 1,
            thread_id: THREAD,
        },
        mnu_abi::ExecutionIdentity {
            thread_id: 9999,
            ..sender(peer)
        },
    ] {
        let result = service.poll_wait_signal_info_with_timers(
            peer,
            image,
            identity,
            bit(SIGNAL),
            0,
            Some(0),
            100,
            processes,
            |_| panic!("bad caller published"),
        );
        assert_eq!(
            result,
            Err(if identity.process_id != peer.process_id {
                protocol::STATUS_EPERM
            } else {
                protocol::STATUS_ESRCH
            })
        );
    }
    assert_eq!(
        poll(service, peer, image, processes, bit(10)),
        Err(STATUS_EINVAL)
    );
    terminal_mask(service, peer, THREAD, 0);
    assert_eq!(
        poll(service, peer, image, processes, 0),
        Err(protocol::STATUS_EINTR)
    );
    CLOCKS.with(|clocks| assert!(clocks.borrow().reads.is_empty()));
    terminal_mask(service, peer, THREAD, bit(SIGNAL));
    assert_eq!(take(service, peer, processes, bit(SIGNAL)).signal, SIGNAL);
}

#[test]
fn clock_failure_and_native_exec_during_joint_acceptance_never_publish_old_metadata() {
    let (client, environment) = setup();
    let peer = client.transport().peer;
    let mut environment = environment.borrow_mut();
    let Environment { service, processes } = &mut *environment;
    terminal_mask(service, peer, THREAD, bit(SIGNAL));
    let id = arm(service, peer, SIGNAL, 777);
    service.observe_process_timers(processes).unwrap();
    let image = service.capture_request_image(peer).unwrap();
    CLOCKS.with(|clocks| clocks.borrow_mut().fail = true);
    assert_eq!(
        poll(service, peer, image, processes, bit(SIGNAL)),
        Err(protocol::STATUS_EIO)
    );
    assert_eq!(service.process_timers(peer).unwrap().overrun(id), Ok(0));
    CLOCKS.with(|clocks| {
        let mut clocks = clocks.borrow_mut();
        clocks.fail = false;
        clocks.exec = true;
    });
    assert_eq!(
        poll(service, peer, image, processes, bit(SIGNAL)),
        Err(protocol::STATUS_ESRCH)
    );
    assert_eq!(
        service.process_timers(peer).unwrap().clock(id),
        Err(STATUS_EINVAL)
    );
}

#[test]
fn ignored_and_job_control_canceled_timer_events_never_resurrect() {
    let (client, environment) = setup();
    let peer = client.transport().peer;
    let mut environment = environment.borrow_mut();
    let Environment { service, processes } = &mut *environment;
    terminal_mask(service, peer, THREAD, bit(SIGNAL));
    let id = arm(service, peer, SIGNAL, 777);
    service.observe_process_timers(processes).unwrap();
    CLOCKS.with(|clocks| clocks.borrow_mut().samples.monotonic_ns = 35);
    assert_eq!(
        take(service, peer, processes, bit(SIGNAL))
            .origin
            .timer
            .unwrap()
            .overrun,
        2
    );
    CLOCKS.with(|clocks| clocks.borrow_mut().samples.monotonic_ns = 40);
    service.observe_process_timers(processes).unwrap();
    action(service, peer, SIGNAL, protocol::SIGNAL_DISPOSITION_IGNORE);
    action(service, peer, SIGNAL, protocol::SIGNAL_DISPOSITION_CAUGHT);
    let image = service.capture_request_image(peer).unwrap();
    assert_eq!(
        poll(service, peer, image, processes, bit(SIGNAL)),
        Err(protocol::STATUS_EAGAIN)
    );
    action(service, peer, SIGNAL, protocol::SIGNAL_DISPOSITION_IGNORE);
    CLOCKS.with(|clocks| clocks.borrow_mut().samples.monotonic_ns = 65);
    service.observe_process_timers(processes).unwrap();
    action(service, peer, SIGNAL, protocol::SIGNAL_DISPOSITION_CAUGHT);
    assert_eq!(service.process_timers(peer).unwrap().overrun(id), Ok(2));
    assert_eq!(
        poll(service, peer, image, processes, bit(SIGNAL)),
        Err(protocol::STATUS_EAGAIN)
    );
    CLOCKS.with(|clocks| clocks.borrow_mut().samples.monotonic_ns = 70);
    service.observe_process_timers(processes).unwrap();
    assert_eq!(
        take(service, peer, processes, bit(SIGNAL))
            .origin
            .timer
            .unwrap()
            .overrun,
        0
    );
    assert_eq!(service.process_timers(peer).unwrap().overrun(id), Ok(0));

    let stop = protocol::SIGNAL_TSTP;
    terminal_mask(service, peer, THREAD, bit(stop));
    arm(service, peer, stop, 888);
    service.observe_process_timers(processes).unwrap();
    send_signal(service, peer, peer, protocol::SIGNAL_CONT);
    // SIGCONT itself may be pending, but canceled stop events are gone.
    assert!(service
        .process_timers(peer)
        .unwrap()
        .select_pending_signal(bit(stop))
        .is_none());
}

#[test]
fn lazy_one_shot_observation_while_ignored_does_not_resurrect_when_caught() {
    let (client, environment) = setup();
    let peer = client.transport().peer;
    let mut environment = environment.borrow_mut();
    let Environment { service, processes } = &mut *environment;
    terminal_mask(service, peer, THREAD, bit(SIGNAL));
    let id = arm_internal(
        service,
        peer,
        Clock::Monotonic,
        Notification::Default,
        10,
        0,
        false,
    );
    action(service, peer, SIGNAL, protocol::SIGNAL_DISPOSITION_IGNORE);
    let image = service.capture_request_image(peer).unwrap();
    let payload = id.raw().to_le_bytes();
    let response = service.handle_process_timer_request(
        peer,
        image,
        protocol::Header {
            opcode: protocol::OP_TIMER_GET,
            payload_len: payload.len() as u32,
            ..Default::default()
        },
        &payload,
        &[],
        processes,
    );
    assert_eq!(response.response.header.status, 0);
    assert!(!service.has_observable_process_timers());
    action(service, peer, SIGNAL, protocol::SIGNAL_DISPOSITION_CAUGHT);
    assert_eq!(
        poll(service, peer, image, processes, bit(SIGNAL)),
        Err(protocol::STATUS_EAGAIN)
    );
    assert_eq!(service.process_timers(peer).unwrap().overrun(id), Ok(0));
}
