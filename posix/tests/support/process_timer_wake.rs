use super::*;
const SIGNAL: u32 = protocol::SIGNAL_ALRM;
const THREAD: u64 = 901;
fn bit(signal: u32) -> u64 {
    1u64 << (signal - 1)
}
fn sender(peer: PeerIdentity, thread: u64) -> mnu_abi::ExecutionIdentity {
    mnu_abi::ExecutionIdentity {
        process_id: peer.process_id,
        thread_id: thread,
    }
}
fn queued(service: &PosixService, peer: PeerIdentity) -> bool {
    service
        .signal_notification_processes()
        .any(|owner| owner == peer.process_id)
}
fn arm(
    service: &mut PosixService,
    peer: PeerIdentity,
    signal: u32,
    interval: u128,
) -> posix_service::process_timer::TimerId {
    arm_internal(
        service,
        peer,
        Clock::Monotonic,
        Notification::Signal { signal, value: 71 },
        10,
        interval,
        false,
    )
}
fn action(service: &mut PosixService, peer: PeerIdentity, signal: u32, kind: u32) {
    let mut payload = [0; protocol::SIGNAL_DISPOSITION_LEN];
    protocol::encode_signal_disposition(
        protocol::SignalDisposition {
            signal,
            kind,
            child_options: 0,
        },
        &mut payload,
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
                &payload
            )
            .header
            .status,
        0
    );
}

#[test]
fn public_signal_timer_queues_once_per_event_not_once_per_overrun_and_unblock_replays() {
    let (client, environment) = setup();
    let peer = client.transport().peer;
    let id = client
        .timer_create(
            Clock::Monotonic,
            Notification::Signal {
                signal: SIGNAL,
                value: 71,
            },
        )
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
    let mut environment = environment.borrow_mut();
    let Environment { service, processes } = &mut *environment;
    terminal_mask(service, peer, THREAD, bit(SIGNAL));
    CLOCKS.with(|clocks| clocks.borrow_mut().samples.monotonic_ns = 19);
    service.observe_process_timers(processes).unwrap();
    assert!(!queued(service, peer));
    CLOCKS.with(|clocks| clocks.borrow_mut().samples.monotonic_ns = 20);
    service.observe_process_timers(processes).unwrap();
    assert!(queued(service, peer));
    service.acknowledge_signal_notification(peer.process_id);
    CLOCKS.with(|clocks| clocks.borrow_mut().samples.monotonic_ns = 55);
    service.observe_process_timers(processes).unwrap();
    assert!(!queued(service, peer));
    terminal_mask(service, peer, THREAD, 0);
    assert!(queued(service, peer));
    let image = service.capture_request_image(peer).unwrap();
    let accepted = service
        .dequeue_signal_with_timers(peer, image, sender(peer, THREAD), processes, |_| true)
        .unwrap()
        .unwrap();
    assert_eq!(accepted.signal, SIGNAL);
    assert!(!queued(service, peer));
    assert_eq!(client.transport().peer, peer);
    CLOCKS.with(|clocks| clocks.borrow_mut().samples.monotonic_ns = 60);
    service.observe_process_timers(processes).unwrap();
    assert!(queued(service, peer));
}

#[test]
fn newly_retained_thread_replays_timer_after_initialization_wake_was_already_acknowledged() {
    let (client, environment) = setup();
    let peer = client.transport().peer;
    let mut environment = environment.borrow_mut();
    let Environment { service, processes } = &mut *environment;
    terminal_mask(service, peer, THREAD, bit(SIGNAL));
    arm(service, peer, SIGNAL, 0);
    service.observe_process_timers(processes).unwrap();
    service.acknowledge_signal_notification(peer.process_id);
    service
        .signal_thread_ready(peer, sender(peer, THREAD))
        .unwrap();
    assert!(!queued(service, peer));
    terminal_mask(service, peer, THREAD + 1, 0);
    assert!(queued(service, peer));
    service.acknowledge_signal_notification(peer.process_id);
    service
        .signal_thread_ready(peer, sender(peer, THREAD + 1))
        .unwrap();
    assert!(queued(service, peer));
    service.acknowledge_signal_notification(peer.process_id);
    assert_eq!(
        service.signal_thread_ready(peer, sender(peer, 9999)),
        Ok(false)
    );
    assert_eq!(
        service.signal_thread_ready(
            peer,
            mnu_abi::ExecutionIdentity {
                process_id: peer.process_id + 1,
                thread_id: THREAD
            }
        ),
        Err(protocol::STATUS_EPERM)
    );
    assert!(!queued(service, peer));
    let image = service.capture_request_image(peer).unwrap();
    assert_eq!(
        service.dequeue_signal_with_timers(peer, image, sender(peer, 9999), processes, |_| panic!(
            "implicit mask"
        )),
        Err(protocol::STATUS_ESRCH)
    );
}

#[test]
fn failed_one_shot_reply_requeues_a_wake_after_previous_interrupt_was_acknowledged() {
    let (client, environment) = setup();
    let peer = client.transport().peer;
    let mut environment = environment.borrow_mut();
    let Environment { service, processes } = &mut *environment;
    terminal_mask(service, peer, THREAD, 0);
    arm(service, peer, SIGNAL, 0);
    service.observe_process_timers(processes).unwrap();
    assert!(!service.has_observable_process_timers());
    service.acknowledge_signal_notification(peer.process_id);
    let image = service.capture_request_image(peer).unwrap();
    assert_eq!(
        service.dequeue_signal_with_timers(peer, image, sender(peer, THREAD), processes, |_| false),
        Ok(None)
    );
    assert!(queued(service, peer));
    service.acknowledge_signal_notification(peer.process_id);
    service
        .dequeue_signal_with_timers(peer, image, sender(peer, THREAD), processes, |_| true)
        .unwrap();
    assert!(!queued(service, peer));
}

#[test]
fn synchronous_acceptance_clears_only_empty_process_wakes() {
    let (client, environment) = setup();
    let peer = client.transport().peer;
    let mut environment = environment.borrow_mut();
    let Environment { service, processes } = &mut *environment;
    terminal_mask(service, peer, THREAD, bit(SIGNAL));
    arm(service, peer, SIGNAL, 0);
    arm(service, peer, SIGNAL, 0);
    service.observe_process_timers(processes).unwrap();
    let image = service.capture_request_image(peer).unwrap();
    for remains in [true, false] {
        service
            .poll_wait_signal_info_with_timers(
                peer,
                image,
                sender(peer, THREAD),
                bit(SIGNAL),
                0,
                None,
                0,
                processes,
                |_| true,
            )
            .unwrap();
        assert_eq!(queued(service, peer), remains);
    }
}

#[test]
fn ignore_or_delete_of_one_timer_does_not_clear_another_timer_wake() {
    let (client, environment) = setup();
    let peer = client.transport().peer;
    let other;
    {
        let mut environment = environment.borrow_mut();
        let Environment { service, processes } = &mut *environment;
        arm(service, peer, 10, 0);
        other = arm(service, peer, 12, 0);
        service.observe_process_timers(processes).unwrap();
        action(service, peer, 10, protocol::SIGNAL_DISPOSITION_IGNORE);
        assert!(queued(service, peer));
        // Enqueuing an ignored ordinary occurrence must not clear that wake.
        send_signal(service, peer, peer, 10);
        assert!(queued(service, peer));
    }
    client.timer_delete(other.raw()).unwrap();
    assert!(!queued(&environment.borrow().service, peer));
}

#[test]
fn ignored_continue_timer_still_resumes_and_cancels_pending_stop_notifications() {
    let (client, environment) = setup();
    let peer = client.transport().peer;
    let mut environment = environment.borrow_mut();
    let Environment { service, processes } = &mut *environment;
    arm(service, peer, protocol::SIGNAL_TSTP, 0);
    service.observe_process_timers(processes).unwrap();
    action(
        service,
        peer,
        protocol::SIGNAL_CONT,
        protocol::SIGNAL_DISPOSITION_IGNORE,
    );
    arm(service, peer, protocol::SIGNAL_CONT, 0);
    service.observe_process_timers(processes).unwrap();
    assert!(service
        .process_timers(peer)
        .unwrap()
        .select_pending_signal(u64::MAX)
        .is_none());
    assert!(!queued(service, peer));
    assert!(service
        .process_resume_notification_processes()
        .any(|owner| owner == peer.process_id));
    processes
        .states
        .insert(peer.process_id as u32, ProcessLifecycle::Running);
    assert_eq!(
        service.apply_process_resume(peer.process_id, processes),
        Ok(true)
    );
    assert_eq!(processes.resumed, [peer.process_id as u32]);
}

#[test]
fn lazy_one_shot_query_creates_a_wake_without_a_remaining_reactor_deadline() {
    let (client, environment) = setup();
    let peer = client.transport().peer;
    let id = client
        .timer_create(Clock::Monotonic, Notification::Default)
        .unwrap();
    client
        .timer_set(
            id,
            false,
            Value {
                remaining_ns: 10,
                interval_ns: 0,
            },
        )
        .unwrap();
    CLOCKS.with(|clocks| clocks.borrow_mut().samples.monotonic_ns = 20);
    assert_eq!(client.timer_value(id).unwrap().remaining_ns, 0);
    let environment = environment.borrow();
    assert!(!environment.service.has_observable_process_timers());
    assert!(queued(&environment.service, peer));
}

#[test]
fn native_clock_failure_does_not_publish_a_wake_and_successful_recovery_does() {
    let (client, environment) = setup();
    let peer = client.transport().peer;
    let mut environment = environment.borrow_mut();
    let Environment { service, processes } = &mut *environment;
    arm(service, peer, SIGNAL, 0);
    CLOCKS.with(|clocks| clocks.borrow_mut().fail = true);
    assert_eq!(
        service.observe_process_timers(processes),
        Err(protocol::STATUS_EIO)
    );
    assert!(!queued(service, peer));
    assert!(service.has_observable_process_timers());
    CLOCKS.with(|clocks| clocks.borrow_mut().fail = false);
    service.observe_process_timers(processes).unwrap();
    assert!(queued(service, peer));
}
