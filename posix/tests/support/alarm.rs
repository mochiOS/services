use super::*;
use std::cell::Cell;

thread_local! {static NOW: Cell<Result<u64, i32>> = const {Cell::new(Ok(0))};}
fn clock() -> Result<u64, i32> {
    NOW.get()
}
fn alarm(service: &mut PosixService, peer: PeerIdentity, seconds: u32) -> Result<u32, i32> {
    let reply = service.handle(
        peer,
        protocol::Header {
            opcode: protocol::OP_ALARM,
            ..Default::default()
        },
        &seconds.to_le_bytes(),
    );
    if reply.header.status != 0 {
        return Err(reply.header.status);
    }
    Ok(u32::from_le_bytes(reply.payload.try_into().unwrap()))
}

#[test]
fn alarm_client_roundtrips_replacement_cancellation_and_upward_rounding() {
    NOW.set(Ok(0));
    let peer = PeerIdentity {
        process_id: 717,
        effective_uid: 505,
        effective_gid: 24,
    };
    let client = Client::new(LocalTransport {
        peer,
        service: RefCell::new(service_for(peer).with_monotonic_clock(clock)),
    });
    assert_eq!(client.alarm(5), Ok(0));
    NOW.set(Ok(1));
    assert_eq!(client.alarm(3), Ok(5));
    NOW.set(Ok(1_000_000_001));
    assert_eq!(client.alarm(0), Ok(2));
    assert_eq!(
        client.transport().service.borrow().next_alarm_deadline(),
        None
    );
    assert_eq!(client.alarm(0), Ok(0));
    assert_eq!(client.alarm(1), Ok(0));
    NOW.set(Ok(2_000_000_001));
    assert_eq!(
        client.transport().service.borrow_mut().expire_alarms(),
        Ok(1)
    );
    assert_eq!(
        client.transport().service.borrow_mut().expire_alarms(),
        Ok(0)
    );
    assert_eq!(
        client.pending_signals().unwrap(),
        1 << (protocol::SIGNAL_ALRM - 1)
    );
    // Canceling an alarm does not consume an already generated signal.
    assert_eq!(client.alarm(0), Ok(0));
    assert_eq!(
        client.pending_signals().unwrap(),
        1 << (protocol::SIGNAL_ALRM - 1)
    );
}

#[test]
fn alarm_is_process_owned_not_inherited_by_fork_and_survives_exec() {
    let (service, init, parent, _, mut filesystem, _) = orphan_family();
    let mut service = service.with_monotonic_clock(clock);
    NOW.set(Ok(0));
    assert_eq!(alarm(&mut service, parent, 8), Ok(0));
    let child = PeerIdentity {
        process_id: 1440,
        ..parent
    };
    service
        .adopt_child(
            parent,
            AuthenticatedProcess {
                handle: 144,
                process_id: 1440,
            },
            &mut filesystem,
        )
        .unwrap();
    assert_eq!(alarm(&mut service, child, 0), Ok(0));
    let response =
        thread_signal_request(&mut service, parent, protocol::OP_SIGNAL_IMAGE_STARTED, &[]);
    assert_eq!(response.header.status, 0);
    assert_eq!(service.next_alarm_deadline(), Some(8_000_000_000));
    assert_eq!(alarm(&mut service, init, 2), Ok(0));
    NOW.set(Ok(2_000_000_000));
    assert_eq!(service.expire_alarms(), Ok(1));
    assert_eq!(
        service.signal_state(parent.process_id).unwrap().pending(),
        0
    );
    assert_eq!(service.signal_state(child.process_id).unwrap().pending(), 0);
    assert_eq!(service.next_alarm_deadline(), Some(8_000_000_000));
    NOW.set(Ok(8_000_000_000));
    assert_eq!(service.expire_alarms(), Ok(1));
    assert_ne!(
        service.signal_state(parent.process_id).unwrap().pending(),
        0
    );
    assert_eq!(service.signal_state(child.process_id).unwrap().pending(), 0);
}

#[test]
fn invalid_input_clock_failure_and_deadline_overflow_preserve_the_alarm() {
    let peer = PeerIdentity {
        process_id: 717,
        effective_uid: 505,
        effective_gid: 24,
    };
    let mut service = service_for(peer).with_monotonic_clock(clock);
    NOW.set(Ok(0));
    alarm(&mut service, peer, 5).unwrap();
    for payload in [vec![], vec![0; 3], vec![0; 5]] {
        assert_eq!(
            service
                .handle(
                    peer,
                    protocol::Header {
                        opcode: protocol::OP_ALARM,
                        ..Default::default()
                    },
                    &payload
                )
                .header
                .status,
            STATUS_EINVAL
        );
    }
    assert_eq!(
        alarm(
            &mut service,
            PeerIdentity {
                process_id: 999,
                ..peer
            },
            1
        ),
        Err(protocol::STATUS_ESRCH)
    );
    NOW.set(Err(protocol::STATUS_EIO));
    assert_eq!(alarm(&mut service, peer, 0), Err(protocol::STATUS_EIO));
    assert_eq!(service.expire_alarms(), Err(protocol::STATUS_EIO));
    NOW.set(Ok(u64::MAX - 1));
    assert_eq!(
        alarm(&mut service, peer, 1),
        Err(posix_service::STATUS_EOVERFLOW)
    );
    assert_eq!(service.next_alarm_deadline(), Some(5_000_000_000));
}

#[test]
fn alarm_rejects_infinite_wait_sentinel_but_expires_last_finite_deadline() {
    let peer = PeerIdentity {
        process_id: 717,
        effective_uid: 505,
        effective_gid: 24,
    };
    let mut service = service_for(peer).with_monotonic_clock(clock);
    NOW.set(Ok(0));
    assert_eq!(alarm(&mut service, peer, 5), Ok(0));

    NOW.set(Ok(u64::MAX - 1_000_000_000));
    assert_eq!(
        alarm(&mut service, peer, 1),
        Err(posix_service::STATUS_EOVERFLOW)
    );
    assert_eq!(service.next_alarm_deadline(), Some(5_000_000_000));
    assert_eq!(service.signal_state(peer.process_id).unwrap().pending(), 0);

    // The deadline immediately below the sentinel is still finite and valid.
    let mut service = service_for(peer).with_monotonic_clock(clock);
    NOW.set(Ok(u64::MAX - 1_000_000_001));
    assert_eq!(alarm(&mut service, peer, 1), Ok(0));
    assert_eq!(service.next_alarm_deadline(), Some(u64::MAX - 1));
    NOW.set(Ok(u64::MAX - 2));
    assert_eq!(service.expire_alarms(), Ok(0));
    NOW.set(Ok(u64::MAX - 1));
    assert_eq!(service.expire_alarms(), Ok(1));
    assert_eq!(service.next_alarm_deadline(), None);
    assert_ne!(service.signal_state(peer.process_id).unwrap().pending(), 0);
}

#[test]
fn root_process_exit_cancels_alarm_and_is_observed_without_a_posix_parent() {
    let (service, init, _, _, _, mut processes) = orphan_family();
    let mut service = service.with_monotonic_clock(clock);
    NOW.set(Ok(0));
    alarm(&mut service, init, 5).unwrap();
    assert!(service.child_lifecycle_handles().contains(&140));
    processes
        .states
        .insert(140, ProcessLifecycle::Exited { exit_code: 0 });
    service
        .refresh_child_exit_notifications(&mut processes)
        .unwrap();
    assert_eq!(service.next_alarm_deadline(), None);
    NOW.set(Ok(9_000_000_000));
    assert_eq!(service.expire_alarms(), Ok(0));
    assert_eq!(alarm(&mut service, init, 1), Err(protocol::STATUS_ESRCH));
}

#[test]
fn expiration_obeys_ignored_and_thread_blocked_signal_state() {
    let peer = PeerIdentity {
        process_id: 717,
        effective_uid: 505,
        effective_gid: 24,
    };
    let mut service = service_for(peer).with_monotonic_clock(clock);
    NOW.set(Ok(0));
    let bit = 1 << (protocol::SIGNAL_ALRM - 1);
    let mut mask = [0; protocol::SIGNAL_THREAD_MASK_LEN];
    protocol::encode_signal_mask_request(
        protocol::SignalMaskRequest {
            operation: protocol::SIGNAL_MASK_SET,
            mask: bit,
        },
        &mut mask,
    )
    .unwrap();
    assert_eq!(
        thread_signal_request(&mut service, peer, protocol::OP_SIGNAL_THREAD_MASK, &mask)
            .header
            .status,
        0
    );
    alarm(&mut service, peer, 1).unwrap();
    NOW.set(Ok(1_000_000_000));
    assert_eq!(service.expire_alarms(), Ok(1));
    assert_eq!(dequeue_signal(&mut service, peer).signal, 0);
    protocol::encode_signal_mask_request(
        protocol::SignalMaskRequest {
            operation: protocol::SIGNAL_MASK_UNBLOCK,
            mask: bit,
        },
        &mut mask,
    )
    .unwrap();
    assert_eq!(
        thread_signal_request(&mut service, peer, protocol::OP_SIGNAL_THREAD_MASK, &mask)
            .header
            .status,
        0
    );
    let delivery = dequeue_signal(&mut service, peer);
    assert_eq!(delivery.signal, protocol::SIGNAL_ALRM);
    let mut encoded = [0; protocol::SIGNAL_DELIVERY_LEN];
    protocol::encode_signal_delivery(delivery, &mut encoded).unwrap();
    service.complete_signal_delivery(peer, &encoded).unwrap();
    let mut disposition = [0; protocol::SIGNAL_DISPOSITION_LEN];
    protocol::encode_signal_disposition(
        protocol::SignalDisposition {
            signal: protocol::SIGNAL_ALRM,
            kind: protocol::SIGNAL_DISPOSITION_IGNORE,
            child_options: 0,
        },
        &mut disposition,
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
                &disposition
            )
            .header
            .status,
        0
    );
    alarm(&mut service, peer, 1).unwrap();
    NOW.set(Ok(2_000_000_000));
    assert_eq!(service.expire_alarms(), Ok(1));
    assert_eq!(service.signal_state(peer.process_id).unwrap().pending(), 0);
    assert_eq!(service.next_alarm_deadline(), None);
}
