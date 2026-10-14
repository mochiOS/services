use mnu_abi::ExecutionIdentity;
use mochios_posix_protocol as protocol;
use posix_service::{AuthenticatedProcess, PeerIdentity, PosixService};

const FIRST: u64 = 501;
const SECOND: u64 = 502;
const USR1: u32 = 10;
const USR2: u32 = 12;

fn bit(signal: u32) -> u64 {
    1 << (signal - 1)
}

fn peer(process_id: u64) -> PeerIdentity {
    PeerIdentity {
        process_id,
        effective_uid: 501,
        effective_gid: 501,
    }
}

fn identity(thread_id: u64) -> ExecutionIdentity {
    ExecutionIdentity {
        process_id: 101,
        thread_id,
    }
}

fn fixture(mask: u64) -> PosixService {
    let mut service = PosixService::new();
    service
        .initialize_bootstrap_process(
            AuthenticatedProcess {
                handle: 1,
                process_id: 1,
            },
            0,
            0,
            &[],
        )
        .unwrap();
    service
        .initialize_process(
            peer(1),
            AuthenticatedProcess {
                handle: 101,
                process_id: 101,
            },
            501,
            501,
            &[],
        )
        .unwrap();
    for thread in [FIRST, SECOND] {
        let mut payload = [0; protocol::SIGNAL_THREAD_MASK_LEN];
        protocol::encode_signal_mask_request(
            protocol::SignalMaskRequest {
                operation: protocol::SIGNAL_MASK_SET,
                mask,
            },
            &mut payload,
        )
        .unwrap();
        let response = service.handle_thread_signal_request(
            peer(101),
            identity(thread),
            protocol::Header {
                opcode: protocol::OP_SIGNAL_THREAD_MASK,
                ..Default::default()
            },
            &payload,
        );
        assert_eq!(response.header.status, protocol::STATUS_OK);
    }
    service
}

fn raise(service: &mut PosixService, thread: u64, signal: u32) {
    let mut payload = [0; protocol::SIGNAL_SEND_REQUEST_LEN];
    protocol::encode_signal_send_request(
        protocol::SignalSendRequest {
            selector: 0,
            signal,
        },
        &mut payload,
    )
    .unwrap();
    let response = service.handle_thread_signal_request(
        peer(101),
        identity(thread),
        protocol::Header {
            opcode: protocol::OP_SIGNAL_THREAD_RAISE,
            ..Default::default()
        },
        &payload,
    );
    assert_eq!(response.header.status, protocol::STATUS_OK);
}

fn process_signal(service: &mut PosixService, signal: u32) {
    let mut payload = [0; protocol::SIGNAL_SEND_REQUEST_LEN];
    protocol::encode_signal_send_request(
        protocol::SignalSendRequest {
            selector: 101,
            signal,
        },
        &mut payload,
    )
    .unwrap();
    let response = service.handle(
        peer(101),
        protocol::Header {
            opcode: protocol::OP_SIGNAL_SEND,
            ..Default::default()
        },
        &payload,
    );
    assert_eq!(response.header.status, protocol::STATUS_OK);
}

#[test]
fn accepts_only_selected_signals_without_unblocking_or_async_delivery() {
    let mut service = fixture(bit(USR1) | bit(USR2));
    raise(&mut service, FIRST, USR1);
    raise(&mut service, FIRST, USR2);
    assert_eq!(
        service.try_wait_signal(peer(101), identity(FIRST), bit(USR2), 0),
        Ok(USR2)
    );
    assert_eq!(
        service.try_wait_signal(peer(101), identity(FIRST), bit(USR2), 0),
        Err(protocol::STATUS_EAGAIN)
    );
    assert_eq!(
        service.try_wait_signal(peer(101), identity(FIRST), bit(USR1), 0),
        Ok(USR1)
    );
    // A synchronous acceptance does not advance the async delivery epoch.
    assert_eq!(
        service.validate_wait_delivery_epoch(peer(101), identity(FIRST), 0),
        Ok(())
    );
    assert!(
        service
            .thread_signal_notification_threads()
            .next()
            .is_none()
    );
}

#[test]
fn never_steals_another_threads_private_pending_signal() {
    let mut service = fixture(bit(USR1));
    raise(&mut service, SECOND, USR1);
    assert_eq!(
        service.try_wait_signal(peer(101), identity(FIRST), bit(USR1), 0),
        Err(protocol::STATUS_EAGAIN)
    );
    assert_eq!(
        service.try_wait_signal(peer(101), identity(SECOND), bit(USR1), 0),
        Ok(USR1)
    );
}

#[test]
fn private_and_process_instances_are_separate_and_shared_instance_is_accepted_once() {
    let mut service = fixture(bit(USR1));
    process_signal(&mut service, USR1);
    raise(&mut service, FIRST, USR1);
    assert_eq!(
        service.try_wait_signal(peer(101), identity(FIRST), bit(USR1), 0),
        Ok(USR1)
    );
    assert_eq!(service.signal_state(101).unwrap().pending(), bit(USR1));
    assert_eq!(
        service.try_wait_signal(peer(101), identity(SECOND), bit(USR1), 0),
        Ok(USR1)
    );
    assert_eq!(
        service.try_wait_signal(peer(101), identity(FIRST), bit(USR1), 0),
        Err(protocol::STATUS_EAGAIN)
    );
}

#[test]
fn invalid_identity_or_mask_never_consumes_a_pending_signal() {
    let mut service = fixture(bit(USR1));
    raise(&mut service, FIRST, USR1);
    for (peer, sender, set, expected) in [
        (
            peer(102),
            identity(FIRST),
            bit(USR1),
            protocol::STATUS_EPERM,
        ),
        (peer(101), identity(0), bit(USR1), protocol::STATUS_EPERM),
        (peer(101), identity(999), bit(USR1), protocol::STATUS_ESRCH),
        (
            peer(101),
            identity(FIRST),
            bit(USR1) | bit(USR2),
            posix_service::STATUS_EINVAL,
        ),
    ] {
        assert_eq!(service.try_wait_signal(peer, sender, set, 0), Err(expected));
    }
    assert_eq!(
        service.try_wait_signal(peer(101), identity(FIRST), bit(USR1), 0),
        Ok(USR1)
    );
}

#[test]
fn interrupted_or_stale_wait_preserves_selected_signal_for_retry() {
    let mut service = fixture(bit(USR1));
    raise(&mut service, FIRST, USR1);
    assert_eq!(
        service.try_wait_signal(peer(101), identity(FIRST), bit(USR1), 1),
        Err(protocol::STATUS_EINTR)
    );
    raise(&mut service, FIRST, USR2);
    assert_eq!(
        service.try_wait_signal(peer(101), identity(FIRST), bit(USR1), 0),
        Err(protocol::STATUS_EINTR)
    );
    let response = service.handle_thread_signal_request(
        peer(101),
        identity(FIRST),
        protocol::Header {
            opcode: protocol::OP_SIGNAL_THREAD_DEQUEUE,
            ..Default::default()
        },
        &[],
    );
    let delivery = protocol::decode_signal_delivery(&response.payload).unwrap();
    assert_eq!(delivery.signal, USR2);
    assert_eq!(
        service.try_wait_signal(peer(101), identity(FIRST), bit(USR1), 0),
        Err(protocol::STATUS_EINTR)
    );
    assert_eq!(
        service.try_wait_signal(peer(101), identity(FIRST), bit(USR1), 1),
        Ok(USR1)
    );
}

#[test]
fn empty_and_uncatchable_only_sets_wait_without_consuming_other_signals() {
    let mut service = fixture(bit(USR1));
    process_signal(&mut service, USR1);
    for set in [0, bit(protocol::SIGNAL_KILL) | bit(protocol::SIGNAL_STOP)] {
        assert_eq!(
            service.try_wait_signal(peer(101), identity(FIRST), set, 0),
            Err(protocol::STATUS_EAGAIN)
        );
        assert_eq!(service.signal_state(101).unwrap().pending(), bit(USR1));
    }
    assert_eq!(
        service.try_wait_signal(
            peer(101),
            identity(FIRST),
            bit(USR1) | bit(protocol::SIGNAL_KILL),
            0
        ),
        Ok(USR1)
    );
}

#[test]
fn synchronous_acceptance_retains_authenticated_origin_and_consumes_it_once() {
    let mut service = fixture(bit(USR1));
    process_signal(&mut service, USR1);
    raise(&mut service, FIRST, USR1);
    for thread in [FIRST, SECOND] {
        let accepted = service
            .try_wait_signal_info(peer(101), identity(thread), bit(USR1), 0)
            .unwrap();
        assert_eq!(accepted.signal, USR1);
        assert_eq!(accepted.origin.source, protocol::signal_origin::USER);
        assert_eq!(
            (accepted.origin.process_id, accepted.origin.real_uid),
            (101, 501)
        );
    }
    for thread in [FIRST, SECOND] {
        assert_eq!(
            service.try_wait_signal_info(peer(101), identity(thread), bit(USR1), 0),
            Err(protocol::STATUS_EAGAIN)
        );
    }
    // No async handler token/epoch was manufactured to fetch provenance.
    assert_eq!(
        service.validate_wait_delivery_epoch(peer(101), identity(FIRST), 0),
        Ok(())
    );
}

#[test]
fn stale_wait_preserves_provenance_for_a_fresh_atomic_acceptance() {
    let mut service = fixture(bit(USR1));
    raise(&mut service, FIRST, USR1);
    assert_eq!(
        service.try_wait_signal_info(peer(101), identity(FIRST), bit(USR1), 1),
        Err(protocol::STATUS_EINTR)
    );
    let accepted = service
        .try_wait_signal_info(peer(101), identity(FIRST), bit(USR1), 0)
        .unwrap();
    assert_eq!(accepted.origin.process_id, 101);
    assert_eq!(accepted.origin.real_uid, 501);
}
