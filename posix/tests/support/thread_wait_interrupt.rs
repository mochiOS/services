use super::*;
use posix_service::thread_wait_interrupt::{finish, inspect};

fn epoch(service: &mut PosixService, peer: PeerIdentity) -> u64 {
    let mut mask = [0; protocol::SIGNAL_THREAD_MASK_LEN];
    protocol::encode_signal_mask_request(
        protocol::SignalMaskRequest {
            operation: protocol::SIGNAL_MASK_INITIALIZE,
            mask: 0,
        },
        &mut mask,
    )
    .unwrap();
    assert_eq!(
        thread_signal_request(service, peer, protocol::OP_SIGNAL_THREAD_MASK, &mask)
            .header
            .status,
        0
    );
    let response = thread_signal_request(service, peer, protocol::OP_SIGNAL_THREAD_EPOCH, &[]);
    assert_eq!(response.header.status, 0);
    protocol::decode_signal_mask(&response.payload).unwrap()
}
fn header() -> protocol::Header {
    protocol::Header {
        opcode: protocol::OP_THREAD_WAIT_INTERRUPT,
        request_id: 93,
        ..Default::default()
    }
}
fn object() -> AttachedObject<u32> {
    AttachedObject {
        handle: 71,
        rights: protocol::THREAD_WAIT_INTERRUPT_RIGHTS,
    }
}
fn status(peer: PeerIdentity) -> mnu_abi::ThreadStatus {
    mnu_abi::ThreadStatus {
        process_id: peer.process_id,
        thread_id: peer.process_id,
        state: mnu_abi::THREAD_STATE_BLOCKED,
        reserved: 0,
    }
}

#[test]
fn delegated_thread_interrupt_closes_registration_race_without_an_app_signal() {
    let (mut service, _, peer, _, _, _) = orphan_family();
    let before = epoch(&mut service, peer);
    let identity = mnu_abi::ExecutionIdentity {
        process_id: peer.process_id,
        thread_id: peer.process_id,
    };
    assert_eq!(
        service.validate_wait_delivery_epoch(peer, identity, before),
        Ok(())
    );
    let pending = inspect(peer, header(), &[], &[object()], |handle| {
        assert_eq!(handle, 71);
        Ok(status(peer))
    });
    let response = finish(&mut service, peer, pending, Ok(()));
    assert_eq!(
        (
            response.response.header.status,
            response.response.header.request_id
        ),
        (0, 93)
    );
    assert!(response.handles.is_empty() && response.response.payload.is_empty());
    assert_eq!(
        service.validate_wait_delivery_epoch(peer, identity, before),
        Err(protocol::STATUS_EINTR)
    );
    assert_eq!(epoch(&mut service, peer), before + 1);
    assert_eq!(service.signal_state(peer.process_id).unwrap().pending(), 0);
}

#[test]
fn foreign_dead_malformed_and_unobserved_targets_cannot_advance_epoch() {
    let (mut service, _, peer, other, _, _) = orphan_family();
    let before = epoch(&mut service, peer);
    for fault in 0..7 {
        let mut value = status(peer);
        let expected = match fault {
            0 => {
                value.process_id = other.process_id;
                protocol::STATUS_EPERM
            }
            1 => {
                value.thread_id = 0;
                protocol::STATUS_EPERM
            }
            2 => {
                value.state = mnu_abi::THREAD_STATE_TERMINATED;
                protocol::STATUS_ESRCH
            }
            3 => {
                value.state = 0;
                protocol::STATUS_EIO
            }
            4 => {
                value.reserved = 1;
                protocol::STATUS_EIO
            }
            5 => -5,
            _ => {
                value.thread_id += 100;
                protocol::STATUS_ESRCH
            }
        };
        let pending = inspect(peer, header(), &[], &[object()], |_| {
            if fault == 5 { Err(-5) } else { Ok(value) }
        });
        assert_eq!(
            finish(&mut service, peer, pending, Ok(()))
                .response
                .header
                .status,
            expected
        );
        assert_eq!(epoch(&mut service, peer), before);
    }
    let pending = inspect(peer, header(), &[], &[object()], |_| Ok(status(peer)));
    assert_eq!(
        finish(&mut service, peer, pending, Err(-5))
            .response
            .header
            .status,
        -5
    );
    assert_eq!(epoch(&mut service, peer), before);
    let pending = inspect(peer, header(), &[], &[object()], |_| Ok(status(peer)));
    assert_eq!(
        finish(&mut service, other, pending, Ok(()))
            .response
            .header
            .status,
        protocol::STATUS_EPERM
    );
    assert_eq!(epoch(&mut service, peer), before);
}

#[test]
fn malformed_envelope_and_missing_wait_transfer_authority_do_not_observe_native_objects() {
    let (mut service, _, peer, _, _, _) = orphan_family();
    epoch(&mut service, peer);
    for right in [mnu_abi::HANDLE_RIGHT_WAIT, mnu_abi::HANDLE_RIGHT_TRANSFER] {
        let mut source = object();
        source.rights &= !right;
        let pending = inspect(peer, header(), &[], &[source], |_| {
            panic!("authority preflight")
        });
        assert_eq!(
            finish(&mut service, peer, pending, Ok(()))
                .response
                .header
                .status,
            -13
        );
    }
    for fault in 0..5 {
        let mut header = header();
        match fault {
            0 => header.flags = 1,
            1 => header.status = -5,
            2 => header.payload_len = 1,
            3 => header.opcode = protocol::OP_RECORD_LOCK_WAIT,
            _ => {}
        }
        let handles = if fault == 4 { &[][..] } else { &[object()][..] };
        let pending = inspect(peer, header, &[], handles, |_| panic!("envelope preflight"));
        assert_eq!(
            finish(&mut service, peer, pending, Ok(()))
                .response
                .header
                .status,
            STATUS_EINVAL
        );
    }
}
