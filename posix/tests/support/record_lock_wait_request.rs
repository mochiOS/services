use super::*;
use posix_service::record_lock_wait::{Completion, Token};
use posix_service::record_lock_wait_request::{finish, inspect};
use protocol::{record_lock as locks, record_lock_wait as wire};

fn request() -> locks::Request {
    locks::Request {
        operation: locks::Operation::Set(locks::Kind::Write),
        origin: locks::Origin::Start,
        start: 10,
        length: 20,
    }
}
fn identity(peer: PeerIdentity) -> mnu_abi::ExecutionIdentity {
    mnu_abi::ExecutionIdentity {
        process_id: peer.process_id,
        thread_id: peer.process_id,
    }
}
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
fn pending(
    fs: &mut RecordingFilesystem,
    request: locks::Request,
    epoch: u64,
    rights: u64,
) -> posix_service::record_lock_wait_request::Pending<u32> {
    let mut payload = [0; wire::LEN];
    wire::encode(
        wire::Request {
            lock: request,
            epoch,
        },
        &mut payload,
    )
    .unwrap();
    inspect(
        protocol::Header {
            opcode: protocol::OP_RECORD_LOCK_WAIT,
            payload_len: wire::LEN as u32,
            ..Default::default()
        },
        &payload,
        &[AttachedObject { handle: 71, rights }],
        fs,
        |_| Ok(100),
    )
}

#[test]
fn deferred_admission_reuses_file_authority_and_pins_only_a_successful_reply() {
    let (mut service, _, first, second, mut fs, _) = orphan_family();
    let before = fs.retained.len();
    let epoch = epoch(&mut service, first);
    let request = request();
    for delivered in [false, true] {
        let prepared = pending(&mut fs, request, epoch, locks::required_rights(request));
        let (result, retained) = finish(
            &mut service,
            first,
            identity(first),
            prepared,
            Ok(()),
            &mut fs,
            || delivered,
        );
        assert_eq!(
            result,
            Ok(if delivered {
                Completion::Replied
            } else {
                Completion::Undelivered
            })
        );
        assert_eq!(retained, delivered.then_some(71));
        let status = sample_status();
        assert_eq!(
            service
                .record_locks(second)
                .unwrap()
                .conflict(
                    posix_service::record_lock::FileKey {
                        device: status.device,
                        inode: status.inode
                    },
                    locks::Kind::Read,
                    posix_service::record_lock::Range::normalize(0, 10, 20).unwrap()
                )
                .is_some(),
            delivered
        );
    }
    assert_eq!(
        fs.retained.len(),
        before,
        "no duplicate/control authority requested"
    );
    assert_eq!(fs.stat_file.unwrap().rights, mnu_abi::HANDLE_RIGHT_TRANSFER);
}

#[test]
fn blocked_admission_defers_reply_and_cancellation_releases_the_final_file_pin() {
    let (mut service, _, first, second, mut fs, _) = orphan_family();
    let epoch1 = epoch(&mut service, first);
    let epoch2 = epoch(&mut service, second);
    let lock = request();
    let first_request = pending(&mut fs, lock, epoch1, u64::MAX);
    assert_eq!(
        finish(
            &mut service,
            first,
            identity(first),
            first_request,
            Ok(()),
            &mut fs,
            || true
        )
        .0,
        Ok(Completion::Replied)
    );
    let second_request = pending(&mut fs, lock, epoch2, u64::MAX);
    let Completion::Pending(token) = finish(
        &mut service,
        second,
        identity(second),
        second_request,
        Ok(()),
        &mut fs,
        || panic!("blocked request must not reply"),
    )
    .0
    .unwrap() else {
        panic!()
    };
    let status = sample_status();
    service
        .record_locks(first)
        .unwrap()
        .release_file(posix_service::record_lock::FileKey {
            device: status.device,
            inode: status.inode,
        });
    service.release_unused_record_lock_files(&mut fs);
    assert!(fs.released.is_empty());
    assert_eq!(
        service.retry_record_lock_wait_with_reply(second, token, || false),
        Ok(Completion::Undelivered)
    );
    service.release_unused_record_lock_files(&mut fs);
    assert_eq!(fs.released.len(), 1);
    assert_eq!(
        service.cancel_record_lock_wait(second, token),
        Err(protocol::STATUS_ESRCH)
    );
    assert!(Token::from_raw(token.as_raw()).is_some());
}

#[test]
fn stale_epoch_foreign_identity_and_image_failure_never_invoke_the_success_reply() {
    for fault in 0..3 {
        let (mut service, _, first, second, mut fs, _) = orphan_family();
        let current = epoch(&mut service, first);
        let stale = if fault == 0 {
            current.wrapping_add(1)
        } else {
            current
        };
        let prepared = pending(&mut fs, request(), stale, u64::MAX);
        let (result, retained) = finish(
            &mut service,
            first,
            identity(if fault == 1 { second } else { first }),
            prepared,
            if fault == 2 { Err(-5) } else { Ok(()) },
            &mut fs,
            || panic!("must validate before publication"),
        );
        assert_eq!(
            result,
            Err(match fault {
                0 => protocol::STATUS_EINTR,
                1 => protocol::STATUS_EPERM,
                _ => -5,
            })
        );
        assert_eq!(retained, None);
        assert!(fs.released.is_empty());
    }
}

#[test]
fn malformed_envelope_or_missing_rights_cannot_mutate_or_reply() {
    let (mut service, _, first, _, mut fs, _) = orphan_family();
    let current = epoch(&mut service, first);
    let prepared = pending(&mut fs, request(), current, mnu_abi::HANDLE_RIGHT_TRANSFER);
    assert_eq!(
        finish(
            &mut service,
            first,
            identity(first),
            prepared,
            Ok(()),
            &mut fs,
            || panic!()
        )
        .0,
        Err(-13)
    );
    let mut payload = [0; wire::LEN];
    wire::encode(
        wire::Request {
            lock: request(),
            epoch: current,
        },
        &mut payload,
    )
    .unwrap();
    for fault in 0..5 {
        let mut header = protocol::Header {
            opcode: protocol::OP_RECORD_LOCK_WAIT,
            payload_len: wire::LEN as u32,
            ..Default::default()
        };
        match fault {
            0 => header.opcode = protocol::OP_RECORD_LOCK,
            1 => header.flags = 1,
            2 => header.status = -5,
            3 => header.payload_len -= 1,
            _ => payload[7] = 1,
        }
        let prepared = inspect(header, &payload, &[], &mut fs, |_| panic!());
        assert_eq!(
            finish(
                &mut service,
                first,
                identity(first),
                prepared,
                Ok(()),
                &mut fs,
                || panic!()
            )
            .0,
            Err(STATUS_EINVAL)
        );
    }
}
