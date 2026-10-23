use super::*;
use posix_service::{
    record_lock::{FileKey, Kind, Range},
    record_lock_exec_request::{finish, inspect},
};
use protocol::record_lock_exec as wire;

fn key(inode: u64) -> FileKey {
    FileKey { device: 1, inode }
}
fn lock(service: &mut PosixService, peer: PeerIdentity, inode: u64) {
    service
        .record_locks(peer)
        .unwrap()
        .set(key(inode), Kind::Read, Range::normalize(0, 0, 0).unwrap())
        .unwrap();
}
fn locked(service: &mut PosixService, observer: PeerIdentity, inode: u64) -> bool {
    service
        .record_locks(observer)
        .unwrap()
        .conflict(key(inode), Kind::Write, Range::normalize(0, 0, 0).unwrap())
        .is_some()
}
fn object(handle: u32) -> AttachedObject<u32> {
    AttachedObject {
        handle,
        rights: mnu_abi::HANDLE_RIGHT_TRANSFER,
    }
}
fn pending(
    request: wire::Request,
    files: &[AttachedObject<u32>],
    fs: &mut RecordingFilesystem,
) -> posix_service::record_lock_exec_request::Pending {
    let mut bytes = [0; wire::LEN];
    wire::encode(request, &mut bytes).unwrap();
    inspect(
        protocol::Header {
            opcode: protocol::OP_RECORD_LOCK_EXEC,
            request_id: 99,
            payload_len: wire::LEN as u32,
            ..Default::default()
        },
        &bytes,
        files,
        fs,
    )
}
fn token(reply: posix_service::ObjectResponse<u32>) -> u64 {
    assert_eq!(reply.response.header.status, 0);
    assert_eq!(reply.response.header.request_id, 99);
    assert!(reply.handles.is_empty());
    wire::decode_reply(&reply.response.payload).unwrap()
}
fn status(fs: &mut RecordingFilesystem, handle: u32, inode: u64) {
    fs.stat_statuses.insert(
        handle,
        Ok(protocol::FileStatus {
            inode,
            ..sample_status()
        }),
    );
}

#[test]
fn batches_identify_only_attached_files_and_do_not_release_until_native_commit() {
    let (mut service, observer, peer, _, mut fs, mut processes) = orphan_family();
    for inode in [9, 10, 11, 12] {
        lock(&mut service, peer, inode);
    }
    for (handle, inode) in [(71, 9), (72, 10), (73, 11)] {
        status(&mut fs, handle, inode);
    }
    let retained = fs.retained.len();
    let observed = pending(
        wire::Request::Prepare(0),
        &[object(71), object(72)],
        &mut fs,
    );
    let first = token(finish(&mut service, peer, observed, Ok(())));
    assert_ne!(first, 0);
    let observed = pending(
        wire::Request::Prepare(first),
        &[object(73), object(71)],
        &mut fs,
    );
    assert_eq!(token(finish(&mut service, peer, observed, Ok(()))), first);
    assert_eq!(fs.stat_file, Some(object(71)));
    assert_eq!(
        fs.retained.len(),
        retained,
        "existing lock pins suffice; incoming references remain receive-owned"
    );
    assert!(fs.released.is_empty());
    assert_eq!(
        service.refresh_record_lock_execs(&mut processes, None),
        Ok(0)
    );
    for inode in [9, 10, 11, 12] {
        assert!(locked(&mut service, observer, inode));
    }
    processes.images.insert(
        141,
        Ok(mnu_abi::ProcessStatus {
            process_id: peer.process_id,
            image_revision: 1,
            state: mnu_abi::PROCESS_STATE_RUNNING,
            ..Default::default()
        }),
    );
    assert_eq!(
        service.refresh_record_lock_execs(&mut processes, Some(key(11))),
        Ok(1)
    );
    for inode in [9, 10, 11] {
        assert!(!locked(&mut service, observer, inode));
    }
    assert!(locked(&mut service, observer, 12));
    assert!(!service.has_record_lock_execs());
}

#[test]
fn failed_batch_and_rejected_image_cannot_extend_a_preparation() {
    for observation_failure in [false, true] {
        let (mut service, observer, peer, _, mut fs, mut processes) = orphan_family();
        for inode in [9, 10, 11] {
            lock(&mut service, peer, inode);
        }
        for (handle, inode) in [(71, 9), (72, 10), (73, 11)] {
            status(&mut fs, handle, inode);
        }
        let observed = pending(wire::Request::Prepare(0), &[object(71)], &mut fs);
        let first = token(finish(&mut service, peer, observed, Ok(())));
        if observation_failure {
            fs.stat_statuses.insert(73, Err(protocol::STATUS_EIO));
        }
        let observed = pending(
            wire::Request::Prepare(first),
            &[object(72), object(73)],
            &mut fs,
        );
        let validation = if observation_failure {
            Ok(())
        } else {
            Err(protocol::STATUS_ESRCH)
        };
        let reply = finish(&mut service, peer, observed, validation);
        assert_eq!(
            reply.response.header.status,
            if observation_failure {
                protocol::STATUS_EIO
            } else {
                protocol::STATUS_ESRCH
            }
        );
        processes.images.insert(
            141,
            Ok(mnu_abi::ProcessStatus {
                process_id: peer.process_id,
                image_revision: 1,
                state: mnu_abi::PROCESS_STATE_RUNNING,
                ..Default::default()
            }),
        );
        assert_eq!(
            service.refresh_record_lock_execs(&mut processes, None),
            Ok(1)
        );
        assert!(!locked(&mut service, observer, 9));
        for inode in [10, 11] {
            assert!(locked(&mut service, observer, inode));
        }
    }
}

#[test]
fn cancellation_is_owner_bound_and_keeps_locks_after_a_failed_exec() {
    let (mut service, observer, peer, other, mut fs, mut processes) = orphan_family();
    lock(&mut service, peer, 9);
    let observed = pending(wire::Request::Prepare(0), &[object(71)], &mut fs);
    let first = token(finish(&mut service, peer, observed, Ok(())));
    let observed = pending(wire::Request::Cancel(first), &[], &mut fs);
    assert_eq!(
        finish(&mut service, other, observed, Ok(()))
            .response
            .header
            .status,
        protocol::STATUS_ESRCH
    );
    let observed = pending(wire::Request::Cancel(first), &[], &mut fs);
    assert_eq!(token(finish(&mut service, peer, observed, Ok(()))), 0);
    processes.images.insert(
        141,
        Ok(mnu_abi::ProcessStatus {
            process_id: peer.process_id,
            image_revision: 1,
            state: mnu_abi::PROCESS_STATE_RUNNING,
            ..Default::default()
        }),
    );
    service.refresh_image_state(peer, &mut processes).unwrap();
    assert!(locked(&mut service, observer, 9));
}

#[test]
fn malformed_envelopes_and_missing_transfer_rights_never_reach_the_provider() {
    let (mut service, _, peer, _, _, _) = orphan_family();
    for case in 0..8 {
        let mut fs = RecordingFilesystem {
            query_hook: Some(Box::new(|| panic!("invalid request reached fstat"))),
            ..Default::default()
        };
        let mut header = protocol::Header {
            opcode: protocol::OP_RECORD_LOCK_EXEC,
            payload_len: wire::LEN as u32,
            ..Default::default()
        };
        let mut payload = [0; wire::LEN];
        wire::encode(wire::Request::Prepare(0), &mut payload).unwrap();
        let mut files = vec![object(71)];
        let expected = match case {
            0 => {
                header.flags = 1;
                -22
            }
            1 => {
                header.status = -1;
                -22
            }
            2 => {
                header.payload_len -= 1;
                -22
            }
            3 => {
                payload[6] = 1;
                -22
            }
            4 => {
                files.clear();
                -22
            }
            5 => {
                files.resize(mnu_abi::IPC_MAX_OBJECT_HANDLES + 1, object(71));
                -22
            }
            6 => {
                wire::encode(wire::Request::Cancel(1), &mut payload).unwrap();
                -22
            }
            _ => {
                files[0].rights = mnu_abi::HANDLE_RIGHT_READ;
                -13
            }
        };
        let observed = inspect(header, &payload, &files, &mut fs);
        assert_eq!(
            finish(&mut service, peer, observed, Ok(()))
                .response
                .header
                .status,
            expected
        );
    }
}

#[test]
fn a_faulty_prepared_owner_does_not_block_unrelated_file_queries_or_independent_commits() {
    let (mut service, observer, first, second, mut fs, mut processes) = orphan_family();
    for (peer, inode, handle) in [(first, 9, 71), (second, 10, 72)] {
        lock(&mut service, peer, inode);
        status(&mut fs, handle, inode);
        let observed = pending(wire::Request::Prepare(0), &[object(handle)], &mut fs);
        assert_ne!(token(finish(&mut service, peer, observed, Ok(()))), 0);
    }
    processes.images.insert(141, Err(protocol::STATUS_EIO));
    processes.images.insert(
        142,
        Ok(mnu_abi::ProcessStatus {
            process_id: second.process_id,
            image_revision: 1,
            state: mnu_abi::PROCESS_STATE_RUNNING,
            ..Default::default()
        }),
    );
    assert_eq!(
        service.refresh_record_lock_execs(&mut processes, Some(key(10))),
        Ok(1)
    );
    assert_eq!(
        service.refresh_record_lock_execs(&mut processes, Some(key(99))),
        Ok(0)
    );
    assert!(locked(&mut service, observer, 9));
    assert!(!locked(&mut service, observer, 10));
    assert_eq!(
        service.refresh_record_lock_execs(&mut processes, Some(key(9))),
        Err(protocol::STATUS_EIO)
    );
    assert!(locked(&mut service, observer, 9));
    processes.images.insert(
        141,
        Ok(mnu_abi::ProcessStatus {
            process_id: first.process_id,
            image_revision: 1,
            state: mnu_abi::PROCESS_STATE_RUNNING,
            ..Default::default()
        }),
    );
    assert_eq!(
        service.refresh_record_lock_execs(&mut processes, None),
        Ok(1)
    );
    assert!(!locked(&mut service, observer, 9));
}
