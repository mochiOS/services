//! Real service state and trusted native image observations; the FD/FileHandle
//! adapter has not yet published exec preparations on the wire.
use super::*;
use posix_service::record_lock::{FileKey, Kind, Range};

fn file(inode: u64) -> FileKey {
    FileKey { device: 7, inode }
}
fn setup(count: u64) -> (PosixService, Vec<PeerIdentity>, RecordingProcesses) {
    let root = PeerIdentity {
        process_id: 1,
        effective_uid: 0,
        effective_gid: 0,
    };
    let mut service = service_for(root);
    let mut peers = vec![root];
    let mut processes = RecordingProcesses::default();
    processes.states.insert(1, ProcessLifecycle::Running);
    for id in 2..=count {
        service
            .initialize_process(
                root,
                AuthenticatedProcess {
                    process_id: id,
                    handle: id as u32,
                },
                501,
                20,
                &[],
            )
            .unwrap();
        peers.push(service.registered_peer(id).unwrap());
        processes
            .states
            .insert(id as u32, ProcessLifecycle::Running);
    }
    (service, peers, processes)
}
fn lock(service: &mut PosixService, peer: PeerIdentity, file: FileKey) {
    service
        .record_locks(peer)
        .unwrap()
        .set(file, Kind::Read, Range::normalize(0, 0, 0).unwrap())
        .unwrap();
}
fn owner(service: &mut PosixService, observer: PeerIdentity, file: FileKey) -> Option<u64> {
    service
        .record_locks(observer)
        .unwrap()
        .conflict(file, Kind::Write, Range::normalize(0, 0, 0).unwrap())
        .map(|lock| lock.owner)
}
fn image(peer: PeerIdentity, revision: u64) -> mnu_abi::ProcessStatus {
    mnu_abi::ProcessStatus {
        process_id: peer.process_id,
        image_revision: revision,
        state: mnu_abi::PROCESS_STATE_RUNNING,
        ..Default::default()
    }
}

#[test]
fn preparing_and_same_image_observation_do_not_release_any_lock() {
    let (mut service, peers, mut processes) = setup(3);
    lock(&mut service, peers[0], file(1));
    let token = service
        .prepare_record_lock_exec(peers[0], &[file(1), file(1)])
        .unwrap()
        .unwrap();
    assert_eq!(owner(&mut service, peers[2], file(1)), Some(1));
    for _ in 0..3 {
        service
            .refresh_image_state(peers[0], &mut processes)
            .unwrap();
        assert_eq!(owner(&mut service, peers[2], file(1)), Some(1));
    }
    service.cancel_record_lock_exec(peers[0], token).unwrap();
    processes.images.insert(1, Ok(image(peers[0], 1)));
    service
        .refresh_image_state(peers[0], &mut processes)
        .unwrap();
    assert_eq!(
        owner(&mut service, peers[2], file(1)),
        Some(1),
        "a failed exec followed by unrelated successful exec cannot commit the cancelled plan"
    );
}

#[test]
fn committed_image_retires_selected_owner_files_only_and_consumes_the_plan_once() {
    let (mut service, peers, mut processes) = setup(3);
    for file in [file(1), file(2)] {
        lock(&mut service, peers[0], file);
    }
    lock(&mut service, peers[1], file(1));
    let token = service
        .prepare_record_lock_exec(peers[0], &[file(1), file(1)])
        .unwrap()
        .unwrap();
    processes.images.insert(1, Ok(image(peers[0], 2)));
    service
        .refresh_image_state(peers[0], &mut processes)
        .unwrap();
    assert_eq!(owner(&mut service, peers[2], file(1)), Some(2));
    assert_eq!(owner(&mut service, peers[2], file(2)), Some(1));
    assert_eq!(
        service.cancel_record_lock_exec(peers[0], token),
        Err(protocol::STATUS_ESRCH)
    );
    lock(&mut service, peers[0], file(1));
    for revision in [2, 3, 3] {
        processes.images.insert(1, Ok(image(peers[0], revision)));
        service
            .refresh_image_state(peers[0], &mut processes)
            .unwrap();
        assert_eq!(
            owner(&mut service, peers[2], file(1)),
            Some(1),
            "later observations must not replay the consumed plan"
        );
    }
}

#[test]
fn cancellation_is_owner_bound_and_old_tokens_cannot_erase_new_preparations() {
    let (mut service, peers, _) = setup(3);
    lock(&mut service, peers[0], file(1));
    let old = service
        .prepare_record_lock_exec(peers[0], &[file(1)])
        .unwrap()
        .unwrap();
    assert_eq!(
        service.prepare_record_lock_exec(peers[0], &[file(1)]),
        Err(protocol::STATUS_EAGAIN)
    );
    assert_eq!(
        service.cancel_record_lock_exec(peers[1], old),
        Err(protocol::STATUS_ESRCH)
    );
    service.cancel_record_lock_exec(peers[0], old).unwrap();
    let fresh = service
        .prepare_record_lock_exec(peers[0], &[file(1)])
        .unwrap()
        .unwrap();
    assert_ne!(old, fresh);
    assert_eq!(
        service.cancel_record_lock_exec(peers[0], old),
        Err(protocol::STATUS_ESRCH)
    );
    assert_eq!(
        service.prepare_record_lock_exec(peers[0], &[file(1)]),
        Err(protocol::STATUS_EAGAIN)
    );
    service.cancel_record_lock_exec(peers[0], fresh).unwrap();
    assert_eq!(owner(&mut service, peers[2], file(1)), Some(1));
}

#[test]
fn missing_foreign_and_unlocked_files_do_not_create_a_preparation_or_grant_authority() {
    let (mut service, peers, _) = setup(3);
    lock(&mut service, peers[0], file(1));
    for files in [&[][..], &[file(2)][..], &[file(1), file(2)][..]] {
        assert_eq!(service.prepare_record_lock_exec(peers[1], files), Ok(None));
    }
    let forged = PeerIdentity {
        process_id: 9999,
        effective_uid: 0,
        effective_gid: 0,
    };
    assert_eq!(
        service.prepare_record_lock_exec(forged, &[file(1)]),
        Err(protocol::STATUS_ESRCH)
    );
    assert_eq!(owner(&mut service, peers[2], file(1)), Some(1));
}

#[test]
fn failed_or_malformed_native_observation_keeps_preparations_and_locks_intact() {
    for fault in 0..6 {
        let (mut service, peers, mut processes) = setup(3);
        processes.images.insert(1, Ok(image(peers[0], 5)));
        service
            .refresh_image_state(peers[0], &mut processes)
            .unwrap();
        lock(&mut service, peers[0], file(1));
        let token = service
            .prepare_record_lock_exec(peers[0], &[file(1)])
            .unwrap()
            .unwrap();
        let mut invalid = image(peers[0], 6);
        let expected = match fault {
            0 => protocol::STATUS_EIO,
            1 => {
                invalid.process_id = 2;
                protocol::STATUS_EIO
            }
            2 => {
                invalid.reserved = 1;
                protocol::STATUS_EIO
            }
            3 => {
                invalid.state = 99;
                protocol::STATUS_EIO
            }
            4 => {
                invalid.image_revision = 4;
                protocol::STATUS_EIO
            }
            _ => {
                invalid.state = mnu_abi::PROCESS_STATE_EXITED;
                protocol::STATUS_ESRCH
            }
        };
        processes.images.insert(
            1,
            if fault == 0 {
                Err(expected)
            } else {
                Ok(invalid)
            },
        );
        assert_eq!(
            service.refresh_image_state(peers[0], &mut processes),
            Err(expected)
        );
        assert_eq!(owner(&mut service, peers[2], file(1)), Some(1));
        service.cancel_record_lock_exec(peers[0], token).unwrap();
        processes.images.insert(1, Ok(image(peers[0], 6)));
        service
            .refresh_image_state(peers[0], &mut processes)
            .unwrap();
        assert_eq!(owner(&mut service, peers[2], file(1)), Some(1));
    }
}

#[test]
fn fork_child_has_no_parent_preparation_and_cannot_commit_it_by_executing() {
    let (mut service, peers, mut processes) = setup(2);
    let mut fs = RecordingFilesystem::default();
    lock(&mut service, peers[0], file(1));
    let plan = service
        .prepare_record_lock_exec(peers[0], &[file(1)])
        .unwrap()
        .unwrap();
    let fork = service.prepare_fork(peers[0], &mut fs).unwrap();
    service
        .commit_fork(
            peers[0],
            fork,
            AuthenticatedProcess {
                process_id: 3,
                handle: 3,
            },
        )
        .unwrap();
    let child = service.registered_peer(3).unwrap();
    assert_eq!(
        service.cancel_record_lock_exec(child, plan),
        Err(protocol::STATUS_ESRCH)
    );
    processes.images.insert(3, Ok(image(child, 1)));
    service.refresh_image_state(child, &mut processes).unwrap();
    assert_eq!(owner(&mut service, peers[1], file(1)), Some(1));
    service.cancel_record_lock_exec(peers[0], plan).unwrap();
}

#[test]
fn prepared_owner_remains_exit_observable_after_unlock_and_exit_discards_the_plan() {
    let (mut service, peers, mut processes) = setup(2);
    lock(&mut service, peers[0], file(1));
    let plan = service
        .prepare_record_lock_exec(peers[0], &[file(1)])
        .unwrap()
        .unwrap();
    service
        .record_locks(peers[0])
        .unwrap()
        .release_file(file(1));
    assert!(service.child_lifecycle_handles().contains(&1));
    processes
        .states
        .insert(1, ProcessLifecycle::Exited { exit_code: 0 });
    service
        .refresh_child_exit_notifications(&mut processes)
        .unwrap();
    assert!(!service.child_lifecycle_handles().contains(&1));
    assert_eq!(
        service.cancel_record_lock_exec(peers[1], plan),
        Err(protocol::STATUS_ESRCH)
    );
    assert_eq!(
        service.prepare_record_lock_exec(peers[0], &[file(1)]),
        Err(protocol::STATUS_ESRCH)
    );
}

#[test]
fn global_preparation_quota_is_bounded_atomic_and_recovers_after_cancellation() {
    let limit = posix_service::record_lock_exec::MAX_PREPARATIONS;
    let (mut service, peers, _) = setup(limit as u64 + 1);
    let mut tokens = Vec::new();
    for &peer in &peers[..limit] {
        lock(&mut service, peer, file(peer.process_id));
        tokens.push(
            service
                .prepare_record_lock_exec(peer, &[file(peer.process_id)])
                .unwrap()
                .unwrap(),
        );
    }
    let last = peers[limit];
    lock(&mut service, last, file(last.process_id));
    assert_eq!(
        service.prepare_record_lock_exec(last, &[file(last.process_id)]),
        Err(protocol::STATUS_EAGAIN)
    );
    assert_eq!(
        owner(&mut service, peers[0], file(last.process_id)),
        Some(last.process_id)
    );
    service
        .cancel_record_lock_exec(peers[0], tokens[0])
        .unwrap();
    let fresh = service
        .prepare_record_lock_exec(last, &[file(last.process_id)])
        .unwrap()
        .unwrap();
    assert!(!tokens.contains(&fresh));
    assert_eq!(
        service.cancel_record_lock_exec(last, tokens[0]),
        Err(protocol::STATUS_ESRCH)
    );
    service.cancel_record_lock_exec(last, fresh).unwrap();
}
