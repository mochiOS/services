use super::*;
use posix_service::record_lock_request::{finish, inspect};
use protocol::record_lock::{self as wire, Kind, Operation, Origin, Reply, Request};

fn request(operation: Operation) -> Request {
    Request {
        operation,
        origin: Origin::Start,
        start: 0,
        length: 0,
    }
}
fn object(handle: u32, request: Request) -> AttachedObject<u32> {
    AttachedObject {
        handle,
        rights: wire::required_rights(request),
    }
}
fn pending(
    request: Request,
    objects: &[AttachedObject<u32>],
    fs: &mut RecordingFilesystem,
) -> posix_service::record_lock_request::Pending<u32> {
    let mut bytes = [0; wire::REQUEST_LEN];
    wire::encode_request(request, &mut bytes).unwrap();
    inspect(
        protocol::Header {
            opcode: protocol::OP_RECORD_LOCK,
            request_id: 99,
            payload_len: bytes.len() as u32,
            ..Default::default()
        },
        &bytes,
        objects,
        fs,
        |_| Ok(100),
    )
}
fn result(response: &posix_service::ObjectResponse<u32>) -> Reply {
    assert_eq!(response.response.header.status, 0);
    assert_eq!(response.response.header.request_id, 99);
    assert!(response.handles.is_empty());
    wire::decode_reply(&response.response.payload).unwrap()
}

#[test]
fn one_received_reference_pins_a_file_across_owners_and_releases_after_the_last_unlock() {
    let (mut service, _, first, second, mut fs, _) = orphan_family();
    let read = request(Operation::Set(Kind::Read));
    let retained_count = fs.retained.len();
    let transfer = mnu_abi::HANDLE_RIGHT_TRANSFER;
    for (peer, handle, retained) in [(first, 71, Some(71)), (first, 72, None), (second, 73, None)] {
        let incoming = object(handle, read);
        let observed = pending(read, &[incoming], &mut fs);
        assert_eq!(
            fs.stat_file,
            Some(AttachedObject {
                handle,
                rights: transfer
            })
        );
        let (response, owned) = finish(&mut service, peer, observed, Ok(()), &mut fs);
        assert_eq!(result(&response), Reply::Done);
        assert_eq!(owned, retained);
        assert_eq!(
            fs.retained.len(),
            retained_count,
            "no DUPLICATE authority requested"
        );
        assert!(fs.released.is_empty());
    }
    let release = request(Operation::ReleaseFile);
    for peer in [first, second] {
        let observed = pending(release, &[object(74, release)], &mut fs);
        let (response, owned) = finish(&mut service, peer, observed, Ok(()), &mut fs);
        assert_eq!(result(&response), Reply::Done);
        assert_eq!(owned, None);
        if peer == first {
            assert!(fs.released.is_empty());
        }
    }
    assert_eq!(fs.released, [object(71, read)]);
    service.release_unused_record_lock_files(&mut fs);
    assert_eq!(
        fs.released.len(),
        1,
        "exactly one service reference retired"
    );
}

#[test]
fn pending_lock_keeps_the_inode_pin_until_cancel_exec_or_native_exit() {
    use posix_service::record_lock_wait::Outcome;
    for retirement in 0..3 {
        let (mut service, _, first, second, mut fs, mut processes) = orphan_family();
        let write = request(Operation::Set(Kind::Write));
        let observed = pending(write, &[object(71, write)], &mut fs);
        assert_eq!(
            finish(&mut service, first, observed, Ok(()), &mut fs).1,
            Some(71)
        );
        let status = sample_status();
        let file = posix_service::record_lock::FileKey {
            device: status.device,
            inode: status.inode,
        };
        let range = posix_service::record_lock::Range::normalize(0, 0, 0).unwrap();
        let Outcome::Pending(token) = service
            .begin_record_lock_wait(second, file, Kind::Read, range)
            .unwrap()
        else {
            panic!()
        };
        service.record_locks(first).unwrap().release_file(file);
        service.release_unused_record_lock_files(&mut fs);
        assert!(
            fs.released.is_empty(),
            "waiting still pins the unlinked inode"
        );
        match retirement {
            0 => service.cancel_record_lock_wait(second, token).unwrap(),
            1 => {
                processes.images.insert(
                    142,
                    Ok(mnu_abi::ProcessStatus {
                        process_id: second.process_id,
                        image_revision: 1,
                        state: mnu_abi::PROCESS_STATE_RUNNING,
                        ..Default::default()
                    }),
                );
                service.refresh_image_state(second, &mut processes).unwrap();
            }
            _ => {
                processes
                    .states
                    .insert(142, ProcessLifecycle::Exited { exit_code: 0 });
                // Parent image failure cannot prevent the child's retirement.
                processes.images.insert(141, Err(protocol::STATUS_EIO));
                assert_eq!(
                    service.refresh_child_exit_notifications(&mut processes),
                    Err(protocol::STATUS_EIO)
                );
            }
        }
        service.release_unused_record_lock_files(&mut fs);
        assert_eq!(
            fs.released
                .iter()
                .filter(|item| **item == object(71, write))
                .count(),
            1
        );
        service.release_unused_record_lock_files(&mut fs);
        assert_eq!(
            fs.released
                .iter()
                .filter(|item| **item == object(71, write))
                .count(),
            1
        );
    }
}

#[test]
fn acquiring_a_pending_lock_hands_pin_lifetime_to_the_new_owner() {
    use posix_service::record_lock_wait::Outcome;
    let (mut service, _, first, second, mut fs, _) = orphan_family();
    let write = request(Operation::Set(Kind::Write));
    let observed = pending(write, &[object(71, write)], &mut fs);
    assert_eq!(
        finish(&mut service, first, observed, Ok(()), &mut fs).1,
        Some(71)
    );
    let status = sample_status();
    let file = posix_service::record_lock::FileKey {
        device: status.device,
        inode: status.inode,
    };
    let range = posix_service::record_lock::Range::normalize(0, 0, 0).unwrap();
    let Outcome::Pending(token) = service
        .begin_record_lock_wait(second, file, Kind::Read, range)
        .unwrap()
    else {
        panic!()
    };
    service.record_locks(first).unwrap().release_file(file);
    assert_eq!(
        service.retry_record_lock_wait(second, token),
        Ok(Outcome::Acquired)
    );
    service.release_unused_record_lock_files(&mut fs);
    assert!(fs.released.is_empty());
    service.record_locks(second).unwrap().release_file(file);
    service.release_unused_record_lock_files(&mut fs);
    assert_eq!(fs.released, [object(71, write)]);
}

#[test]
fn insufficient_delegation_and_malformed_frames_never_reach_the_filesystem() {
    let (mut service, _, peer, _, _, _) = orphan_family();
    let write = request(Operation::Set(Kind::Write));
    let mut bytes = [0; wire::REQUEST_LEN];
    wire::encode_request(write, &mut bytes).unwrap();
    let valid = protocol::Header {
        opcode: protocol::OP_RECORD_LOCK,
        payload_len: bytes.len() as u32,
        ..Default::default()
    };
    for case in 0..7 {
        let mut fs = RecordingFilesystem {
            query_hook: Some(Box::new(|| panic!("unadmitted file observation"))),
            ..Default::default()
        };
        let mut header = valid;
        let mut payload = bytes;
        let mut objects = vec![object(71, write)];
        let expected = match case {
            0 => {
                objects.clear();
                -22
            }
            1 => {
                objects.push(objects[0]);
                -22
            }
            2 => {
                header.flags = 1;
                -22
            }
            3 => {
                header.status = -1;
                -22
            }
            4 => {
                header.payload_len -= 1;
                -22
            }
            5 => {
                payload[7] = 1;
                -22
            }
            _ => {
                objects[0].rights = mnu_abi::HANDLE_RIGHT_READ | mnu_abi::HANDLE_RIGHT_TRANSFER;
                -13
            }
        };
        let observation = inspect(header, &payload, &objects, &mut fs, |_| {
            panic!("cursor query")
        });
        let (reply, owned) = finish(&mut service, peer, observation, Ok(()), &mut fs);
        assert_eq!(reply.response.header.status, expected);
        assert_eq!(owned, None);
        assert!(fs.released.is_empty());
    }
}

#[test]
fn cursor_snapshot_and_owner_metadata_failures_do_not_create_or_release_locks() {
    let (mut service, _, first, second, mut fs, _) = orphan_family();
    let write = Request {
        origin: Origin::Current,
        start: -10,
        length: -20,
        ..request(Operation::Set(Kind::Write))
    };
    let observation = pending(write, &[object(71, write)], &mut fs);
    assert_eq!(
        finish(&mut service, first, observation, Ok(()), &mut fs).1,
        Some(71)
    );
    for status in [-9, -5, -13] {
        fs.query_hook = Some(Box::new(move || Err(status)));
        let observation = pending(write, &[object(72, write)], &mut fs);
        let (reply, owned) = finish(&mut service, second, observation, Ok(()), &mut fs);
        assert_eq!(reply.response.header.status, status);
        assert_eq!(owned, None);
        assert!(fs.released.is_empty());
    }
    fs.query_hook = None;
    let mut bytes = [0; wire::REQUEST_LEN];
    wire::encode_request(write, &mut bytes).unwrap();
    let observation = inspect(
        protocol::Header {
            opcode: protocol::OP_RECORD_LOCK,
            payload_len: bytes.len() as u32,
            ..Default::default()
        },
        &bytes,
        &[object(73, write)],
        &mut fs,
        |attached| {
            assert_eq!(attached.rights, mnu_abi::HANDLE_RIGHT_SEEK);
            Err(-5)
        },
    );
    assert_eq!(
        finish(&mut service, second, observation, Ok(()), &mut fs)
            .0
            .response
            .header
            .status,
        -5
    );
    let query = Request {
        start: 75,
        length: 1,
        ..request(Operation::Query(Kind::Read))
    };
    let observation = pending(query, &[object(74, query)], &mut fs);
    let (reply, owned) = finish(&mut service, second, observation, Ok(()), &mut fs);
    assert_eq!(owned, None);
    assert_eq!(
        result(&reply),
        Reply::Conflict {
            owner: first.process_id,
            kind: Kind::Write,
            start: 70,
            length: 20
        }
    );
}

#[test]
fn image_change_or_unverified_image_never_installs_or_releases_a_pin() {
    for validation in [
        Err(protocol::STATUS_ESRCH),
        Err(protocol::STATUS_EIO),
        Err(protocol::STATUS_EPERM),
    ] {
        let (mut service, _, peer, _, mut fs, _) = orphan_family();
        let write = request(Operation::Set(Kind::Write));
        let observation = pending(write, &[object(71, write)], &mut fs);
        let (reply, owned) = finish(&mut service, peer, observation, validation, &mut fs);
        assert_eq!(reply.response.header.status, validation.unwrap_err());
        assert_eq!(owned, None);
        assert!(fs.released.is_empty());
    }
}

#[test]
fn native_exit_retires_the_last_pin_even_when_parent_notification_fails() {
    let (mut service, _, parent, child, mut fs, mut processes) = orphan_family();
    let write = request(Operation::Set(Kind::Write));
    let observation = pending(write, &[object(71, write)], &mut fs);
    assert_eq!(
        finish(&mut service, child, observation, Ok(()), &mut fs).1,
        Some(71)
    );
    processes
        .states
        .insert(142, ProcessLifecycle::Exited { exit_code: 0 });
    processes.images.insert(141, Err(protocol::STATUS_EIO));
    let _ = service.refresh_child_exit_notifications(&mut processes);
    service.release_unused_record_lock_files(&mut fs);
    assert_eq!(fs.released, [object(71, write)]);
    let observation = pending(write, &[object(72, write)], &mut fs);
    assert_eq!(
        finish(&mut service, parent, observation, Ok(()), &mut fs).1,
        Some(72)
    );
}

#[test]
fn directories_are_not_regular_file_locks_and_current_origin_requires_seek_authority() {
    let (mut service, _, peer, _, mut fs, _) = orphan_family();
    fs.stat_mode = Some(0o040700);
    let read = request(Operation::Set(Kind::Read));
    let observation = pending(read, &[object(71, read)], &mut fs);
    assert_eq!(
        finish(&mut service, peer, observation, Ok(()), &mut fs)
            .0
            .response
            .header
            .status,
        -22
    );
    fs.stat_mode = None;
    fs.stat_file = None;
    let current = Request {
        origin: Origin::Current,
        ..read
    };
    let observation = pending(current, &[object(72, read)], &mut fs);
    assert!(fs.stat_file.is_none());
    assert_eq!(
        finish(&mut service, peer, observation, Ok(()), &mut fs)
            .0
            .response
            .header
            .status,
        -13
    );
}

fn lock_present(service: &mut PosixService, observer: PeerIdentity, start: i64) -> bool {
    let status = sample_status();
    service
        .record_locks(observer)
        .unwrap()
        .conflict(
            posix_service::record_lock::FileKey {
                device: status.device,
                inode: status.inode,
            },
            Kind::Write,
            posix_service::record_lock::Range::normalize(0, start, 1).unwrap(),
        )
        .is_some()
}

#[test]
fn failed_status_preserves_unknown_owners_locks_but_does_not_block_a_later_native_exit() {
    let (mut service, init, first, second, mut fs, mut processes) = orphan_family();
    for (peer, handle, start) in [(first, 71, 0), (second, 72, 20)] {
        let write = Request {
            start,
            length: 10,
            ..request(Operation::Set(Kind::Write))
        };
        let observation = pending(write, &[object(handle, write)], &mut fs);
        assert_eq!(
            result(&finish(&mut service, peer, observation, Ok(()), &mut fs).0),
            Reply::Done
        );
    }
    processes.states.remove(&141);
    processes
        .states
        .insert(142, ProcessLifecycle::Exited { exit_code: 0 });
    assert_eq!(
        service.refresh_child_exit_notifications(&mut processes),
        Err(protocol::STATUS_ESRCH)
    );
    assert!(
        lock_present(&mut service, init, 0),
        "unknown exit must not release authority"
    );
    assert!(
        !lock_present(&mut service, init, 20),
        "later confirmed exit must still retire locks"
    );
    service.release_unused_record_lock_files(&mut fs);
    assert!(
        fs.released.is_empty(),
        "the unknown owner still pins this file"
    );
    processes
        .states
        .insert(141, ProcessLifecycle::Exited { exit_code: 0 });
    service
        .refresh_child_exit_notifications(&mut processes)
        .unwrap();
    service.release_unused_record_lock_files(&mut fs);
    assert_eq!(fs.released.len(), 1);
}

#[test]
fn failed_parent_notification_does_not_starve_later_exited_owners_or_the_last_file_reference() {
    let (mut service, init, first, second, mut fs, mut processes) = orphan_family();
    for (peer, handle, start) in [(first, 71, 0), (second, 72, 20)] {
        let write = Request {
            start,
            length: 10,
            ..request(Operation::Set(Kind::Write))
        };
        let observation = pending(write, &[object(handle, write)], &mut fs);
        assert_eq!(
            result(&finish(&mut service, peer, observation, Ok(()), &mut fs).0),
            Reply::Done
        );
    }
    for handle in [141, 142] {
        processes
            .states
            .insert(handle, ProcessLifecycle::Exited { exit_code: 0 });
    }
    processes.images.insert(140, Err(protocol::STATUS_EIO));
    for _ in 0..3 {
        assert_eq!(
            service.refresh_child_exit_notifications(&mut processes),
            Err(protocol::STATUS_EIO)
        );
        assert!(!lock_present(&mut service, init, 0));
        assert!(!lock_present(&mut service, init, 20));
        service.release_unused_record_lock_files(&mut fs);
        assert_eq!(
            fs.released.len(),
            1,
            "pin is retired once despite persistent notification failure"
        );
    }
    processes.images.remove(&140);
    service
        .refresh_child_exit_notifications(&mut processes)
        .unwrap();
    service.release_unused_record_lock_files(&mut fs);
    assert_eq!(fs.released.len(), 1);
}

#[test]
fn a_failed_deferred_continue_notification_does_not_prevent_independent_exit_cleanup() {
    let (mut service, init, parent, child, mut fs, mut processes) = orphan_family();
    set_child_signal_policy(
        &mut service,
        parent,
        protocol::SIGNAL_DISPOSITION_CAUGHT,
        protocol::SIGNAL_CHILD_OPTION_NOCLDSTOP,
    );
    stop_job_member(&mut service, parent, child, &mut processes);
    send_signal(&mut service, parent, child, protocol::SIGNAL_CONT);
    service
        .apply_process_resume(child.process_id, &mut processes)
        .unwrap();
    assert!(service.has_deferred_child_notifications());
    service
        .initialize_process(
            init,
            AuthenticatedProcess {
                process_id: 1403,
                handle: 143,
            },
            501,
            20,
            &[],
        )
        .unwrap();
    let owner = service.registered_peer(1403).unwrap();
    let write = request(Operation::Set(Kind::Write));
    let observation = pending(write, &[object(71, write)], &mut fs);
    assert_eq!(
        finish(&mut service, owner, observation, Ok(()), &mut fs).1,
        Some(71)
    );
    processes.identities.insert(143, 1403);
    processes
        .states
        .insert(143, ProcessLifecycle::Exited { exit_code: 0 });
    processes.images.insert(141, Err(protocol::STATUS_EIO));
    assert_eq!(
        service.refresh_child_exit_notifications(&mut processes),
        Err(protocol::STATUS_EIO)
    );
    assert!(
        service.has_deferred_child_notifications(),
        "the failed notification remains retryable"
    );
    assert!(!lock_present(&mut service, init, 0));
    service.release_unused_record_lock_files(&mut fs);
    assert_eq!(fs.released.len(), 1);
    processes.images.remove(&141);
    service
        .refresh_child_exit_notifications(&mut processes)
        .unwrap();
    assert!(!service.has_deferred_child_notifications());
    service.release_unused_record_lock_files(&mut fs);
    assert_eq!(fs.released.len(), 1);
}

#[test]
fn exec_preparation_releases_the_real_file_pin_only_after_an_uncancelled_native_image_change() {
    for cancel in [false, true] {
        let (mut service, _, peer, _, mut fs, mut processes) = orphan_family();
        let write = request(Operation::Set(Kind::Write));
        let observation = pending(write, &[object(71, write)], &mut fs);
        assert_eq!(
            finish(&mut service, peer, observation, Ok(()), &mut fs).1,
            Some(71)
        );
        let status = sample_status();
        let file = posix_service::record_lock::FileKey {
            device: status.device,
            inode: status.inode,
        };
        let token = service
            .prepare_record_lock_exec(peer, &[file])
            .unwrap()
            .unwrap();
        service.refresh_image_state(peer, &mut processes).unwrap();
        service.release_unused_record_lock_files(&mut fs);
        assert!(
            fs.released.is_empty(),
            "merely preparing an exec must not close the live file pin"
        );
        if cancel {
            service.cancel_record_lock_exec(peer, token).unwrap();
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
        service.refresh_image_state(peer, &mut processes).unwrap();
        service.release_unused_record_lock_files(&mut fs);
        assert_eq!(fs.released.len(), usize::from(!cancel));
        service.refresh_image_state(peer, &mut processes).unwrap();
        service.release_unused_record_lock_files(&mut fs);
        assert_eq!(fs.released.len(), usize::from(!cancel));
    }
}
