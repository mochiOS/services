use super::*;

fn id(service: &mut PosixService, peer: PeerIdentity, opcode: u16, value: u32) -> i32 {
    let mut bytes = [0; protocol::CREDENTIAL_ID_PAYLOAD_LEN];
    protocol::encode_credential_id(value, &mut bytes).unwrap();
    service
        .handle(
            peer,
            protocol::Header {
                opcode,
                ..Default::default()
            },
            &bytes,
        )
        .header
        .status
}

fn setup() -> (PosixService, PeerIdentity, RecordingProcesses) {
    let peer = PeerIdentity {
        process_id: 2401,
        effective_uid: 0,
        effective_gid: 0,
    };
    let mut service = service_for(peer);
    for (opcode, real, effective) in [
        (protocol::OP_SET_REAL_EFFECTIVE_UID, 501, 0),
        (protocol::OP_SET_REAL_EFFECTIVE_GID, 20, 0),
    ] {
        let mut bytes = [0; protocol::CREDENTIAL_PAIR_PAYLOAD_LEN];
        protocol::encode_credential_pair(real, effective, &mut bytes).unwrap();
        assert_eq!(
            service
                .handle(
                    peer,
                    protocol::Header {
                        opcode,
                        ..Default::default()
                    },
                    &bytes
                )
                .header
                .status,
            0
        );
    }
    assert_eq!(
        id(&mut service, peer, protocol::OP_SET_EFFECTIVE_GID, 20),
        0
    );
    assert_eq!(
        id(&mut service, peer, protocol::OP_SET_EFFECTIVE_UID, 501),
        0
    );
    let mut processes = RecordingProcesses::default();
    processes.images.insert(
        2401,
        Ok(mnu_abi::ProcessStatus {
            process_id: peer.process_id,
            state: mnu_abi::PROCESS_STATE_RUNNING,
            ..Default::default()
        }),
    );
    (service, peer, processes)
}

fn revision(processes: &mut RecordingProcesses, value: u64) {
    processes
        .images
        .get_mut(&2401)
        .unwrap()
        .as_mut()
        .unwrap()
        .image_revision = value;
}

#[test]
fn only_a_committed_image_replaces_saved_ids_and_revokes_old_saved_root() {
    let (mut service, peer, mut processes) = setup();
    let before = *service.session(peer.process_id).unwrap();
    assert_eq!(
        (before.real_uid, before.effective_uid, before.saved_uid),
        (501, 501, 0)
    );
    assert_eq!(
        (before.real_gid, before.effective_gid, before.saved_gid),
        (20, 20, 0)
    );
    // Failed exec, or a client claiming startup without exec, cannot copy IDs.
    service
        .refresh_image_state(peer, &mut processes)
        .unwrap();
    assert_eq!(*service.session(peer.process_id).unwrap(), before);
    let response = service.handle_thread_signal_request(
        peer,
        mnu_abi::ExecutionIdentity {
            process_id: peer.process_id,
            thread_id: 900,
        },
        protocol::Header {
            opcode: protocol::OP_SIGNAL_IMAGE_STARTED,
            ..Default::default()
        },
        &[],
    );
    assert_eq!(response.header.status, 0);
    service
        .refresh_image_state(peer, &mut processes)
        .unwrap();
    assert_eq!(*service.session(peer.process_id).unwrap(), before);
    assert_eq!(id(&mut service, peer, protocol::OP_SET_EFFECTIVE_UID, 0), 0);
    assert_eq!(
        id(&mut service, peer, protocol::OP_SET_EFFECTIVE_UID, 501),
        0
    );
    revision(&mut processes, 1);
    service
        .refresh_image_state(peer, &mut processes)
        .unwrap();
    let after = *service.session(peer.process_id).unwrap();
    assert_eq!(
        (after.real_uid, after.effective_uid, after.saved_uid),
        (501, 501, 501)
    );
    assert_eq!(
        (after.real_gid, after.effective_gid, after.saved_gid),
        (20, 20, 20)
    );
    // The stale peer UID zero does not authorize credential changes.
    assert_eq!(
        id(&mut service, peer, protocol::OP_SET_EFFECTIVE_UID, 0),
        protocol::STATUS_EPERM
    );
    assert_eq!(
        id(&mut service, peer, protocol::OP_SET_EFFECTIVE_GID, 0),
        protocol::STATUS_EPERM
    );
    assert_eq!(*service.session(peer.process_id).unwrap(), after);
}

#[test]
fn repeated_observation_preserves_later_changes_and_fork_has_its_own_revision() {
    let (mut service, peer, mut processes) = setup();
    // Retain a distinct real ID so a later effective-ID change is permitted.
    assert_eq!(id(&mut service, peer, protocol::OP_SET_EFFECTIVE_UID, 0), 0);
    assert_eq!(
        id(&mut service, peer, protocol::OP_SET_EFFECTIVE_UID, 502),
        0
    );
    revision(&mut processes, 4);
    service
        .refresh_image_state(peer, &mut processes)
        .unwrap();
    assert_eq!(service.session(peer.process_id).unwrap().saved_uid, 502);
    assert_eq!(
        id(&mut service, peer, protocol::OP_SET_EFFECTIVE_UID, 501),
        0
    );
    service
        .refresh_image_state(peer, &mut processes)
        .unwrap();
    assert_eq!(service.session(peer.process_id).unwrap().saved_uid, 502);
    let child = PeerIdentity {
        process_id: 2402,
        ..peer
    };
    service
        .adopt_child(
            peer,
            AuthenticatedProcess {
                handle: 82,
                process_id: child.process_id,
            },
            &mut RecordingFilesystem::default(),
        )
        .unwrap();
    processes.images.insert(
        82,
        Ok(mnu_abi::ProcessStatus {
            process_id: child.process_id,
            state: mnu_abi::PROCESS_STATE_RUNNING,
            ..Default::default()
        }),
    );
    service
        .refresh_image_state(child, &mut processes)
        .unwrap();
    assert_eq!(service.session(child.process_id).unwrap().saved_uid, 502);
    processes
        .images
        .get_mut(&82)
        .unwrap()
        .as_mut()
        .unwrap()
        .image_revision = 1;
    service
        .refresh_image_state(child, &mut processes)
        .unwrap();
    assert_eq!(service.session(child.process_id).unwrap().saved_uid, 501);
    assert_eq!(service.session(peer.process_id).unwrap().saved_uid, 502);
}

#[test]
fn failed_or_regressing_metadata_never_changes_credentials_or_consumes_revision() {
    let (mut service, peer, mut processes) = setup();
    revision(&mut processes, 1);
    service
        .refresh_image_state(peer, &mut processes)
        .unwrap();
    let before = *service.session(peer.process_id).unwrap();
    let valid = processes.images[&2401].unwrap();
    for (value, error) in [
        (Err(protocol::STATUS_EIO), protocol::STATUS_EIO),
        (Err(protocol::STATUS_ENOSYS), protocol::STATUS_ENOSYS),
        (
            Ok(mnu_abi::ProcessStatus {
                process_id: 999,
                ..valid
            }),
            protocol::STATUS_EIO,
        ),
        (
            Ok(mnu_abi::ProcessStatus {
                reserved: 1,
                ..valid
            }),
            protocol::STATUS_EIO,
        ),
        (
            Ok(mnu_abi::ProcessStatus { state: 99, ..valid }),
            protocol::STATUS_EIO,
        ),
        (
            Ok(mnu_abi::ProcessStatus {
                state: mnu_abi::PROCESS_STATE_EXITED,
                ..valid
            }),
            protocol::STATUS_ESRCH,
        ),
        (
            Ok(mnu_abi::ProcessStatus {
                image_revision: 0,
                ..valid
            }),
            protocol::STATUS_EIO,
        ),
    ] {
        processes.images.insert(2401, value);
        assert_eq!(
            service.refresh_image_state(peer, &mut processes),
            Err(error)
        );
        assert_eq!(*service.session(peer.process_id).unwrap(), before);
    }
    processes.images.insert(
        2401,
        Ok(mnu_abi::ProcessStatus {
            image_revision: 2,
            ..valid
        }),
    );
    service
        .refresh_image_state(peer, &mut processes)
        .unwrap();
}

#[test]
fn broker_loaded_images_do_not_inherit_requesters_old_saved_root() {
    let (mut service, requester, mut processes) = setup();
    assert_eq!(
        id(&mut service, requester, protocol::OP_SET_EFFECTIVE_UID, 0),
        0
    );
    let broker = PeerIdentity {
        process_id: 2403,
        effective_uid: 0,
        effective_gid: 0,
    };
    service
        .initialize_process(
            requester,
            AuthenticatedProcess {
                handle: 83,
                process_id: broker.process_id,
            },
            0,
            0,
            &[],
        )
        .unwrap();
    assert_eq!(
        id(&mut service, requester, protocol::OP_SET_EFFECTIVE_UID, 501),
        0
    );
    service
        .adopt_launched_child(
            broker,
            AuthenticatedProcess {
                handle: 2401,
                process_id: requester.process_id,
            },
            AuthenticatedProcess {
                handle: 84,
                process_id: 2404,
            },
            &mut RecordingFilesystem::default(),
        )
        .unwrap();
    let child = PeerIdentity {
        process_id: 2404,
        effective_uid: 501,
        effective_gid: 20,
    };
    assert_eq!(service.session(requester.process_id).unwrap().saved_uid, 0);
    assert_eq!(service.session(child.process_id).unwrap().saved_uid, 501);
    assert_eq!(service.session(child.process_id).unwrap().saved_gid, 20);
    processes.images.insert(
        84,
        Ok(mnu_abi::ProcessStatus {
            process_id: child.process_id,
            state: mnu_abi::PROCESS_STATE_RUNNING,
            ..Default::default()
        }),
    );
    service
        .refresh_image_state(child, &mut processes)
        .unwrap();
    assert_eq!(
        id(&mut service, child, protocol::OP_SET_EFFECTIVE_UID, 0),
        protocol::STATUS_EPERM
    );
    assert_eq!(
        id(&mut service, child, protocol::OP_SET_EFFECTIVE_GID, 0),
        protocol::STATUS_EPERM
    );
}

#[test]
fn native_dispatch_refreshes_before_provider_side_effects_and_keeps_cleanup() {
    let main = include_str!("../../src/main.rs");
    let admission = main.find("let image_state_error =").unwrap();
    let resource = main[admission..].find("let opened_pty =").unwrap() + admission;
    let dispatch = main[admission..]
        .find("let object_response = match")
        .unwrap()
        + admission;
    assert!(admission < resource && resource < dispatch);
    assert!(main[admission..resource].contains("refresh_image_state(peer, &mut processes)"));
    assert!(main[admission..resource].contains("peer.is_some()"));
    let rejection = &main[admission..resource];
    assert!(rejection.contains("status_response(header.request_id, status)"));
    assert!(rejection.contains("platform::handle::close(attachment.handle)"));
    assert!(rejection.contains("platform::ipc::reply(sender"));
    assert!(rejection.contains("continue;"));
}
