use super::*;
use std::sync::{Arc, Mutex};

fn setup(
    base: protocol::OpenBase,
    flags: u32,
) -> (
    Arc<Mutex<PosixService>>,
    PeerIdentity,
    protocol::Header,
    Vec<u8>,
) {
    let peer = PeerIdentity {
        process_id: 91,
        effective_uid: 501,
        effective_gid: 20,
    };
    let state = Arc::new(Mutex::new(service_for(peer)));
    let mut payload = vec![0; 128];
    let len = protocol::encode_open_at(
        protocol::OpenAtRequest {
            base,
            options: protocol::OPEN_READ,
            mode: 0,
            path: b"file",
        },
        &mut payload,
    )
    .unwrap();
    payload.truncate(len);
    let header = protocol::Header {
        opcode: protocol::OP_OPEN_AT,
        request_id: 87,
        flags,
        payload_len: len as u32,
        ..Default::default()
    };
    (state, peer, header, payload)
}

#[test]
fn root_and_open_rpc_release_state_lock_and_keep_owned_path_anchors() {
    let (state, peer, header, payload) = setup(protocol::OpenBase::ProcessCwd, 0);
    let root_state = state.clone();
    let open_state = state.clone();
    let mut fs = RecordingFilesystem {
        root_hook: Some(Box::new(move || {
            assert!(root_state.try_lock().is_ok());
        })),
        open_hook: Some(Box::new(move || {
            let mut service = open_state.try_lock().expect("open must not hold state");
            // A concurrent cwd change releases the old session-owned Handle.
            let mut other_fs = RecordingFilesystem::default();
            let mut bytes = [0u8; 128];
            let len = protocol::encode_stat_at(
                protocol::StatAtRequest {
                    base: protocol::OpenBase::ProcessRoot,
                    flags: 0,
                    path: b"next",
                },
                &mut bytes,
            )
            .unwrap();
            let response = service.handle_objects(
                peer,
                protocol::Header {
                    opcode: protocol::OP_CHDIR_AT,
                    payload_len: len as u32,
                    ..Default::default()
                },
                &bytes[..len],
                &[],
                &mut other_fs,
            );
            assert_eq!(response.response.header.status, 0);
            assert_eq!(other_fs.released[0].handle, 101);
        })),
        ..Default::default()
    };
    let response =
        posix_service::open_request::execute(&state, peer, header, &payload, &[], &mut fs);
    assert_eq!(response.response.header.status, 0);
    assert_eq!(response.handles[0].handle, 200);
    assert_eq!(fs.root.unwrap().handle, 1100);
    assert_eq!(fs.directory.unwrap().handle, 1101);
    assert_eq!(
        fs.released.iter().map(|h| h.handle).collect::<Vec<_>>(),
        [1100, 1101]
    );
    assert_eq!(
        state
            .lock()
            .unwrap()
            .session_directories(peer.process_id)
            .unwrap()
            .cwd
            .handle,
        200
    );
}

#[test]
fn attached_directory_and_admission_ticket_are_borrowed_not_duplicated() {
    let (state, peer, header, payload) = setup(
        protocol::OpenBase::AttachedDirectory,
        protocol::MUTATION_ADMISSION | protocol::MUTATION_ADMISSION_ATTACHED,
    );
    let sources = [
        AttachedObject {
            handle: 70,
            rights: mnu_abi::HANDLE_RIGHT_TRANSFER,
        },
        AttachedObject {
            handle: 71,
            rights: posix_service::mutation_admission::TICKET_RIGHTS,
        },
    ];
    let mut fs = RecordingFilesystem::default();
    let response =
        posix_service::open_request::execute(&state, peer, header, &payload, &sources, &mut fs);
    assert_eq!(response.response.header.status, 0);
    assert_eq!(fs.directory, Some(sources[0]));
    assert_eq!(
        fs.admission_calls,
        [(protocol::OP_OPEN_AT, Some(sources[1]))]
    );
    assert_eq!(fs.retained.len(), 1);
    assert_eq!(
        fs.released.iter().map(|h| h.handle).collect::<Vec<_>>(),
        [1100]
    );
}

#[test]
fn partial_anchor_retention_failure_releases_only_new_owned_references() {
    let (state, peer, header, payload) = setup(protocol::OpenBase::ProcessCwd, 0);
    let mut fs = RecordingFilesystem {
        retain_failure_at: Some(2),
        ..Default::default()
    };
    let response =
        posix_service::open_request::execute(&state, peer, header, &payload, &[], &mut fs);
    assert_eq!(response.response.header.status, -5);
    assert!(response.handles.is_empty());
    assert!(fs.request.is_none());
    assert_eq!(
        fs.released.iter().map(|h| h.handle).collect::<Vec<_>>(),
        [1100]
    );
    assert!(
        state
            .lock()
            .unwrap()
            .session_directories(peer.process_id)
            .is_some()
    );
}

#[test]
fn changed_policy_during_root_rpc_discards_uninstalled_roots_before_open() {
    let (state, peer, header, payload) = setup(protocol::OpenBase::ProcessCwd, 0);
    let root_state = state.clone();
    let mut fs = RecordingFilesystem {
        root_hook: Some(Box::new(move || {
            let mut service = root_state.try_lock().unwrap();
            let mut mask = [0; protocol::UMASK_PAYLOAD_LEN];
            protocol::encode_umask(0o077, &mut mask).unwrap();
            service.handle(
                peer,
                protocol::Header {
                    opcode: protocol::OP_UMASK_SET,
                    payload_len: mask.len() as u32,
                    ..Default::default()
                },
                &mask,
            );
        })),
        ..Default::default()
    };
    // A creation request makes the changed umask observable in PreparedOpen.
    let mut payload = payload;
    let len = protocol::encode_open_at(
        protocol::OpenAtRequest {
            base: protocol::OpenBase::ProcessCwd,
            options: protocol::OPEN_READ | protocol::OPEN_CREATE,
            mode: 0o666,
            path: b"file",
        },
        &mut payload,
    )
    .unwrap();
    payload.truncate(len);
    let response =
        posix_service::open_request::execute(&state, peer, header, &payload, &[], &mut fs);
    assert_eq!(response.response.header.status, protocol::STATUS_EAGAIN);
    assert!(fs.request.is_none());
    assert_eq!(
        fs.released.iter().map(|h| h.handle).collect::<Vec<_>>(),
        [100, 101]
    );
    assert!(
        state
            .lock()
            .unwrap()
            .session_directories(peer.process_id)
            .is_none()
    );
}

#[test]
fn rejected_framing_has_no_filesystem_side_effects() {
    let (state, peer, header, payload) = setup(protocol::OpenBase::ProcessRoot, 0);
    for header in [
        protocol::Header {
            status: -1,
            ..header
        },
        protocol::Header {
            payload_len: 0,
            ..header
        },
        protocol::Header {
            flags: u32::MAX,
            ..header
        },
    ] {
        let mut fs = RecordingFilesystem::default();
        let response =
            posix_service::open_request::execute(&state, peer, header, &payload, &[], &mut fs);
        assert_eq!(response.response.header.status, STATUS_EINVAL);
        assert_eq!(fs.roots_opened, 0);
        assert!(fs.retained.is_empty());
    }
}

#[test]
fn admission_wait_returns_ticket_but_releases_path_snapshot() {
    let (state, peer, header, payload) = setup(
        protocol::OpenBase::ProcessRoot,
        protocol::MUTATION_ADMISSION,
    );
    let ticket = OpenedObject {
        handle: 72,
        rights: posix_service::mutation_admission::TICKET_RIGHTS,
    };
    let mut fs = RecordingFilesystem {
        admission_response: Some(Ok(ticket)),
        ..Default::default()
    };
    let response =
        posix_service::open_request::execute(&state, peer, header, &payload, &[], &mut fs);
    assert_eq!(
        response.response.header.status,
        protocol::STATUS_MEMORY_ADMISSION_BUSY
    );
    assert_eq!(response.handles, [ticket]);
    assert_eq!(
        fs.released.iter().map(|h| h.handle).collect::<Vec<_>>(),
        [1100]
    );
}

#[test]
fn rejected_image_releases_open_result_or_admission_ticket_without_returning_it() {
    for flags in [0, protocol::MUTATION_ADMISSION] {
        let (state, peer, header, payload) = setup(protocol::OpenBase::ProcessRoot, flags);
        let ticket = OpenedObject {
            handle: 72,
            rights: posix_service::mutation_admission::TICKET_RIGHTS,
        };
        let mut fs = RecordingFilesystem {
            admission_response: (flags != 0).then_some(Ok(ticket)),
            ..Default::default()
        };
        let response =
            posix_service::open_request::execute(&state, peer, header, &payload, &[], &mut fs);
        let opened = response.handles[0];
        let response =
            posix_service::open_request::finish(response, Err(protocol::STATUS_ESRCH), &mut fs);
        assert_eq!(response.response.header.request_id, header.request_id);
        assert_eq!(response.response.header.status, protocol::STATUS_ESRCH);
        assert!(response.handles.is_empty());
        assert_eq!(fs.released.last().unwrap().handle, opened.handle);
    }
}

#[test]
fn accepted_image_keeps_the_output_reference_owned_by_reply() {
    let (state, peer, header, payload) = setup(protocol::OpenBase::ProcessRoot, 0);
    let mut fs = RecordingFilesystem::default();
    let response =
        posix_service::open_request::execute(&state, peer, header, &payload, &[], &mut fs);
    let response = posix_service::open_request::finish(response, Ok(()), &mut fs);
    assert_eq!(response.handles[0].handle, 200);
    assert_eq!(
        fs.released.iter().map(|h| h.handle).collect::<Vec<_>>(),
        [1100]
    );
}
