use super::*;
use std::sync::{Arc, Mutex};

#[test]
fn pty_request_rejects_malformed_envelopes_before_allocating() {
    let valid = protocol::Header {
        opcode: protocol::OP_PTY_OPEN,
        request_id: 351,
        ..Default::default()
    };
    let unexpected = [AttachedObject {
        handle: 77,
        rights: 1,
    }];
    for (header, payload, handles) in [
        (
            protocol::Header {
                opcode: protocol::OP_PING,
                ..valid
            },
            &[][..],
            &[][..],
        ),
        (protocol::Header { flags: 1, ..valid }, &[][..], &[][..]),
        (
            protocol::Header {
                status: -22,
                ..valid
            },
            &[][..],
            &[][..],
        ),
        (protocol::Header { status: 1, ..valid }, &[][..], &[][..]),
        (
            protocol::Header {
                payload_len: 1,
                ..valid
            },
            &[][..],
            &[][..],
        ),
        (valid, &[1][..], &[][..]),
        (valid, &[][..], &unexpected[..]),
    ] {
        let result = posix_service::pty_request::execute(header, payload, handles, || {
            panic!("invalid request must not allocate a PTY")
        });
        assert_eq!(result.response.header.status, -22);
        assert_eq!(result.response.header.request_id, 351);
        assert!(result.handles.is_empty());
    }
}

#[test]
fn pty_pair_is_released_if_execution_image_validation_fails() {
    for validation in [
        Ok(()),
        Err(protocol::STATUS_ESRCH),
        Err(protocol::STATUS_EPERM),
    ] {
        let mut fs = RecordingFilesystem::default();
        let mut allocations = 0;
        let response = posix_service::pty_request::execute(
            protocol::Header {
                opcode: protocol::OP_PTY_OPEN,
                request_id: 352,
                ..Default::default()
            },
            &[],
            &[],
            || {
                allocations += 1;
                posix_service::ObjectResponse {
                    response: posix_service::Response {
                        header: protocol::Header {
                            request_id: 352,
                            ..Default::default()
                        },
                        payload: Vec::new(),
                    },
                    handles: vec![
                        posix_service::OpenedObject {
                            handle: 201,
                            rights: 3,
                        },
                        posix_service::OpenedObject {
                            handle: 202,
                            rights: 3,
                        },
                    ],
                }
            },
        );
        let response = posix_service::open_request::finish(response, validation, &mut fs);
        assert_eq!(allocations, 1);
        assert_eq!(response.response.header.request_id, 352);
        if let Err(status) = validation {
            assert_eq!(response.response.header.status, status);
            assert!(response.handles.is_empty());
            assert_eq!(
                fs.released.iter().map(|h| h.handle).collect::<Vec<_>>(),
                [201, 202]
            );
        } else {
            assert_eq!(response.handles.len(), 2);
            assert!(fs.released.is_empty());
        }
    }
}

#[test]
fn native_pty_dispatch_validates_image_after_unlocked_allocation() {
    let source = include_str!("../../src/main.rs");
    let preflight = source
        .split("let opened_pty =")
        .nth(1)
        .unwrap()
        .split("let opened_socket =")
        .next()
        .unwrap();
    assert!(preflight.contains("request_image.is_some()"));
    assert!(preflight.contains("posix_service::pty_request::execute("));
    let finish = source
        .split("if opened_pty.is_some() =>")
        .nth(1)
        .unwrap()
        .split("protocol::OP_PROCESS_SESSION_INFO")
        .next()
        .unwrap();
    assert!(finish.contains("validate_pending_request_image("));
    assert!(finish.contains("posix_service::open_request::finish("));
}

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
fn fifo_continuation_is_explicit_owned_and_image_rejection_reclaims_both_handles() {
    let flags = protocol::MUTATION_ADMISSION | protocol::fifo::OPEN_CONTINUATION;
    for invalid_image in [false, true] {
        let (state, peer, header, payload) = setup(protocol::OpenBase::ProcessCwd, flags);
        let data = OpenedObject {
            handle: 301,
            rights: protocol::fifo::data_rights(protocol::OPEN_READ).unwrap(),
        };
        let notification = OpenedObject {
            handle: 302,
            rights: protocol::fifo::NOTIFICATION_RIGHTS,
        };
        let state_ref = state.clone();
        let mut fs = RecordingFilesystem {
            fifo_pending: Some((data, notification)),
            open_hook: Some(Box::new(move || {
                assert!(
                    state_ref.try_lock().is_ok(),
                    "no state lock across FIFO handoff"
                );
            })),
            ..Default::default()
        };
        let result =
            posix_service::open_request::execute(&state, peer, header, &payload, &[], &mut fs);
        assert_eq!(result.response.header.status, 0);
        assert_eq!(
            result.response.header.flags,
            protocol::fifo::OPEN_PENDING_REPLY
        );
        assert_eq!(result.handles, [data, notification]);
        assert!(result.response.payload.is_empty());
        let old = fs.released.len();
        let result = posix_service::open_request::finish(
            result,
            if invalid_image { Err(-1) } else { Ok(()) },
            &mut fs,
        );
        if invalid_image {
            assert_eq!(result.response.header.status, -1);
            assert_eq!(result.response.header.flags, 0);
            assert!(result.handles.is_empty());
            assert_eq!(
                fs.released[old..]
                    .iter()
                    .map(|o| o.handle)
                    .collect::<Vec<_>>(),
                [301, 302]
            );
        } else {
            assert_eq!(result.handles, [data, notification]);
            assert_eq!(fs.released.len(), old);
        }
    }
}

#[test]
fn invalid_pending_rights_or_nonblocking_open_release_both_instead_of_publishing() {
    for mode in 0..3 {
        let (state, peer, mut header, mut payload) = setup(
            protocol::OpenBase::ProcessCwd,
            protocol::MUTATION_ADMISSION | protocol::fifo::OPEN_CONTINUATION,
        );
        if mode == 2 {
            let len = protocol::encode_open_at(
                protocol::OpenAtRequest {
                    base: protocol::OpenBase::ProcessCwd,
                    options: protocol::OPEN_READ | protocol::OPEN_NONBLOCK,
                    mode: 0,
                    path: b"fifo",
                },
                &mut payload,
            )
            .unwrap();
            payload.truncate(len);
            header.payload_len = len as u32;
        }
        let data = OpenedObject {
            handle: 301,
            rights: protocol::fifo::data_rights(protocol::OPEN_READ).unwrap()
                | if mode == 0 {
                    mnu_abi::HANDLE_RIGHT_WRITE
                } else {
                    0
                },
        };
        let notification = OpenedObject {
            handle: 302,
            rights: protocol::fifo::NOTIFICATION_RIGHTS
                | if mode == 1 {
                    mnu_abi::HANDLE_RIGHT_READ
                } else {
                    0
                },
        };
        let mut fs = RecordingFilesystem {
            fifo_pending: Some((data, notification)),
            ..Default::default()
        };
        let result =
            posix_service::open_request::execute(&state, peer, header, &payload, &[], &mut fs);
        assert_eq!(result.response.header.status, protocol::STATUS_EIO);
        assert!(result.handles.is_empty());
        assert!(fs.released.iter().any(|o| o.handle == 301));
        assert!(fs.released.iter().any(|o| o.handle == 302));
    }
}

#[test]
fn continuation_flag_requires_open_at_and_admission_and_preserves_borrowed_sources() {
    for (opcode, flags, valid) in [
        (
            protocol::OP_OPEN_AT,
            protocol::fifo::OPEN_CONTINUATION,
            false,
        ),
        (
            protocol::OP_FTRUNCATE,
            protocol::MUTATION_ADMISSION | protocol::fifo::OPEN_CONTINUATION,
            false,
        ),
        (
            protocol::OP_TRUNCATE_AT,
            protocol::MUTATION_ADMISSION | protocol::fifo::OPEN_CONTINUATION,
            false,
        ),
        (
            protocol::OP_OPEN_AT,
            protocol::MUTATION_ADMISSION | protocol::fifo::OPEN_CONTINUATION,
            true,
        ),
    ] {
        let decoded = posix_service::mutation_admission::Request::<u32>::decode(
            protocol::Header {
                opcode,
                flags,
                ..Default::default()
            },
            &[],
        );
        if valid {
            assert!(decoded.unwrap().open_continuation);
        } else {
            assert_eq!(decoded.err(), Some(-22));
        }
    }
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
