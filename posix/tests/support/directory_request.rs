use super::*;
use std::sync::{Arc, Mutex};

const OPS: [u16; 2] = [protocol::OP_CHDIR_AT, protocol::OP_CHROOT_AT];

fn setup(uid: u32) -> (Arc<Mutex<PosixService>>, PeerIdentity) {
    let peer = PeerIdentity {
        process_id: 99,
        effective_uid: uid,
        effective_gid: 20,
    };
    (Arc::new(Mutex::new(service_for(peer))), peer)
}

fn request(opcode: u16, base: protocol::OpenBase) -> (protocol::Header, Vec<u8>) {
    let mut bytes = vec![0; 128];
    let len = protocol::encode_stat_at(
        protocol::StatAtRequest {
            base,
            flags: 0,
            path: b"child-\xff",
        },
        &mut bytes,
    )
    .unwrap();
    bytes.truncate(len);
    (
        protocol::Header {
            opcode,
            request_id: 106,
            payload_len: len as u32,
            ..Default::default()
        },
        bytes,
    )
}

fn finish(
    state: &Mutex<PosixService>,
    peer: PeerIdentity,
    pending: posix_service::directory_request::Pending<u32>,
    validation: Result<(), i32>,
    fs: &mut RecordingFilesystem,
) -> posix_service::ObjectResponse<u32> {
    posix_service::directory_request::finish(
        &mut state.lock().unwrap(),
        peer,
        pending,
        validation,
        fs,
    )
}

#[test]
fn directory_lookup_is_unlocked_and_only_finish_installs_the_owned_reference() {
    for opcode in OPS {
        for base in [
            protocol::OpenBase::ProcessRoot,
            protocol::OpenBase::ProcessCwd,
            protocol::OpenBase::AttachedDirectory,
        ] {
            let (state, peer) = setup(0);
            let root_state = state.clone();
            let directory_state = state.clone();
            let mut fs = RecordingFilesystem {
                root_hook: Some(Box::new(move || {
                    assert!(root_state.try_lock().is_ok());
                })),
                query_hook: Some(Box::new(move || {
                    assert!(directory_state.try_lock().is_ok());
                    Ok(())
                })),
                ..Default::default()
            };
            let (header, payload) = request(opcode, base);
            let attached = [AttachedObject {
                handle: 79,
                rights: mnu_abi::HANDLE_RIGHT_TRANSFER,
            }];
            let handles = if base == protocol::OpenBase::AttachedDirectory {
                &attached[..]
            } else {
                &[]
            };
            let pending = posix_service::directory_request::execute(
                &state, peer, header, &payload, handles, &mut fs,
            );
            let before = *state.lock().unwrap().session_directories(99).unwrap();
            assert_eq!((before.root.handle, before.cwd.handle), (100, 101));
            assert!(!fs.released.iter().any(|h| h.handle == 200));
            let response = finish(&state, peer, pending, Ok(()), &mut fs);
            assert_eq!(response.response.header.status, 0);
            assert_eq!(response.response.header.request_id, 106);
            assert!(response.handles.is_empty());
            let after = *state.lock().unwrap().session_directories(99).unwrap();
            assert_eq!(
                (after.root.handle, after.cwd.handle),
                if opcode == protocol::OP_CHROOT_AT {
                    (200, 101)
                } else {
                    (100, 200)
                }
            );
            assert_eq!(
                fs.released.last().unwrap().handle,
                if opcode == protocol::OP_CHROOT_AT {
                    100
                } else {
                    101
                }
            );
            assert_eq!(fs.directory_request.as_ref().unwrap().path, b"child-\xff");
            assert_eq!(
                fs.directory.map(|h| h.handle),
                match base {
                    protocol::OpenBase::ProcessRoot => None,
                    protocol::OpenBase::ProcessCwd => Some(1101),
                    protocol::OpenBase::AttachedDirectory => Some(79),
                }
            );
        }
    }
}

#[test]
fn image_rejection_releases_lookup_result_without_changing_directory_context() {
    for opcode in OPS {
        let (state, peer) = setup(0);
        let (header, payload) = request(opcode, protocol::OpenBase::ProcessCwd);
        let mut fs = RecordingFilesystem::default();
        let pending =
            posix_service::directory_request::execute(&state, peer, header, &payload, &[], &mut fs);
        let response = finish(&state, peer, pending, Err(protocol::STATUS_ESRCH), &mut fs);
        assert_eq!(response.response.header.status, protocol::STATUS_ESRCH);
        assert!(response.handles.is_empty());
        assert_eq!(
            fs.released.iter().map(|h| h.handle).collect::<Vec<_>>(),
            [1100, 1101, 200]
        );
        let dirs = *state.lock().unwrap().session_directories(99).unwrap();
        assert_eq!((dirs.root.handle, dirs.cwd.handle), (100, 101));
    }
}

#[test]
fn changed_credentials_or_wrong_process_cannot_install_a_prepared_directory() {
    for opcode in OPS {
        for wrong_process in [false, true] {
            let (state, peer) = setup(0);
            let (header, payload) = request(opcode, protocol::OpenBase::ProcessRoot);
            let mut fs = RecordingFilesystem::default();
            let pending = posix_service::directory_request::execute(
                &state,
                peer,
                header,
                &payload,
                &[],
                &mut fs,
            );
            let finisher = if wrong_process {
                PeerIdentity {
                    process_id: 100,
                    ..peer
                }
            } else {
                let value = 501u32.to_le_bytes();
                assert_eq!(
                    state
                        .lock()
                        .unwrap()
                        .handle(
                            peer,
                            protocol::Header {
                                opcode: protocol::OP_SET_EFFECTIVE_UID,
                                payload_len: value.len() as u32,
                                ..Default::default()
                            },
                            &value
                        )
                        .header
                        .status,
                    0
                );
                peer
            };
            let response = finish(&state, finisher, pending, Ok(()), &mut fs);
            assert_eq!(
                response.response.header.status,
                if wrong_process {
                    protocol::STATUS_EPERM
                } else {
                    protocol::STATUS_EAGAIN
                }
            );
            assert_eq!(fs.released.last().unwrap().handle, 200);
            let dirs = *state.lock().unwrap().session_directories(99).unwrap();
            assert_eq!((dirs.root.handle, dirs.cwd.handle), (100, 101));
        }
    }
}

#[test]
fn lookup_errors_and_failed_anchor_retention_preserve_existing_context() {
    for opcode in OPS {
        for fail_retention in [false, true] {
            let (state, peer) = setup(0);
            let (header, payload) = request(opcode, protocol::OpenBase::ProcessCwd);
            let mut fs = RecordingFilesystem {
                retain_failure_at: fail_retention.then_some(2),
                query_hook: Some(Box::new(|| Err(-13))),
                ..Default::default()
            };
            let pending = posix_service::directory_request::execute(
                &state,
                peer,
                header,
                &payload,
                &[],
                &mut fs,
            );
            let response = finish(&state, peer, pending, Ok(()), &mut fs);
            assert_eq!(
                response.response.header.status,
                if fail_retention { -5 } else { -13 }
            );
            assert!(
                !fs.released
                    .iter()
                    .any(|h| h.handle == 200 || h.handle == 100 || h.handle == 101)
            );
            let dirs = *state.lock().unwrap().session_directories(99).unwrap();
            assert_eq!((dirs.root.handle, dirs.cwd.handle), (100, 101));
        }
    }
}

#[test]
fn chroot_uses_stored_privilege_and_does_not_treat_uid_zero_as_a_capability_bypass() {
    let (state, peer) = setup(501);
    let peer = PeerIdentity {
        effective_uid: 0,
        ..peer
    };
    let (header, payload) = request(protocol::OP_CHROOT_AT, protocol::OpenBase::ProcessRoot);
    let mut fs = RecordingFilesystem::default();
    let pending =
        posix_service::directory_request::execute(&state, peer, header, &payload, &[], &mut fs);
    assert_eq!(
        finish(&state, peer, pending, Ok(()), &mut fs)
            .response
            .header
            .status,
        protocol::STATUS_EPERM
    );
    assert_eq!(fs.roots_opened, 0);
    // A privileged POSIX identity still propagates filesystem capability denial.
    let (state, peer) = setup(0);
    let mut fs = RecordingFilesystem {
        query_hook: Some(Box::new(|| Err(-13))),
        ..Default::default()
    };
    let pending =
        posix_service::directory_request::execute(&state, peer, header, &payload, &[], &mut fs);
    assert_eq!(
        finish(&state, peer, pending, Ok(()), &mut fs)
            .response
            .header
            .status,
        -13
    );
}

#[test]
fn malformed_directory_requests_never_open_roots() {
    for opcode in OPS {
        let (state, peer) = setup(0);
        let (header, payload) = request(opcode, protocol::OpenBase::ProcessRoot);
        for header in [
            protocol::Header { flags: 1, ..header },
            protocol::Header {
                status: -1,
                ..header
            },
            protocol::Header {
                payload_len: 0,
                ..header
            },
        ] {
            let mut fs = RecordingFilesystem::default();
            let pending = posix_service::directory_request::execute(
                &state,
                peer,
                header,
                &payload,
                &[],
                &mut fs,
            );
            assert_eq!(
                finish(&state, peer, pending, Ok(()), &mut fs)
                    .response
                    .header
                    .status,
                STATUS_EINVAL
            );
            assert_eq!(fs.roots_opened, 0);
        }
    }
}

#[test]
fn getcwd_uses_retained_anchors_without_holding_state_and_propagates_backend_errors() {
    for error in [None, Some(-2)] {
        let (state, peer) = setup(501);
        let query_state = state.clone();
        let mut fs = RecordingFilesystem {
            directory_path: b"/folder-\xff".to_vec(),
            query_hook: Some(Box::new(move || {
                assert!(query_state.try_lock().is_ok());
                error.map_or(Ok(()), Err)
            })),
            ..Default::default()
        };
        let response = posix_service::path_query::execute(
            &state,
            peer,
            protocol::Header {
                opcode: protocol::OP_GETCWD,
                request_id: 107,
                ..Default::default()
            },
            &[],
            &[],
            &mut fs,
        );
        assert_eq!(response.response.header.status, error.unwrap_or(0));
        assert_eq!(
            response.response.payload,
            if error.is_none() {
                b"/folder-\xff".as_slice()
            } else {
                &[]
            }
        );
        assert_eq!(
            fs.released.iter().map(|h| h.handle).collect::<Vec<_>>(),
            [1100, 1101]
        );
        if error.is_none() {
            assert_eq!(fs.path_query.unwrap().0.handle, 1100);
        }
    }
}

#[test]
fn runtime_observes_native_image_before_installing_a_prepared_directory() {
    assert!(posix_service::path_query::supports(protocol::OP_GETCWD));
    assert!(posix_service::directory_request::supports(
        protocol::OP_FCHDIR
    ));
    // Structural wiring only; actual native image/IPC behavior remains unverified.
    let source = include_str!("../../src/main.rs");
    let preflight = source.split("let prepared_directory = ").nth(1).unwrap();
    assert!(
        preflight.find("directory_request::execute(").unwrap()
            < preflight
                .find("let mut service = service_state.lock().unwrap()")
                .unwrap()
    );
    let completion = preflight
        .split("if prepared_directory.is_some()")
        .nth(1)
        .unwrap();
    assert!(
        completion.find("validate_pending_request_image(").unwrap()
            < completion.find("directory_request::finish(").unwrap()
    );
}
