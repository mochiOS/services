use super::*;
use std::sync::{Arc, Mutex};

const BASES: [protocol::OpenBase; 3] = [
    protocol::OpenBase::ProcessRoot,
    protocol::OpenBase::ProcessCwd,
    protocol::OpenBase::AttachedDirectory,
];
const OPS: [u16; 2] = [protocol::OP_RENAME_AT, protocol::OP_LINK_AT];

fn setup() -> (Arc<Mutex<PosixService>>, PeerIdentity) {
    let peer = PeerIdentity {
        process_id: 97,
        effective_uid: 0,
        effective_gid: 0,
    };
    let mut service = PosixService::new();
    service
        .initialize_bootstrap_process(
            AuthenticatedProcess {
                handle: 97,
                process_id: 97,
            },
            501,
            20,
            &[20, 42],
        )
        .unwrap();
    (Arc::new(Mutex::new(service)), peer)
}

fn request(
    opcode: u16,
    old_base: protocol::OpenBase,
    new_base: protocol::OpenBase,
) -> (protocol::Header, Vec<u8>) {
    let mut bytes = vec![0; 256];
    let len = if opcode == protocol::OP_RENAME_AT {
        protocol::encode_rename_at(
            protocol::RenameAtRequest {
                old_base,
                new_base,
                old_path: b"old-\xff",
                new_path: b"new-\xfe",
            },
            &mut bytes,
        )
    } else {
        protocol::encode_link_at(
            protocol::LinkAtRequest {
                old_base,
                new_base,
                flags: protocol::LINK_FOLLOW_SOURCE,
                old_path: b"old-\xff",
                new_path: b"new-\xfe",
            },
            &mut bytes,
        )
    }
    .unwrap();
    bytes.truncate(len);
    (
        protocol::Header {
            opcode,
            request_id: 104,
            payload_len: len as u32,
            ..Default::default()
        },
        bytes,
    )
}

fn paths(fs: &RecordingFilesystem, opcode: u16) -> posix_service::RenamePathObjects<u32> {
    if opcode == protocol::OP_RENAME_AT {
        fs.rename_paths.unwrap()
    } else {
        fs.link_paths.unwrap()
    }
}

#[test]
fn every_base_pair_keeps_attachment_order_and_runs_one_unlocked_backend_transaction() {
    for opcode in OPS {
        for old_base in BASES {
            for new_base in BASES {
                let (state, peer) = setup();
                let root_state = state.clone();
                let operation_state = state.clone();
                let calls = std::rc::Rc::new(std::cell::Cell::new(0));
                let operation_calls = calls.clone();
                let mut fs = RecordingFilesystem {
                    root_hook: Some(Box::new(move || {
                        assert!(root_state.try_lock().is_ok());
                    })),
                    mutation_hook: Some(Box::new(move || {
                        assert!(operation_state.try_lock().is_ok());
                        operation_calls.set(operation_calls.get() + 1);
                        Ok(())
                    })),
                    ..Default::default()
                };
                let count = [old_base, new_base]
                    .iter()
                    .filter(|b| **b == protocol::OpenBase::AttachedDirectory)
                    .count();
                let attached: Vec<_> = (0..count)
                    .map(|i| AttachedObject {
                        handle: 75 + i as u32,
                        rights: mnu_abi::HANDLE_RIGHT_TRANSFER,
                    })
                    .collect();
                let (header, payload) = request(opcode, old_base, new_base);
                let response = posix_service::path_pair::execute(
                    &state, peer, header, &payload, &attached, &mut fs,
                );
                assert_eq!(response.response.header.status, 0);
                assert_eq!(response.response.header.request_id, 104);
                assert!(response.handles.is_empty());
                assert_eq!(calls.get(), 1);
                let resolved = paths(&fs, opcode);
                assert_eq!(resolved.root.handle, 1100);
                let mut next = attached.iter();
                let mut expected = |base| match base {
                    protocol::OpenBase::ProcessRoot => None,
                    protocol::OpenBase::ProcessCwd => Some(1101),
                    protocol::OpenBase::AttachedDirectory => Some(next.next().unwrap().handle),
                };
                assert_eq!(resolved.old_base.map(|h| h.handle), expected(old_base));
                assert_eq!(resolved.new_base.map(|h| h.handle), expected(new_base));
                let cwd = [old_base, new_base].contains(&protocol::OpenBase::ProcessCwd);
                assert_eq!(fs.retained.len(), if cwd { 2 } else { 1 });
                assert_eq!(
                    fs.released.iter().map(|h| h.handle).collect::<Vec<_>>(),
                    if cwd { vec![1100, 1101] } else { vec![1100] }
                );
                let (uid, gid, groups, old, new) = if opcode == protocol::OP_RENAME_AT {
                    let p = fs.rename_request.as_ref().unwrap();
                    (
                        p.effective_uid,
                        p.effective_gid,
                        &p.supplementary_groups,
                        &p.old_path,
                        &p.new_path,
                    )
                } else {
                    let p = fs.link_request.as_ref().unwrap();
                    assert_eq!(p.flags, protocol::LINK_FOLLOW_SOURCE);
                    (
                        p.effective_uid,
                        p.effective_gid,
                        &p.supplementary_groups,
                        &p.old_path,
                        &p.new_path,
                    )
                };
                assert_eq!((uid, gid), (501, 20));
                assert_eq!(groups, &[20, 42]);
                assert_eq!(old, b"old-\xff");
                assert_eq!(new, b"new-\xfe");
            }
        }
    }
}

#[test]
fn concurrent_cwd_change_cannot_mix_old_and_new_path_anchors() {
    for opcode in OPS {
        let (state, peer) = setup();
        let operation_state = state.clone();
        let mut fs = RecordingFilesystem {
            mutation_hook: Some(Box::new(move || {
                let mut service = operation_state.try_lock().unwrap();
                let mut other_fs = RecordingFilesystem {
                    stat_mode: Some(0o040755),
                    ..Default::default()
                };
                let response = service.handle_objects(
                    peer,
                    protocol::Header {
                        opcode: protocol::OP_FCHDIR,
                        ..Default::default()
                    },
                    &[],
                    &[AttachedObject {
                        handle: 58,
                        rights: 0x81,
                    }],
                    &mut other_fs,
                );
                assert_eq!(response.response.header.status, 0);
                assert_eq!(other_fs.released[0].handle, 101);
                Ok(())
            })),
            ..Default::default()
        };
        let (header, payload) = request(
            opcode,
            protocol::OpenBase::ProcessCwd,
            protocol::OpenBase::ProcessCwd,
        );
        let response =
            posix_service::path_pair::execute(&state, peer, header, &payload, &[], &mut fs);
        assert_eq!(response.response.header.status, 0);
        let resolved = paths(&fs, opcode);
        assert_eq!(resolved.old_base.unwrap().handle, 1101);
        assert_eq!(resolved.new_base.unwrap().handle, 1101);
        assert_eq!(
            state
                .lock()
                .unwrap()
                .session_directories(97)
                .unwrap()
                .cwd
                .handle,
            1058
        );
        assert_eq!(fs.retained.len(), 2);
    }
}

#[test]
fn changed_credentials_during_root_open_abort_before_either_namespace_operation() {
    for opcode in OPS {
        let peer = PeerIdentity {
            process_id: 97,
            effective_uid: 0,
            effective_gid: 0,
        };
        let state = Arc::new(Mutex::new(service_for(peer)));
        let root_state = state.clone();
        let mut fs = RecordingFilesystem {
            root_hook: Some(Box::new(move || {
                let payload = 501u32.to_le_bytes();
                let response = root_state.try_lock().unwrap().handle(
                    peer,
                    protocol::Header {
                        opcode: protocol::OP_SET_EFFECTIVE_UID,
                        payload_len: payload.len() as u32,
                        ..Default::default()
                    },
                    &payload,
                );
                assert_eq!(response.header.status, 0);
            })),
            mutation_hook: Some(Box::new(|| {
                panic!("no namespace operation with stale credentials")
            })),
            ..Default::default()
        };
        let (header, payload) = request(
            opcode,
            protocol::OpenBase::ProcessCwd,
            protocol::OpenBase::ProcessRoot,
        );
        let response =
            posix_service::path_pair::execute(&state, peer, header, &payload, &[], &mut fs);
        assert_eq!(response.response.header.status, protocol::STATUS_EAGAIN);
        assert!(state.lock().unwrap().session_directories(97).is_none());
        assert_eq!(
            fs.released.iter().map(|h| h.handle).collect::<Vec<_>>(),
            [100, 101]
        );
    }
}

#[test]
fn failed_retention_does_not_reach_the_namespace_and_backend_errors_are_not_retried() {
    for opcode in OPS {
        let (state, peer) = setup();
        let (header, payload) = request(
            opcode,
            protocol::OpenBase::ProcessRoot,
            protocol::OpenBase::ProcessCwd,
        );
        let mut fs = RecordingFilesystem {
            retain_failure_at: Some(2),
            mutation_hook: Some(Box::new(|| panic!("no mutation after failed retention"))),
            ..Default::default()
        };
        assert_eq!(
            posix_service::path_pair::execute(&state, peer, header, &payload, &[], &mut fs)
                .response
                .header
                .status,
            -5
        );
        assert_eq!(
            fs.released.iter().map(|h| h.handle).collect::<Vec<_>>(),
            [1100]
        );
        let calls = std::rc::Rc::new(std::cell::Cell::new(0));
        let operation_calls = calls.clone();
        let mut fs = RecordingFilesystem {
            mutation_hook: Some(Box::new(move || {
                operation_calls.set(operation_calls.get() + 1);
                Err(-18)
            })),
            ..Default::default()
        };
        assert_eq!(
            posix_service::path_pair::execute(&state, peer, header, &payload, &[], &mut fs)
                .response
                .header
                .status,
            -18
        );
        assert_eq!(calls.get(), 1);
        assert_eq!(
            fs.released.iter().map(|h| h.handle).collect::<Vec<_>>(),
            [1100, 1101]
        );
    }
}

#[test]
fn malformed_framing_and_missing_or_extra_directories_do_not_open_roots() {
    for opcode in OPS {
        let (state, peer) = setup();
        let (header, payload) = request(
            opcode,
            protocol::OpenBase::AttachedDirectory,
            protocol::OpenBase::AttachedDirectory,
        );
        let attached: Vec<_> = (75..78)
            .map(|handle| AttachedObject {
                handle,
                rights: mnu_abi::HANDLE_RIGHT_TRANSFER,
            })
            .collect();
        for handles in [&attached[..0], &attached[..1], &attached[..3]] {
            let mut fs = RecordingFilesystem::default();
            assert_eq!(
                posix_service::path_pair::execute(&state, peer, header, &payload, handles, &mut fs)
                    .response
                    .header
                    .status,
                STATUS_EINVAL
            );
            assert_eq!(fs.roots_opened, 0);
        }
        for header in [
            protocol::Header {
                payload_len: 0,
                ..header
            },
            protocol::Header {
                flags: protocol::MUTATION_ADMISSION,
                ..header
            },
            protocol::Header {
                status: -1,
                ..header
            },
        ] {
            let mut fs = RecordingFilesystem::default();
            assert_eq!(
                posix_service::path_pair::execute(
                    &state,
                    peer,
                    header,
                    &payload,
                    &attached[..2],
                    &mut fs
                )
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
fn image_rejection_never_replays_a_committed_namespace_operation() {
    for opcode in OPS {
        let (state, peer) = setup();
        let (header, payload) = request(
            opcode,
            protocol::OpenBase::ProcessRoot,
            protocol::OpenBase::ProcessRoot,
        );
        let calls = std::rc::Rc::new(std::cell::Cell::new(0));
        let operation_calls = calls.clone();
        let mut fs = RecordingFilesystem {
            mutation_hook: Some(Box::new(move || {
                operation_calls.set(operation_calls.get() + 1);
                Ok(())
            })),
            ..Default::default()
        };
        let response =
            posix_service::path_pair::execute(&state, peer, header, &payload, &[], &mut fs);
        // A post-RPC image rejection cannot undo FS effects; it must not retry.
        let response =
            posix_service::open_request::finish(response, Err(protocol::STATUS_ESRCH), &mut fs);
        assert_eq!(response.response.header.status, protocol::STATUS_ESRCH);
        assert!(response.handles.is_empty());
        assert_eq!(calls.get(), 1);
    }
}

#[test]
fn runtime_only_dispatches_pair_operations_before_locking_posix_state() {
    for opcode in OPS {
        assert!(posix_service::path_pair::supports(opcode));
    }
    for opcode in [
        protocol::OP_CHDIR_AT,
        protocol::OP_OPEN_AT,
        protocol::OP_UNLINK_AT,
        u16::MAX,
    ] {
        assert!(!posix_service::path_pair::supports(opcode));
        let (state, peer) = setup();
        let mut fs = RecordingFilesystem::default();
        assert_eq!(
            posix_service::path_pair::execute(
                &state,
                peer,
                protocol::Header {
                    opcode,
                    ..Default::default()
                },
                &[],
                &[],
                &mut fs
            )
            .response
            .header
            .status,
            protocol::STATUS_ENOSYS
        );
        assert_eq!(fs.roots_opened, 0);
    }
    // Structural wiring only, not native OS integration evidence.
    let source = include_str!("../../src/main.rs");
    let preflight = source.split("let prepared_path = ").nth(1).unwrap();
    assert!(
        preflight.find("path_pair::execute(").unwrap()
            < preflight
                .find("let mut service = service_state.lock().unwrap()")
                .unwrap()
    );
}
