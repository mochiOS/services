use super::*;
use std::sync::{Arc, Mutex};

const OPERATIONS: [u16; 7] = [
    protocol::OP_MKDIR_AT,
    protocol::OP_UNLINK_AT,
    protocol::OP_TRUNCATE_AT,
    protocol::OP_SYMLINK_AT,
    protocol::OP_UTIMENS_AT,
    protocol::OP_CHMOD_AT,
    protocol::OP_CHOWN_AT,
];
const PATH: &[u8] = b"../file-\xff";

fn setup() -> (Arc<Mutex<PosixService>>, PeerIdentity) {
    // Incoming claims cannot replace credentials registered in service state.
    let peer = PeerIdentity {
        process_id: 95,
        effective_uid: 0,
        effective_gid: 0,
    };
    let mut service = PosixService::new();
    service
        .initialize_bootstrap_process(
            AuthenticatedProcess {
                handle: 95,
                process_id: peer.process_id,
            },
            501,
            20,
            &[20, 42],
        )
        .unwrap();
    let mask = 0o027u32.to_le_bytes();
    let response = service.handle(
        peer,
        protocol::Header {
            opcode: protocol::OP_UMASK_SET,
            payload_len: mask.len() as u32,
            ..Default::default()
        },
        &mask,
    );
    assert_eq!(response.header.status, 0);
    (Arc::new(Mutex::new(service)), peer)
}

fn request(opcode: u16, base: protocol::OpenBase) -> (protocol::Header, Vec<u8>) {
    let mut payload = vec![0; 256];
    let length = match opcode {
        protocol::OP_MKDIR_AT | protocol::OP_CHMOD_AT => protocol::encode_open_at(
            protocol::OpenAtRequest {
                base,
                options: 0,
                mode: 0o6777,
                path: PATH,
            },
            &mut payload,
        ),
        protocol::OP_UNLINK_AT => protocol::encode_stat_at(
            protocol::StatAtRequest {
                base,
                flags: protocol::UNLINK_REMOVE_DIRECTORY,
                path: PATH,
            },
            &mut payload,
        ),
        protocol::OP_TRUNCATE_AT => protocol::encode_truncate_at(
            protocol::TruncateAtRequest {
                base,
                length: 4096,
                path: PATH,
            },
            &mut payload,
        ),
        protocol::OP_SYMLINK_AT => protocol::encode_symlink_at(
            protocol::SymlinkAtRequest {
                base,
                target: b"../target-\xfe",
                link_path: PATH,
            },
            &mut payload,
        ),
        protocol::OP_UTIMENS_AT => protocol::file_time::encode_at(
            protocol::file_time::AtRequest {
                target: protocol::StatAtRequest {
                    base,
                    flags: protocol::STAT_NOFOLLOW,
                    path: PATH,
                },
                times: protocol::file_time::Update {
                    access: protocol::file_time::Change::Omit,
                    modification: protocol::file_time::Change::Set {
                        seconds: -1,
                        nanoseconds: 123,
                    },
                },
            },
            &mut payload,
        ),
        protocol::OP_CHOWN_AT => protocol::encode_chown_at(
            protocol::ChownAtRequest {
                base,
                flags: protocol::CHOWN_NOFOLLOW,
                uid: 502,
                gid: 21,
                path: PATH,
            },
            &mut payload,
        ),
        _ => unreachable!(),
    }
    .unwrap();
    payload.truncate(length);
    (
        protocol::Header {
            opcode,
            request_id: 102,
            payload_len: length as u32,
            ..Default::default()
        },
        payload,
    )
}

fn check_policy(fs: &RecordingFilesystem, opcode: u16) {
    let (uid, gid, groups, path) = match opcode {
        protocol::OP_MKDIR_AT => {
            let p = fs.mkdir_request.as_ref().unwrap();
            assert_eq!(p.mode, 0o6750);
            (
                p.effective_uid,
                p.effective_gid,
                &p.supplementary_groups,
                &p.path,
            )
        }
        protocol::OP_UNLINK_AT => {
            let p = fs.unlink_request.as_ref().unwrap();
            assert_eq!(p.flags, protocol::UNLINK_REMOVE_DIRECTORY);
            (
                p.effective_uid,
                p.effective_gid,
                &p.supplementary_groups,
                &p.path,
            )
        }
        protocol::OP_TRUNCATE_AT => {
            let p = fs.truncate_request.as_ref().unwrap();
            assert_eq!(p.length, 4096);
            (
                p.effective_uid,
                p.effective_gid,
                &p.supplementary_groups,
                &p.path,
            )
        }
        protocol::OP_SYMLINK_AT => {
            let p = fs.symlink_request.as_ref().unwrap();
            assert_eq!(p.target, b"../target-\xfe");
            (
                p.effective_uid,
                p.effective_gid,
                &p.supplementary_groups,
                &p.link_path,
            )
        }
        protocol::OP_UTIMENS_AT => {
            let p = fs.time_request.as_ref().unwrap();
            assert_eq!(p.target.flags, protocol::STAT_NOFOLLOW);
            assert_eq!(p.times.access, protocol::file_time::Change::Omit);
            assert_eq!(
                p.times.modification,
                protocol::file_time::Change::Set {
                    seconds: -1,
                    nanoseconds: 123
                }
            );
            (
                p.target.effective_uid,
                p.target.effective_gid,
                &p.target.supplementary_groups,
                &p.target.path,
            )
        }
        protocol::OP_CHMOD_AT => {
            let p = fs.chmod_request.as_ref().unwrap();
            assert_eq!(p.mode, 0o6777);
            (
                p.effective_uid,
                p.effective_gid,
                &p.supplementary_groups,
                &p.path,
            )
        }
        protocol::OP_CHOWN_AT => {
            let p = fs.chown_request.as_ref().unwrap();
            assert_eq!((p.uid, p.gid, p.flags), (502, 21, protocol::CHOWN_NOFOLLOW));
            (
                p.effective_uid,
                p.effective_gid,
                &p.supplementary_groups,
                &p.path,
            )
        }
        _ => unreachable!(),
    };
    assert_eq!((uid, gid), (501, 20));
    assert_eq!(groups, &[20, 42]);
    assert_eq!(path, PATH);
}

#[test]
fn mutations_use_stored_policy_and_one_unlocked_backend_operation_with_retained_anchors() {
    for opcode in OPERATIONS {
        let (state, peer) = setup();
        let root_state = state.clone();
        let mutation_state = state.clone();
        let calls = std::rc::Rc::new(std::cell::Cell::new(0));
        let operation_calls = calls.clone();
        let mut fs = RecordingFilesystem {
            root_hook: Some(Box::new(move || {
                assert!(root_state.try_lock().is_ok());
            })),
            mutation_hook: Some(Box::new(move || {
                assert!(mutation_state.try_lock().is_ok());
                operation_calls.set(operation_calls.get() + 1);
                Ok(())
            })),
            ..Default::default()
        };
        let (header, payload) = request(opcode, protocol::OpenBase::ProcessCwd);
        let response =
            posix_service::path_mutation::execute(&state, peer, header, &payload, &[], &mut fs);
        assert_eq!(response.response.header.status, 0);
        assert_eq!(response.response.header.request_id, 102);
        assert!(response.handles.is_empty());
        assert_eq!(calls.get(), 1);
        assert_eq!(fs.root.unwrap().handle, 1100);
        assert_eq!(fs.directory.unwrap().handle, 1101);
        assert_eq!(
            fs.released.iter().map(|h| h.handle).collect::<Vec<_>>(),
            [1100, 1101]
        );
        assert_eq!(fs.root_credentials, Some((501, 20, vec![20, 42])));
        check_policy(&fs, opcode);
    }
}

#[test]
fn backend_errors_preserve_status_and_release_all_path_anchors() {
    for opcode in OPERATIONS {
        let (state, peer) = setup();
        let (header, payload) = request(opcode, protocol::OpenBase::ProcessCwd);
        let mut fs = RecordingFilesystem {
            mutation_hook: Some(Box::new(|| Err(-13))),
            ..Default::default()
        };
        let response =
            posix_service::path_mutation::execute(&state, peer, header, &payload, &[], &mut fs);
        assert_eq!(response.response.header.status, -13);
        assert!(response.handles.is_empty());
        assert_eq!(
            fs.released.iter().map(|h| h.handle).collect::<Vec<_>>(),
            [1100, 1101]
        );
    }
}

#[test]
fn root_and_explicit_directory_bases_do_not_duplicate_the_incoming_directory() {
    for opcode in OPERATIONS {
        for base in [
            protocol::OpenBase::ProcessRoot,
            protocol::OpenBase::AttachedDirectory,
        ] {
            let (state, peer) = setup();
            let (header, payload) = request(opcode, base);
            let attached = [AttachedObject {
                handle: 75,
                rights: mnu_abi::HANDLE_RIGHT_TRANSFER,
            }];
            let handles = if base == protocol::OpenBase::AttachedDirectory {
                &attached[..]
            } else {
                &[]
            };
            let mut fs = RecordingFilesystem::default();
            let response = posix_service::path_mutation::execute(
                &state, peer, header, &payload, handles, &mut fs,
            );
            assert_eq!(response.response.header.status, 0);
            assert_eq!(fs.directory, handles.first().copied());
            assert_eq!(fs.retained.len(), 1);
            assert_eq!(
                fs.released.iter().map(|h| h.handle).collect::<Vec<_>>(),
                [1100]
            );
        }
    }
}

#[test]
fn truncate_wait_ticket_is_returned_without_mutation_then_explicitly_retried() {
    let (state, peer) = setup();
    let (mut header, payload) = request(
        protocol::OP_TRUNCATE_AT,
        protocol::OpenBase::AttachedDirectory,
    );
    header.flags = protocol::MUTATION_ADMISSION;
    let ticket = OpenedObject {
        handle: 76,
        rights: posix_service::mutation_admission::TICKET_RIGHTS,
    };
    let directory = AttachedObject {
        handle: 75,
        rights: mnu_abi::HANDLE_RIGHT_TRANSFER,
    };
    let mut fs = RecordingFilesystem {
        admission_response: Some(Ok(ticket)),
        ..Default::default()
    };
    let first = posix_service::path_mutation::execute(
        &state,
        peer,
        header,
        &payload,
        &[directory],
        &mut fs,
    );
    assert_eq!(
        first.response.header.status,
        protocol::STATUS_MEMORY_ADMISSION_BUSY
    );
    assert_eq!(first.handles, [ticket]);
    assert!(fs.truncate_request.is_none());
    assert_eq!(fs.admission_calls, [(protocol::OP_TRUNCATE_AT, None)]);
    assert_eq!(
        fs.released.iter().map(|h| h.handle).collect::<Vec<_>>(),
        [1100]
    );
    fs.admission_response = None;
    header.flags |= protocol::MUTATION_ADMISSION_ATTACHED;
    let attachments = [
        directory,
        AttachedObject {
            handle: 77,
            rights: ticket.rights,
        },
    ];
    let second = posix_service::path_mutation::execute(
        &state,
        peer,
        header,
        &payload,
        &attachments,
        &mut fs,
    );
    assert_eq!(second.response.header.status, 0);
    assert_eq!(
        fs.admission_calls.last().unwrap(),
        &(protocol::OP_TRUNCATE_AT, Some(attachments[1]))
    );
    assert_eq!(fs.directory, Some(directory));
    check_policy(&fs, protocol::OP_TRUNCATE_AT);
    assert!(fs.retained.iter().all(|h| h.handle == 100));
}

#[test]
fn malformed_mutations_do_not_initialize_roots_or_reach_filesystem() {
    for opcode in OPERATIONS {
        let (state, peer) = setup();
        let (header, payload) = request(opcode, protocol::OpenBase::ProcessRoot);
        for header in [
            protocol::Header {
                payload_len: 0,
                ..header
            },
            protocol::Header {
                status: -1,
                ..header
            },
            protocol::Header { flags: 1, ..header },
        ] {
            let mut fs = RecordingFilesystem::default();
            assert_eq!(
                posix_service::path_mutation::execute(&state, peer, header, &payload, &[], &mut fs)
                    .response
                    .header
                    .status,
                STATUS_EINVAL
            );
            assert_eq!(fs.roots_opened, 0);
        }
        let (header, payload) = request(opcode, protocol::OpenBase::AttachedDirectory);
        let mut fs = RecordingFilesystem::default();
        assert_eq!(
            posix_service::path_mutation::execute(&state, peer, header, &payload, &[], &mut fs)
                .response
                .header
                .status,
            STATUS_EINVAL
        );
        assert_eq!(fs.roots_opened, 0);
    }
}

#[test]
fn partial_anchor_failure_never_performs_a_mutation() {
    for opcode in OPERATIONS {
        let (state, peer) = setup();
        let (header, payload) = request(opcode, protocol::OpenBase::ProcessCwd);
        let mut fs = RecordingFilesystem {
            retain_failure_at: Some(2),
            mutation_hook: Some(Box::new(|| {
                panic!("no operation after preparation failure")
            })),
            ..Default::default()
        };
        assert_eq!(
            posix_service::path_mutation::execute(&state, peer, header, &payload, &[], &mut fs)
                .response
                .header
                .status,
            -5
        );
        assert_eq!(
            fs.released.iter().map(|h| h.handle).collect::<Vec<_>>(),
            [1100]
        );
    }
}

#[test]
fn truncate_retry_captures_the_current_file_size_limit_and_does_not_reuse_old_policy() {
    let (state, peer) = setup();
    let set_limit = |soft| {
        let mut bytes = [0u8; protocol::RESOURCE_LIMIT_REQUEST_LEN];
        protocol::encode_resource_limit_request(
            protocol::ResourceLimitRequest {
                process_id: 0,
                resource: protocol::RLIMIT_FSIZE,
                flags: protocol::RESOURCE_LIMIT_SET,
                limit: protocol::ResourceLimit {
                    soft,
                    hard: u64::MAX,
                },
            },
            &mut bytes,
        )
        .unwrap();
        let response = state.lock().unwrap().handle(
            peer,
            protocol::Header {
                opcode: protocol::OP_RESOURCE_LIMIT,
                payload_len: bytes.len() as u32,
                ..Default::default()
            },
            &bytes,
        );
        assert_eq!(response.header.status, 0);
    };
    set_limit(8192);
    let (mut header, payload) = request(protocol::OP_TRUNCATE_AT, protocol::OpenBase::ProcessRoot);
    header.flags = protocol::MUTATION_ADMISSION;
    let ticket = OpenedObject {
        handle: 76,
        rights: posix_service::mutation_admission::TICKET_RIGHTS,
    };
    let mut fs = RecordingFilesystem {
        admission_response: Some(Ok(ticket)),
        ..Default::default()
    };
    let first = posix_service::path_mutation::execute(&state, peer, header, &payload, &[], &mut fs);
    assert_eq!(first.handles, [ticket]);
    assert!(fs.truncate_request.is_none());
    set_limit(4096);
    fs.admission_response = None;
    header.flags |= protocol::MUTATION_ADMISSION_ATTACHED;
    let attached = [AttachedObject {
        handle: 77,
        rights: ticket.rights,
    }];
    let response =
        posix_service::path_mutation::execute(&state, peer, header, &payload, &attached, &mut fs);
    assert_eq!(response.response.header.status, 0);
    assert_eq!(fs.truncate_request.unwrap().growth_ceiling, 4096);
    assert!(response.handles.is_empty());
}

#[test]
fn admission_envelope_cannot_be_used_for_other_mutations_or_weakened_tickets() {
    for opcode in OPERATIONS
        .into_iter()
        .filter(|opcode| *opcode != protocol::OP_TRUNCATE_AT)
    {
        let (state, peer) = setup();
        let (mut header, payload) = request(opcode, protocol::OpenBase::ProcessRoot);
        header.flags = protocol::MUTATION_ADMISSION;
        let mut fs = RecordingFilesystem::default();
        let response =
            posix_service::path_mutation::execute(&state, peer, header, &payload, &[], &mut fs);
        assert_eq!(response.response.header.status, STATUS_EINVAL);
        assert_eq!(fs.roots_opened, 0);
    }
    let (state, peer) = setup();
    let (mut header, payload) = request(protocol::OP_TRUNCATE_AT, protocol::OpenBase::ProcessRoot);
    header.flags = protocol::MUTATION_ADMISSION | protocol::MUTATION_ADMISSION_ATTACHED;
    let mut fs = RecordingFilesystem::default();
    let attached = [AttachedObject {
        handle: 77,
        rights: mnu_abi::HANDLE_RIGHT_TRANSFER,
    }];
    assert_eq!(
        posix_service::path_mutation::execute(&state, peer, header, &payload, &attached, &mut fs)
            .response
            .header
            .status,
        -13
    );
    assert_eq!(fs.roots_opened, 0);
    // A retry promise needs an owned ticket, not a bare memory-busy errno.
    header.flags = protocol::MUTATION_ADMISSION;
    fs.admission_response = Some(Err(protocol::STATUS_MEMORY_ADMISSION_BUSY));
    assert_eq!(
        posix_service::path_mutation::execute(&state, peer, header, &payload, &[], &mut fs)
            .response
            .header
            .status,
        protocol::STATUS_EIO
    );
}

#[test]
fn image_rejection_discards_ticket_and_runtime_dispatch_precedes_the_state_lock() {
    let (state, peer) = setup();
    let (mut header, payload) = request(protocol::OP_TRUNCATE_AT, protocol::OpenBase::ProcessRoot);
    header.flags = protocol::MUTATION_ADMISSION;
    let ticket = OpenedObject {
        handle: 76,
        rights: posix_service::mutation_admission::TICKET_RIGHTS,
    };
    let mut fs = RecordingFilesystem {
        admission_response: Some(Ok(ticket)),
        ..Default::default()
    };
    let response =
        posix_service::path_mutation::execute(&state, peer, header, &payload, &[], &mut fs);
    let response =
        posix_service::open_request::finish(response, Err(protocol::STATUS_ESRCH), &mut fs);
    assert_eq!(response.response.header.status, protocol::STATUS_ESRCH);
    assert!(response.handles.is_empty());
    assert_eq!(fs.released.last().unwrap().handle, ticket.handle);
    for opcode in OPERATIONS {
        assert!(posix_service::path_mutation::supports(opcode));
    }
    for opcode in [
        protocol::OP_CHDIR_AT,
        protocol::OP_CHROOT_AT,
        protocol::OP_RENAME_AT,
        protocol::OP_LINK_AT,
        protocol::OP_OPEN_AT,
        protocol::OP_STAT_AT,
    ] {
        assert!(!posix_service::path_mutation::supports(opcode));
    }
    // Structural wiring check only; real IPC still needs a native OS test.
    let source = include_str!("../../src/main.rs");
    let preflight = source.split("let prepared_path = ").nth(1).unwrap();
    assert!(
        preflight.find("path_mutation::execute(").unwrap()
            < preflight
                .find("let mut service = service_state.lock().unwrap()")
                .unwrap()
    );
}
