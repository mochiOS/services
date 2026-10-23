use super::*;
use std::sync::{Arc, Mutex};

const OPS: [u16; 5] = [
    protocol::OP_FTRUNCATE,
    protocol::OP_FUTIMENS,
    protocol::OP_FCHMOD,
    protocol::OP_FCHOWN,
    protocol::OP_FSYNC,
];

fn setup() -> (Arc<Mutex<PosixService>>, PeerIdentity) {
    let peer = PeerIdentity {
        process_id: 105,
        effective_uid: 0,
        effective_gid: 0,
    };
    let mut service = PosixService::new();
    service
        .initialize_bootstrap_process(
            AuthenticatedProcess {
                process_id: 105,
                handle: 105,
            },
            501,
            20,
            &[20, 42],
        )
        .unwrap();
    (Arc::new(Mutex::new(service)), peer)
}

fn source(opcode: u16) -> AttachedObject<u32> {
    AttachedObject {
        handle: 82,
        rights: protocol::file_mutation_rights(opcode).unwrap_or(mnu_abi::HANDLE_RIGHT_TRANSFER),
    }
}

fn request(opcode: u16) -> (protocol::Header, Vec<u8>) {
    let mut payload = Vec::new();
    match opcode {
        protocol::OP_FTRUNCATE => payload.extend_from_slice(&4096u64.to_le_bytes()),
        protocol::OP_FUTIMENS => {
            payload.resize(protocol::file_time::UPDATE_LEN, 0);
            protocol::file_time::encode(
                protocol::file_time::Update {
                    access: protocol::file_time::Change::Now,
                    modification: protocol::file_time::Change::Omit,
                },
                &mut payload,
            )
            .unwrap();
        }
        protocol::OP_FCHMOD => payload.extend_from_slice(&0o6750u32.to_le_bytes()),
        protocol::OP_FCHOWN => {
            payload.resize(protocol::FILE_OWNER_PAYLOAD_LEN, 0);
            protocol::encode_file_owner(700, 701, &mut payload).unwrap();
        }
        protocol::OP_FSYNC => {}
        _ => unreachable!(),
    }
    (
        protocol::Header {
            opcode,
            request_id: 110,
            payload_len: payload.len() as u32,
            ..Default::default()
        },
        payload,
    )
}

#[test]
fn every_operation_runs_one_unlocked_backend_call_using_only_the_borrowed_file() {
    for opcode in OPS {
        let (state, peer) = setup();
        let call_state = state.clone();
        let calls = std::rc::Rc::new(std::cell::Cell::new(0));
        let operation_calls = calls.clone();
        let mut fs = RecordingFilesystem {
            file_hook: Some(Box::new(move |actual| {
                assert_eq!(actual, opcode);
                assert!(call_state.try_lock().is_ok());
                operation_calls.set(operation_calls.get() + 1);
                Ok(())
            })),
            ..Default::default()
        };
        let (header, payload) = request(opcode);
        let file = source(opcode);
        let response =
            posix_service::file_request::execute(&state, peer, header, &payload, &[file], &mut fs);
        assert_eq!(response.response.header.status, 0);
        assert_eq!(response.response.header.request_id, 110);
        assert!(response.handles.is_empty());
        assert_eq!(calls.get(), 1);
        assert_eq!(fs.roots_opened, 0);
        assert!(fs.retained.is_empty() && fs.released.is_empty());
        match opcode {
            protocol::OP_FTRUNCATE => {
                assert_eq!(fs.truncated, Some((file, 4096)));
                assert_eq!(fs.truncate_ceiling, Some(u64::MAX));
            }
            protocol::OP_FUTIMENS => {
                let (actual, times, uid, gid, groups) = fs.time_file.unwrap();
                assert_eq!(actual, file);
                assert_eq!((uid, gid), (501, 20));
                assert_eq!(groups, [20, 42]);
                assert_eq!(times.access, protocol::file_time::Change::Now);
                assert_eq!(times.modification, protocol::file_time::Change::Omit);
            }
            protocol::OP_FCHMOD => {
                assert_eq!(fs.chmod_file, Some((file, 0o6750, 501, 20)));
                assert_eq!(fs.chmod_groups, [20, 42]);
            }
            protocol::OP_FCHOWN => {
                assert_eq!(fs.chown_file, Some((file, 700, 701, 501, 20)));
                assert_eq!(fs.chown_groups, [20, 42]);
            }
            protocol::OP_FSYNC => assert_eq!(fs.synced, Some(file)),
            _ => unreachable!(),
        }
    }
}

#[test]
fn missing_file_authority_is_rejected_before_any_backend_operation() {
    for opcode in OPS {
        let (state, peer) = setup();
        let (header, payload) = request(opcode);
        let required = source(opcode).rights;
        for rights in [
            0,
            required & !mnu_abi::HANDLE_RIGHT_TRANSFER,
            if protocol::file_mutation_rights(opcode).is_some() {
                mnu_abi::HANDLE_RIGHT_TRANSFER
            } else {
                0
            },
        ] {
            let mut fs = RecordingFilesystem {
                file_hook: Some(Box::new(|_| panic!("unauthorized backend call"))),
                ..Default::default()
            };
            let response = posix_service::file_request::execute(
                &state,
                peer,
                header,
                &payload,
                &[AttachedObject {
                    rights,
                    ..source(opcode)
                }],
                &mut fs,
            );
            assert_eq!(response.response.header.status, -13);
            assert!(fs.released.is_empty());
        }
    }
}

#[test]
fn backend_errors_are_propagated_without_retry_or_reference_changes() {
    for opcode in OPS {
        let (state, peer) = setup();
        let (header, payload) = request(opcode);
        let calls = std::rc::Rc::new(std::cell::Cell::new(0));
        let operation_calls = calls.clone();
        let mut fs = RecordingFilesystem {
            file_hook: Some(Box::new(move |_| {
                operation_calls.set(operation_calls.get() + 1);
                Err(-5)
            })),
            ..Default::default()
        };
        let response = posix_service::file_request::execute(
            &state,
            peer,
            header,
            &payload,
            &[source(opcode)],
            &mut fs,
        );
        assert_eq!(response.response.header.status, -5);
        assert_eq!(calls.get(), 1);
        assert!(fs.retained.is_empty() && fs.released.is_empty());
    }
}

#[test]
fn malformed_frames_and_payloads_do_not_reach_the_backend() {
    for opcode in OPS {
        let (state, peer) = setup();
        let (header, payload) = request(opcode);
        for header in [
            protocol::Header { flags: 1, ..header },
            protocol::Header {
                status: -1,
                ..header
            },
            protocol::Header {
                payload_len: u32::MAX,
                ..header
            },
        ] {
            let mut fs = RecordingFilesystem {
                file_hook: Some(Box::new(|_| panic!("malformed call"))),
                ..Default::default()
            };
            assert_eq!(
                posix_service::file_request::execute(
                    &state,
                    peer,
                    header,
                    &payload,
                    &[source(opcode)],
                    &mut fs
                )
                .response
                .header
                .status,
                STATUS_EINVAL
            );
        }
        for files in [vec![], vec![source(opcode), source(opcode)]] {
            let mut fs = RecordingFilesystem::default();
            assert_eq!(
                posix_service::file_request::execute(
                    &state, peer, header, &payload, &files, &mut fs
                )
                .response
                .header
                .status,
                STATUS_EINVAL
            );
        }
        let bad = if payload.is_empty() { vec![1] } else { vec![] };
        let mut fs = RecordingFilesystem {
            file_hook: Some(Box::new(|_| panic!("invalid payload"))),
            ..Default::default()
        };
        assert_eq!(
            posix_service::file_request::execute(
                &state,
                peer,
                protocol::Header {
                    payload_len: bad.len() as u32,
                    ..header
                },
                &bad,
                &[source(opcode)],
                &mut fs
            )
            .response
            .header
            .status,
            STATUS_EINVAL
        );
    }
}

#[test]
fn truncate_ticket_retry_uses_latest_limit_and_keeps_input_references_borrowed() {
    let (state, peer) = setup();
    let set_limit = |soft| {
        let mut payload = [0; protocol::RESOURCE_LIMIT_REQUEST_LEN];
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
            &mut payload,
        )
        .unwrap();
        assert_eq!(
            state
                .lock()
                .unwrap()
                .handle(
                    peer,
                    protocol::Header {
                        opcode: protocol::OP_RESOURCE_LIMIT,
                        payload_len: payload.len() as u32,
                        ..Default::default()
                    },
                    &payload
                )
                .header
                .status,
            0
        );
    };
    set_limit(8192);
    let (mut header, payload) = request(protocol::OP_FTRUNCATE);
    header.flags = protocol::MUTATION_ADMISSION;
    let ticket = OpenedObject {
        handle: 90,
        rights: posix_service::mutation_admission::TICKET_RIGHTS,
    };
    let mut fs = RecordingFilesystem {
        admission_response: Some(Ok(ticket)),
        ..Default::default()
    };
    let first = posix_service::file_request::execute(
        &state,
        peer,
        header,
        &payload,
        &[source(header.opcode)],
        &mut fs,
    );
    assert_eq!(
        first.response.header.status,
        protocol::STATUS_MEMORY_ADMISSION_BUSY
    );
    assert_eq!(first.handles, [ticket]);
    assert!(fs.truncated.is_none());
    set_limit(4096);
    fs.admission_response = None;
    header.flags |= protocol::MUTATION_ADMISSION_ATTACHED;
    let inputs = [
        source(header.opcode),
        AttachedObject {
            handle: 91,
            rights: ticket.rights,
        },
    ];
    let response =
        posix_service::file_request::execute(&state, peer, header, &payload, &inputs, &mut fs);
    assert_eq!(response.response.header.status, 0);
    assert_eq!(fs.truncate_ceiling, Some(4096));
    assert_eq!(
        fs.admission_calls,
        [
            (protocol::OP_FTRUNCATE, None),
            (protocol::OP_FTRUNCATE, Some(inputs[1]))
        ]
    );
    assert!(fs.retained.is_empty() && fs.released.is_empty());
}

#[test]
fn rejected_image_discards_empty_reply_or_owned_wait_ticket_without_replaying_operation() {
    for opcode in [protocol::OP_FSYNC, protocol::OP_FTRUNCATE] {
        let (state, peer) = setup();
        let (mut header, payload) = request(opcode);
        let ticket = OpenedObject {
            handle: 90,
            rights: posix_service::mutation_admission::TICKET_RIGHTS,
        };
        let mut fs = RecordingFilesystem {
            admission_response: (opcode == protocol::OP_FTRUNCATE).then_some(Ok(ticket)),
            ..Default::default()
        };
        if opcode == protocol::OP_FTRUNCATE {
            header.flags = protocol::MUTATION_ADMISSION;
        }
        let response = posix_service::file_request::execute(
            &state,
            peer,
            header,
            &payload,
            &[source(opcode)],
            &mut fs,
        );
        let response =
            posix_service::open_request::finish(response, Err(protocol::STATUS_ESRCH), &mut fs);
        assert_eq!(response.response.header.status, protocol::STATUS_ESRCH);
        assert!(response.response.payload.is_empty() && response.handles.is_empty());
        assert_eq!(
            fs.released.iter().map(|h| h.handle).collect::<Vec<_>>(),
            if opcode == protocol::OP_FTRUNCATE {
                vec![90]
            } else {
                vec![]
            }
        );
    }
}

#[test]
fn runtime_dispatches_only_the_supported_file_operations_outside_state() {
    for opcode in OPS {
        assert!(posix_service::file_request::supports(opcode));
    }
    for opcode in [
        protocol::OP_FSTAT,
        protocol::OP_FCHDIR,
        protocol::OP_OPEN_AT,
        u16::MAX,
    ] {
        assert!(!posix_service::file_request::supports(opcode));
    }
    // Structural wiring only; actual IPC/image behavior still needs OS tests.
    let source = include_str!("../../src/main.rs");
    let preflight = source.split("let prepared_filesystem = ").nth(1).unwrap();
    assert!(
        preflight.find("file_request::execute(").unwrap()
            < preflight
                .find("let mut service = service_state.lock().unwrap()")
                .unwrap()
    );
}
