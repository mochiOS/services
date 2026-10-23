use super::*;
use std::sync::{Arc, Mutex};

const QUERIES: [u16; 6] = [
    protocol::OP_PATH_LIMITS_AT,
    protocol::OP_TERMINAL_LIMITS_AT,
    protocol::OP_STAT_AT,
    protocol::OP_CANONICAL_PATH_AT,
    protocol::OP_ACCESS_AT,
    protocol::OP_READLINK_AT,
];

fn setup() -> (Arc<Mutex<PosixService>>, PeerIdentity) {
    let peer = PeerIdentity {
        process_id: 93,
        effective_uid: 0,
        effective_gid: 0,
    };
    (Arc::new(Mutex::new(service_for(peer))), peer)
}

fn request(opcode: u16, base: protocol::OpenBase, flags: u32) -> (protocol::Header, Vec<u8>) {
    let mut payload = vec![0; 128];
    let length = if opcode == protocol::OP_ACCESS_AT {
        protocol::encode_access_at(
            protocol::AccessAtRequest {
                base,
                flags,
                modes: protocol::ACCESS_READ,
                path: b"../file-\xff",
            },
            &mut payload,
        )
        .unwrap()
    } else {
        protocol::encode_stat_at(
            protocol::StatAtRequest {
                base,
                flags,
                path: b"../file-\xff",
            },
            &mut payload,
        )
        .unwrap()
    };
    payload.truncate(length);
    (
        protocol::Header {
            opcode,
            request_id: 98,
            payload_len: length as u32,
            ..Default::default()
        },
        payload,
    )
}

#[test]
fn all_readonly_queries_run_root_and_backend_rpc_without_state_lock() {
    for opcode in QUERIES {
        let (state, peer) = setup();
        let root_state = state.clone();
        let query_state = state.clone();
        let mut fs = RecordingFilesystem {
            root_hook: Some(Box::new(move || {
                assert!(root_state.try_lock().is_ok());
            })),
            query_hook: Some(Box::new(move || {
                assert!(query_state.try_lock().is_ok());
                Ok(())
            })),
            ..Default::default()
        };
        let (header, payload) = request(opcode, protocol::OpenBase::ProcessCwd, 0);
        let response =
            posix_service::path_query::execute(&state, peer, header, &payload, &[], &mut fs);
        assert_eq!(response.response.header.status, 0);
        assert_eq!(response.response.header.request_id, header.request_id);
        assert!(response.handles.is_empty());
        assert_eq!(fs.root.unwrap().handle, 1100);
        assert_eq!(fs.directory.unwrap().handle, 1101);
        assert_eq!(
            fs.released.iter().map(|h| h.handle).collect::<Vec<_>>(),
            [1100, 1101]
        );
        match opcode {
            protocol::OP_STAT_AT => assert_eq!(
                protocol::decode_file_status(&response.response.payload).unwrap(),
                sample_status()
            ),
            protocol::OP_PATH_LIMITS_AT => {
                assert_eq!(
                    filesystem_protocol::object_limits::Limits::decode(&response.response.payload)
                        .unwrap()
                        .name_bytes_max,
                    255
                );
            }
            protocol::OP_TERMINAL_LIMITS_AT => {
                assert_eq!(
                    protocol::terminal_limits::Limits::decode(&response.response.payload)
                        .unwrap()
                        .canonical_bytes,
                    65536
                );
            }
            protocol::OP_CANONICAL_PATH_AT => {
                assert_eq!(response.response.payload, b"/resolved/target")
            }
            protocol::OP_ACCESS_AT => assert!(response.response.payload.is_empty()),
            protocol::OP_READLINK_AT => assert_eq!(response.response.payload, b"../target"),
            _ => unreachable!(),
        }
        let path = fs
            .stat_request
            .as_ref()
            .map(|p| &p.path)
            .or_else(|| fs.access_request.as_ref().map(|p| &p.path))
            .or_else(|| fs.readlink_request.as_ref().map(|p| &p.path))
            .unwrap();
        assert_eq!(path, b"../file-\xff");
    }
}

#[test]
fn backend_failures_return_unchanged_status_and_release_every_retained_anchor() {
    for opcode in QUERIES {
        let (state, peer) = setup();
        let (header, payload) = request(opcode, protocol::OpenBase::ProcessCwd, 0);
        let mut fs = RecordingFilesystem {
            query_hook: Some(Box::new(|| Err(-13))),
            ..Default::default()
        };
        let response =
            posix_service::path_query::execute(&state, peer, header, &payload, &[], &mut fs);
        assert_eq!(response.response.header.status, -13);
        assert!(response.handles.is_empty());
        assert_eq!(
            fs.released.iter().map(|h| h.handle).collect::<Vec<_>>(),
            [1100, 1101]
        );
    }
}

#[test]
fn attached_directory_authority_is_borrowed_and_root_requests_do_not_retain_cwd() {
    for opcode in QUERIES {
        for base in [
            protocol::OpenBase::ProcessRoot,
            protocol::OpenBase::AttachedDirectory,
        ] {
            let (state, peer) = setup();
            let (header, payload) = request(opcode, base, 0);
            let attached = [AttachedObject {
                handle: 73,
                rights: mnu_abi::HANDLE_RIGHT_TRANSFER,
            }];
            let handles = if base == protocol::OpenBase::AttachedDirectory {
                &attached[..]
            } else {
                &[]
            };
            let mut fs = RecordingFilesystem::default();
            let response = posix_service::path_query::execute(
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

fn set_effective(service: &mut PosixService, peer: PeerIdentity, opcode: u16, value: u32) {
    let payload = value.to_le_bytes();
    let response = service.handle(
        peer,
        protocol::Header {
            opcode,
            payload_len: payload.len() as u32,
            ..Default::default()
        },
        &payload,
    );
    assert_eq!(response.header.status, 0);
}

#[test]
fn access_selects_real_or_effective_ids_but_initial_root_always_uses_effective_ids() {
    for flags in [0, protocol::ACCESS_EFFECTIVE_IDS] {
        let (state, peer) = setup();
        {
            let mut service = state.lock().unwrap();
            set_effective(&mut service, peer, protocol::OP_SET_EFFECTIVE_GID, 20);
            set_effective(&mut service, peer, protocol::OP_SET_EFFECTIVE_UID, 501);
        }
        let (header, payload) = request(
            protocol::OP_ACCESS_AT,
            protocol::OpenBase::ProcessRoot,
            flags,
        );
        let mut fs = RecordingFilesystem::default();
        let response =
            posix_service::path_query::execute(&state, peer, header, &payload, &[], &mut fs);
        assert_eq!(response.response.header.status, 0);
        assert_eq!(fs.root_credentials, Some((501, 20, vec![])));
        let prepared = fs.access_request.unwrap();
        assert_eq!(
            (prepared.uid, prepared.gid),
            if flags == 0 { (0, 0) } else { (501, 20) }
        );
    }
}

#[test]
fn root_credentials_are_revalidated_even_when_access_real_credentials_are_unchanged() {
    let (state, peer) = setup();
    let root_state = state.clone();
    let mut fs = RecordingFilesystem {
        root_hook: Some(Box::new(move || {
            set_effective(
                &mut root_state.try_lock().unwrap(),
                peer,
                protocol::OP_SET_EFFECTIVE_UID,
                501,
            );
        })),
        ..Default::default()
    };
    let (header, payload) = request(protocol::OP_ACCESS_AT, protocol::OpenBase::ProcessRoot, 0);
    let response = posix_service::path_query::execute(&state, peer, header, &payload, &[], &mut fs);
    assert_eq!(response.response.header.status, protocol::STATUS_EAGAIN);
    assert!(fs.access_request.is_none());
    assert!(
        state
            .lock()
            .unwrap()
            .session_directories(peer.process_id)
            .is_none()
    );
    assert_eq!(
        fs.released.iter().map(|h| h.handle).collect::<Vec<_>>(),
        [100, 101]
    );
}

#[test]
fn malformed_queries_never_initialize_roots_or_call_the_backend() {
    let (state, peer) = setup();
    for opcode in QUERIES {
        let (header, payload) = request(opcode, protocol::OpenBase::ProcessRoot, 0);
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
            let response =
                posix_service::path_query::execute(&state, peer, header, &payload, &[], &mut fs);
            assert_eq!(response.response.header.status, STATUS_EINVAL);
            assert_eq!(fs.roots_opened, 0);
        }
        let (header, payload) = request(opcode, protocol::OpenBase::AttachedDirectory, 0);
        let mut fs = RecordingFilesystem::default();
        let response =
            posix_service::path_query::execute(&state, peer, header, &payload, &[], &mut fs);
        assert_eq!(response.response.header.status, STATUS_EINVAL);
        assert_eq!(fs.roots_opened, 0);
    }
    for opcode in [
        protocol::OP_CANONICAL_PATH_AT,
        protocol::OP_PATH_LIMITS_AT,
        protocol::OP_TERMINAL_LIMITS_AT,
        protocol::OP_READLINK_AT,
    ] {
        let (header, payload) = request(
            opcode,
            protocol::OpenBase::ProcessRoot,
            protocol::STAT_NOFOLLOW,
        );
        let mut fs = RecordingFilesystem::default();
        assert_eq!(
            posix_service::path_query::execute(&state, peer, header, &payload, &[], &mut fs)
                .response
                .header
                .status,
            STATUS_EINVAL
        );
        assert_eq!(fs.roots_opened, 0);
    }
}

#[test]
fn replaced_image_cannot_receive_query_payload_and_unknown_operations_are_not_dispatched() {
    for opcode in QUERIES {
        assert!(posix_service::path_query::supports(opcode));
        let (state, peer) = setup();
        let (header, payload) = request(opcode, protocol::OpenBase::ProcessRoot, 0);
        let mut fs = RecordingFilesystem::default();
        let response =
            posix_service::path_query::execute(&state, peer, header, &payload, &[], &mut fs);
        let response =
            posix_service::open_request::finish(response, Err(protocol::STATUS_ESRCH), &mut fs);
        assert_eq!(response.response.header.status, protocol::STATUS_ESRCH);
        assert_eq!(response.response.header.payload_len, 0);
        assert!(response.response.payload.is_empty());
    }
    let (state, peer) = setup();
    for opcode in [
        protocol::OP_CHDIR_AT,
        protocol::OP_UNLINK_AT,
        protocol::OP_OPEN_AT,
        u16::MAX,
    ] {
        assert!(!posix_service::path_query::supports(opcode));
        let mut fs = RecordingFilesystem::default();
        let header = protocol::Header {
            opcode,
            ..Default::default()
        };
        let response = posix_service::path_query::execute(&state, peer, header, &[], &[], &mut fs);
        assert_eq!(response.response.header.status, protocol::STATUS_ENOSYS);
        assert_eq!(fs.roots_opened, 0);
    }
    // Structural wiring check only; this is not a native OS integration test.
    let source = include_str!("../../src/main.rs");
    let preflight = source.split("let prepared_filesystem = ").nth(1).unwrap();
    assert!(
        preflight.find("path_query::execute(").unwrap()
            < preflight
                .find("let mut service = service_state.lock().unwrap()")
                .unwrap()
    );
    let completion = preflight
        .split("if prepared_filesystem.is_some()")
        .nth(1)
        .unwrap();
    assert!(
        completion.find("validate_pending_request_image(").unwrap()
            < completion.find("open_request::finish(").unwrap()
    );
}
