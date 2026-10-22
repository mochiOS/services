use super::*;
use std::sync::{Arc, Mutex};

fn setup() -> (Arc<Mutex<PosixService>>, PeerIdentity) {
    let peer = PeerIdentity {
        process_id: 107,
        effective_uid: 0,
        effective_gid: 0,
    };
    let mut service = PosixService::new();
    service
        .initialize_bootstrap_process(
            AuthenticatedProcess {
                process_id: 107,
                handle: 107,
            },
            501,
            20,
            &[20, 42],
        )
        .unwrap();
    (Arc::new(Mutex::new(service)), peer)
}

#[test]
fn first_worker_path_request_initializes_roots_without_state_lock_using_stored_credentials() {
    let (state, peer) = setup();
    let root_state = state.clone();
    let mut fs = RecordingFilesystem {
        root_hook: Some(Box::new(move || {
            assert!(root_state.try_lock().is_ok());
        })),
        ..Default::default()
    };
    assert!(state.lock().unwrap().session_directories(107).is_none());
    posix_service::directory_request::initialize(&state, peer, &mut fs).unwrap();
    let dirs = *state.lock().unwrap().session_directories(107).unwrap();
    assert_eq!((dirs.root.handle, dirs.cwd.handle), (100, 101));
    assert_eq!(fs.root_credentials, Some((501, 20, vec![20, 42])));
    assert_eq!(fs.roots_opened, 1);
    assert_eq!(
        fs.released.iter().map(|h| h.handle).collect::<Vec<_>>(),
        [1100]
    );
    // A later worker snapshot must keep existing cwd/root rather than reopening.
    posix_service::directory_request::initialize(&state, peer, &mut fs).unwrap();
    assert_eq!(fs.roots_opened, 1);
    assert_eq!(
        *state.lock().unwrap().session_directories(107).unwrap(),
        dirs
    );
}

#[test]
fn credential_changes_during_initialization_discard_uninstalled_roots() {
    let peer = PeerIdentity {
        process_id: 107,
        effective_uid: 0,
        effective_gid: 0,
    };
    let state = Arc::new(Mutex::new(service_for(peer)));
    let root_state = state.clone();
    let mut fs = RecordingFilesystem {
        root_hook: Some(Box::new(move || {
            let bytes = 501u32.to_le_bytes();
            let response = root_state.try_lock().unwrap().handle(
                peer,
                protocol::Header {
                    opcode: protocol::OP_SET_EFFECTIVE_UID,
                    payload_len: bytes.len() as u32,
                    ..Default::default()
                },
                &bytes,
            );
            assert_eq!(response.header.status, 0);
        })),
        ..Default::default()
    };
    assert_eq!(
        posix_service::directory_request::initialize(&state, peer, &mut fs),
        Err(protocol::STATUS_EAGAIN)
    );
    assert!(state.lock().unwrap().session_directories(107).is_none());
    assert_eq!(
        fs.released.iter().map(|h| h.handle).collect::<Vec<_>>(),
        [100, 101]
    );
}

#[test]
fn unknown_session_is_rejected_without_backend_calls() {
    let (state, peer) = setup();
    let mut fs = RecordingFilesystem::default();
    assert_eq!(
        posix_service::directory_request::initialize(
            &state,
            PeerIdentity {
                process_id: 108,
                ..peer
            },
            &mut fs
        ),
        Err(protocol::STATUS_ESRCH)
    );
    assert_eq!(fs.roots_opened, 0);
    assert!(fs.retained.is_empty() && fs.released.is_empty());
}

#[test]
fn filesystem_denial_is_returned_without_fabricating_directory_context() {
    let (state, peer) = setup();
    let mut fs = RecordingFilesystem {
        root_error: Some(-13),
        ..Default::default()
    };
    assert_eq!(
        posix_service::directory_request::initialize(&state, peer, &mut fs),
        Err(-13)
    );
    assert!(state.lock().unwrap().session_directories(107).is_none());
    assert!(fs.retained.is_empty() && fs.released.is_empty());
}

#[test]
fn concurrent_initializer_wins_without_losing_or_double_closing_its_references() {
    let (state, peer) = setup();
    let root_state = state.clone();
    let mut fs = RecordingFilesystem {
        root_hook: Some(Box::new(move || {
            let mut other_fs = RecordingFilesystem {
                root_base: Some(200),
                ..Default::default()
            };
            posix_service::directory_request::initialize(&root_state, peer, &mut other_fs).unwrap();
            assert_eq!(
                other_fs
                    .released
                    .iter()
                    .map(|h| h.handle)
                    .collect::<Vec<_>>(),
                [1200]
            );
        })),
        ..Default::default()
    };
    posix_service::directory_request::initialize(&state, peer, &mut fs).unwrap();
    let dirs = *state.lock().unwrap().session_directories(107).unwrap();
    assert_eq!((dirs.root.handle, dirs.cwd.handle), (200, 201));
    // Retire only our unused roots and our borrowed-lifetime snapshot reference.
    assert_eq!(
        fs.released.iter().map(|h| h.handle).collect::<Vec<_>>(),
        [100, 101, 1200]
    );
}

#[test]
fn initialization_failure_does_not_overwrite_an_existing_directory_context() {
    let (state, peer) = setup();
    let mut fs = RecordingFilesystem::default();
    posix_service::directory_request::initialize(&state, peer, &mut fs).unwrap();
    let original = *state.lock().unwrap().session_directories(107).unwrap();
    fs.retain_failure_at = Some(fs.retained.len() + 1);
    assert_eq!(
        posix_service::directory_request::initialize(&state, peer, &mut fs),
        Err(-5)
    );
    assert_eq!(
        *state.lock().unwrap().session_directories(107).unwrap(),
        original
    );
    assert_eq!(fs.roots_opened, 1);
}

#[test]
fn socket_worker_initializes_before_reading_directory_policy_but_not_under_the_state_guard() {
    // Structural native-adapter check only, not proof of native IPC behavior.
    let source = include_str!("../../src/socket_path_native.rs");
    let snapshot = source
        .split("pub(super) fn snapshot_process(")
        .nth(1)
        .unwrap();
    let initialization = snapshot.find("directory_request::initialize(").unwrap();
    let captured = snapshot
        .find("let dirs = state.session_directories(")
        .unwrap();
    assert!(initialization < captured);
    assert!(
        snapshot[..initialization]
            .contains("let mut filesystem = super::RuntimeFilesystem { endpoint }")
    );
    assert!(snapshot[..initialization].contains("let initialize = {"));
    let after_initialization = &snapshot[initialization..];
    assert!(after_initialization.contains("let state = state.lock().map_err(|_| -5)?;"));
}
