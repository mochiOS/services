use super::*;
use std::sync::{Arc, Mutex};

const RIGHTS: u64 = mnu_abi::HANDLE_RIGHT_DUPLICATE | mnu_abi::HANDLE_RIGHT_TRANSFER;
fn source() -> AttachedObject<u32> {
    AttachedObject {
        handle: 80,
        rights: RIGHTS,
    }
}
fn header() -> protocol::Header {
    protocol::Header {
        opcode: protocol::OP_FCHDIR,
        request_id: 108,
        ..Default::default()
    }
}

fn setup(uid: u32, gid: u32, groups: &[u32]) -> (Arc<Mutex<PosixService>>, PeerIdentity) {
    let peer = PeerIdentity {
        process_id: 103,
        effective_uid: 0,
        effective_gid: 0,
    };
    let mut service = PosixService::new();
    service
        .initialize_bootstrap_process(
            AuthenticatedProcess {
                process_id: 103,
                handle: 103,
            },
            uid,
            gid,
            groups,
        )
        .unwrap();
    (Arc::new(Mutex::new(service)), peer)
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
fn fchdir_checks_live_metadata_without_lock_or_path_lookup_and_retains_same_description() {
    let (state, peer) = setup(505, 24, &[]);
    let query_state = state.clone();
    let mut fs = RecordingFilesystem {
        stat_mode: Some(0o040100),
        query_hook: Some(Box::new(move || {
            assert!(query_state.try_lock().is_ok());
            Ok(())
        })),
        ..Default::default()
    };
    let pending = posix_service::directory_request::execute(
        &state,
        peer,
        header(),
        &[],
        &[source()],
        &mut fs,
    );
    assert_eq!(fs.stat_file, Some(source()));
    assert!(fs.directory_request.is_none());
    assert!(fs.stat_request.is_none());
    assert_eq!(
        fs.retained.iter().map(|h| h.handle).collect::<Vec<_>>(),
        [100, 80]
    );
    assert_eq!(
        fs.released.iter().map(|h| h.handle).collect::<Vec<_>>(),
        [1100]
    );
    assert_eq!(
        state
            .lock()
            .unwrap()
            .session_directories(103)
            .unwrap()
            .cwd
            .handle,
        101
    );
    let response = finish(&state, peer, pending, Ok(()), &mut fs);
    assert_eq!(response.response.header.request_id, 108);
    assert_eq!(response.response.header.status, 0);
    assert!(response.handles.is_empty());
    let dirs = *state.lock().unwrap().session_directories(103).unwrap();
    assert_eq!((dirs.root.handle, dirs.cwd.handle), (100, 1080));
    assert_eq!(dirs.cwd.rights, RIGHTS);
    assert_eq!(fs.released.last().unwrap().handle, 101);
}

#[test]
fn search_permissions_choose_owner_group_or_other_without_falling_through_classes() {
    for (uid, gid, groups, mode, expected) in [
        (505, 30, &[][..], 0o040001, -13),
        (505, 24, &[][..], 0o040010, -13),
        (505, 30, &[][..], 0o040100, 0),
        (1000, 24, &[][..], 0o040010, 0),
        (1000, 24, &[][..], 0o040001, -13),
        (1000, 30, &[24][..], 0o040010, 0),
        (1000, 30, &[][..], 0o040001, 0),
        (1000, 30, &[][..], 0o040100, -13),
        (0, 30, &[][..], 0o040000, 0),
    ] {
        let (state, peer) = setup(uid, gid, groups);
        let mut fs = RecordingFilesystem {
            stat_mode: Some(mode),
            ..Default::default()
        };
        let pending = posix_service::directory_request::execute(
            &state,
            peer,
            header(),
            &[],
            &[source()],
            &mut fs,
        );
        let response = finish(&state, peer, pending, Ok(()), &mut fs);
        assert_eq!(
            response.response.header.status, expected,
            "uid={uid} gid={gid} mode={mode:o}"
        );
        if expected != 0 {
            assert_eq!(
                fs.retained.iter().map(|h| h.handle).collect::<Vec<_>>(),
                [100]
            );
            assert_eq!(
                state
                    .lock()
                    .unwrap()
                    .session_directories(103)
                    .unwrap()
                    .cwd
                    .handle,
                101
            );
        }
    }
}

#[test]
fn uid_zero_does_not_recover_missing_transfer_or_duplicate_authority() {
    for rights in [
        0,
        mnu_abi::HANDLE_RIGHT_TRANSFER,
        mnu_abi::HANDLE_RIGHT_DUPLICATE,
    ] {
        let (state, peer) = setup(0, 0, &[]);
        let mut fs = RecordingFilesystem::default();
        let pending = posix_service::directory_request::execute(
            &state,
            peer,
            header(),
            &[],
            &[AttachedObject { rights, ..source() }],
            &mut fs,
        );
        assert_eq!(
            finish(&state, peer, pending, Ok(()), &mut fs)
                .response
                .header
                .status,
            -13
        );
        assert_eq!(fs.roots_opened, 0);
        assert!(fs.stat_file.is_none());
    }
}

#[test]
fn non_directories_and_metadata_or_retain_errors_leave_cwd_unchanged() {
    for (mode, error, retain_failure, expected) in [
        (0o100777, None, false, -20),
        (0o120777, None, false, -20),
        (0o040100, Some(-5), false, -5),
        (0o040100, None, true, -5),
    ] {
        let (state, peer) = setup(505, 24, &[]);
        let mut fs = RecordingFilesystem {
            stat_mode: Some(mode),
            retain_failure_at: retain_failure.then_some(2),
            query_hook: Some(Box::new(move || error.map_or(Ok(()), Err))),
            ..Default::default()
        };
        let pending = posix_service::directory_request::execute(
            &state,
            peer,
            header(),
            &[],
            &[source()],
            &mut fs,
        );
        assert_eq!(
            finish(&state, peer, pending, Ok(()), &mut fs)
                .response
                .header
                .status,
            expected
        );
        assert_eq!(
            state
                .lock()
                .unwrap()
                .session_directories(103)
                .unwrap()
                .cwd
                .handle,
            101
        );
        assert_eq!(
            fs.released.iter().map(|h| h.handle).collect::<Vec<_>>(),
            [1100]
        );
    }
}

#[test]
fn image_rejection_releases_the_retained_reference_not_the_borrowed_incoming_handle() {
    let (state, peer) = setup(505, 24, &[]);
    let mut fs = RecordingFilesystem {
        stat_mode: Some(0o040100),
        ..Default::default()
    };
    let pending = posix_service::directory_request::execute(
        &state,
        peer,
        header(),
        &[],
        &[source()],
        &mut fs,
    );
    let response = finish(&state, peer, pending, Err(protocol::STATUS_ESRCH), &mut fs);
    assert_eq!(response.response.header.status, protocol::STATUS_ESRCH);
    assert_eq!(
        fs.released.iter().map(|h| h.handle).collect::<Vec<_>>(),
        [1100, 1080]
    );
    assert_eq!(
        state
            .lock()
            .unwrap()
            .session_directories(103)
            .unwrap()
            .cwd
            .handle,
        101
    );
}

#[test]
fn credentials_changed_after_metadata_authorization_cannot_install_the_retained_directory() {
    let (state, peer) = setup(0, 0, &[]);
    let mut fs = RecordingFilesystem {
        stat_mode: Some(0o040000),
        ..Default::default()
    };
    let pending = posix_service::directory_request::execute(
        &state,
        peer,
        header(),
        &[],
        &[source()],
        &mut fs,
    );
    let uid = 505u32.to_le_bytes();
    let response = state.lock().unwrap().handle(
        peer,
        protocol::Header {
            opcode: protocol::OP_SET_EFFECTIVE_UID,
            payload_len: uid.len() as u32,
            ..Default::default()
        },
        &uid,
    );
    assert_eq!(response.header.status, 0);
    let response = finish(&state, peer, pending, Ok(()), &mut fs);
    assert_eq!(response.response.header.status, protocol::STATUS_EAGAIN);
    assert_eq!(
        fs.released.iter().map(|h| h.handle).collect::<Vec<_>>(),
        [1100, 1080]
    );
    assert_eq!(
        state
            .lock()
            .unwrap()
            .session_directories(103)
            .unwrap()
            .cwd
            .handle,
        101
    );
}

#[test]
fn fchdir_rejects_payload_and_attachment_count_errors_before_backend_work() {
    for (payload, handles) in [
        (&[][..], vec![]),
        (&[][..], vec![source(), source()]),
        (&b"x"[..], vec![source()]),
    ] {
        let (state, peer) = setup(505, 24, &[]);
        let mut fs = RecordingFilesystem::default();
        let header = protocol::Header {
            payload_len: payload.len() as u32,
            ..header()
        };
        let pending = posix_service::directory_request::execute(
            &state, peer, header, payload, &handles, &mut fs,
        );
        assert_eq!(
            finish(&state, peer, pending, Ok(()), &mut fs)
                .response
                .header
                .status,
            STATUS_EINVAL
        );
        assert_eq!(fs.roots_opened, 0);
        assert!(fs.stat_file.is_none());
    }
}
