use super::*;

fn setup() -> (
    PosixService,
    PeerIdentity,
    RecordingFilesystem,
    RecordingProcesses,
) {
    let owner = PeerIdentity {
        process_id: 2601,
        effective_uid: 0,
        effective_gid: 0,
    };
    let mut service = service_for(owner);
    let mut filesystem = RecordingFilesystem::default();
    let response = service.handle_objects(
        owner,
        protocol::Header {
            opcode: protocol::OP_GETCWD,
            ..Default::default()
        },
        &[],
        &[],
        &mut filesystem,
    );
    assert_eq!(response.response.header.status, 0);
    let mut processes = RecordingProcesses::default();
    processes.images.insert(
        2601,
        Ok(mnu_abi::ProcessStatus {
            process_id: owner.process_id,
            state: mnu_abi::PROCESS_STATE_RUNNING,
            ..Default::default()
        }),
    );
    (service, owner, filesystem, processes)
}

fn observe(
    service: &mut PosixService,
    owner: PeerIdentity,
    processes: &mut RecordingProcesses,
    revision: u64,
) {
    processes
        .images
        .get_mut(&2601)
        .unwrap()
        .as_mut()
        .unwrap()
        .image_revision = revision;
    service.refresh_image_state(owner, processes).unwrap();
}

fn child() -> AuthenticatedProcess<u32> {
    AuthenticatedProcess {
        process_id: 2602,
        handle: 82,
    }
}

#[test]
fn an_old_image_token_cannot_restore_privileged_credentials_after_exec() {
    let (mut service, owner, mut filesystem, mut processes) = setup();
    let mut action = [0; protocol::SIGNAL_DISPOSITION_LEN];
    protocol::encode_signal_disposition(
        protocol::SignalDisposition {
            signal: 30,
            kind: protocol::SIGNAL_DISPOSITION_CAUGHT,
            child_options: 0,
        },
        &mut action,
    )
    .unwrap();
    assert_eq!(
        service
            .handle(
                owner,
                protocol::Header {
                    opcode: protocol::OP_SIGNAL_DISPOSITION,
                    flags: protocol::SIGNAL_DISPOSITION_SET,
                    ..Default::default()
                },
                &action
            )
            .header
            .status,
        0
    );
    let old_signals = service.signal_state(owner.process_id).unwrap();
    let old = service.prepare_fork(owner, &mut filesystem).unwrap();
    let mut bytes = [0; protocol::CREDENTIAL_ID_PAYLOAD_LEN];
    protocol::encode_credential_id(501, &mut bytes).unwrap();
    assert_eq!(
        service
            .handle(
                owner,
                protocol::Header {
                    opcode: protocol::OP_SET_UID,
                    ..Default::default()
                },
                &bytes
            )
            .header
            .status,
        0
    );
    observe(&mut service, owner, &mut processes, 1);
    assert_ne!(service.signal_state(owner.process_id).unwrap(), old_signals);
    assert_eq!(
        service.commit_fork(owner, old, child()),
        Err(protocol::STATUS_ESRCH)
    );
    assert!(service.session(2602).is_none());
    assert!(!service.is_child(owner.process_id, 2602));
    assert!(
        filesystem.released.is_empty(),
        "rejection retains ownership for cancellation"
    );
    service.cancel_fork(owner, old, &mut filesystem).unwrap();
    assert_eq!(filesystem.released.len(), 2);
    let next = service.prepare_fork(owner, &mut filesystem).unwrap();
    assert!(next > old);
    service.commit_fork(owner, next, child()).unwrap();
    let inherited = service.session(2602).unwrap();
    assert_eq!(
        (
            inherited.real_uid,
            inherited.effective_uid,
            inherited.saved_uid
        ),
        (501, 501, 501)
    );
    assert_eq!(
        service.signal_state(2602),
        service.signal_state(owner.process_id)
    );
}

#[test]
fn reclaiming_one_images_tokens_preserves_another_owners_valid_capture() {
    let (mut service, owner, mut filesystem, mut processes) = setup();
    let other = PeerIdentity {
        process_id: 2604,
        effective_uid: 501,
        effective_gid: 20,
    };
    service
        .initialize_process(
            owner,
            AuthenticatedProcess {
                handle: 84,
                process_id: other.process_id,
            },
            501,
            20,
            &[],
        )
        .unwrap();
    assert_eq!(
        service
            .handle_objects(
                other,
                protocol::Header {
                    opcode: protocol::OP_GETCWD,
                    ..Default::default()
                },
                &[],
                &[],
                &mut filesystem
            )
            .response
            .header
            .status,
        0
    );
    let old = service.prepare_fork(owner, &mut filesystem).unwrap();
    let valid = service.prepare_fork(other, &mut filesystem).unwrap();
    observe(&mut service, owner, &mut processes, 1);
    let fresh = service.prepare_fork(owner, &mut filesystem).unwrap();
    assert_eq!(filesystem.released.len(), 2);
    assert_eq!(
        service.cancel_fork(owner, old, &mut filesystem),
        Err(protocol::STATUS_ESRCH)
    );
    service
        .commit_fork(
            other,
            valid,
            AuthenticatedProcess {
                handle: 90,
                process_id: 2630,
            },
        )
        .unwrap();
    assert_eq!(service.session(2630).unwrap().real_uid, 501);
    assert_eq!(
        filesystem.released.len(),
        2,
        "foreign references belong to its new child"
    );
    service.cancel_fork(owner, fresh, &mut filesystem).unwrap();
    assert_eq!(filesystem.released.len(), 4);
}

#[test]
fn unchanged_image_preserves_the_frozen_snapshot_even_if_parent_credentials_change() {
    let (mut service, owner, mut filesystem, mut processes) = setup();
    let token = service.prepare_fork(owner, &mut filesystem).unwrap();
    let mut bytes = [0; protocol::CREDENTIAL_ID_PAYLOAD_LEN];
    protocol::encode_credential_id(501, &mut bytes).unwrap();
    assert_eq!(
        service
            .handle(
                owner,
                protocol::Header {
                    opcode: protocol::OP_SET_UID,
                    ..Default::default()
                },
                &bytes
            )
            .header
            .status,
        0
    );
    observe(&mut service, owner, &mut processes, 0); // Failed exec never advances revision.
    let reply = service.handle_thread_signal_request(
        owner,
        mnu_abi::ExecutionIdentity {
            process_id: owner.process_id,
            thread_id: 55,
        },
        protocol::Header {
            opcode: protocol::OP_SIGNAL_IMAGE_STARTED,
            ..Default::default()
        },
        &[],
    );
    assert_eq!(reply.header.status, 0);
    service.commit_fork(owner, token, child()).unwrap();
    assert_eq!(
        service.session(2602).unwrap().real_uid,
        0,
        "snapshot precedes the parent's change"
    );
    assert_eq!(service.session(owner.process_id).unwrap().real_uid, 501);
}

#[test]
fn exec_invalidated_preparations_release_references_and_capacity_while_owner_is_live() {
    for cleanup_before_prepare in [false, true] {
        let (mut service, owner, mut filesystem, mut processes) = setup();
        let tokens: Vec<_> = (0..64)
            .map(|_| service.prepare_fork(owner, &mut filesystem).unwrap())
            .collect();
        assert_eq!(
            service.prepare_fork(owner, &mut filesystem),
            Err(protocol::STATUS_EAGAIN)
        );
        observe(&mut service, owner, &mut processes, 1);
        if cleanup_before_prepare {
            // The stored image proof is sufficient; no exit observation or
            // termination is required to reclaim an invalidated token.
            assert_eq!(
                service.reap_abandoned_forks(&mut filesystem, &mut processes),
                Ok(64)
            );
            assert_eq!(filesystem.released.len(), 128);
        }
        let fresh = service.prepare_fork(owner, &mut filesystem).unwrap();
        assert!(fresh > *tokens.last().unwrap());
        assert_eq!(filesystem.released.len(), 128);
        for token in tokens {
            assert_eq!(
                service.cancel_fork(owner, token, &mut filesystem),
                Err(protocol::STATUS_ESRCH)
            );
        }
        service.commit_fork(owner, fresh, child()).unwrap();
        assert_eq!(
            filesystem.released.len(),
            128,
            "fresh ownership moved to child"
        );
    }
}
