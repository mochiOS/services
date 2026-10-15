use super::*;

fn peer(process_id: u64, uid: u32) -> PeerIdentity {
    PeerIdentity {
        process_id,
        effective_uid: uid,
        effective_gid: 20,
    }
}

fn limit(service: &mut PosixService, owner: PeerIdentity, soft: u64) {
    let mut bytes = [0; protocol::RESOURCE_LIMIT_REQUEST_LEN];
    protocol::encode_resource_limit_request(
        protocol::ResourceLimitRequest {
            process_id: 0,
            resource: protocol::RLIMIT_NPROC,
            flags: protocol::RESOURCE_LIMIT_SET,
            limit: protocol::ResourceLimit {
                soft,
                hard: protocol::RLIM_INFINITY,
            },
        },
        &mut bytes,
    )
    .unwrap();
    assert_eq!(
        service
            .handle(
                owner,
                protocol::Header {
                    opcode: protocol::OP_RESOURCE_LIMIT,
                    ..Default::default()
                },
                &bytes
            )
            .header
            .status,
        0
    );
}

fn uid(service: &mut PosixService, owner: PeerIdentity, opcode: u16, value: u32) {
    let mut bytes = [0; 4];
    protocol::encode_credential_id(value, &mut bytes).unwrap();
    assert_eq!(
        service
            .handle(
                owner,
                protocol::Header {
                    opcode,
                    ..Default::default()
                },
                &bytes
            )
            .header
            .status,
        0
    );
}

fn add(service: &mut PosixService, authority: PeerIdentity, other: PeerIdentity) {
    service
        .initialize_process(
            authority,
            AuthenticatedProcess {
                process_id: other.process_id,
                handle: other.process_id as u32,
            },
            other.effective_uid,
            other.effective_gid,
            &[],
        )
        .unwrap();
}

#[test]
fn zero_and_exact_limits_reject_before_retaining_directory_references() {
    let owner = peer(801, 501);
    let mut service = service_for(owner);
    let mut fs = RecordingFilesystem::default();
    assert_eq!(
        service
            .handle_objects(
                owner,
                protocol::Header {
                    opcode: protocol::OP_GETCWD,
                    ..Default::default()
                },
                &[],
                &[],
                &mut fs
            )
            .response
            .header
            .status,
        0
    );
    for soft in [0, 1] {
        limit(&mut service, owner, soft);
        let retained = fs.retained.len();
        assert_eq!(
            service.prepare_fork(owner, &mut fs),
            Err(protocol::STATUS_EAGAIN)
        );
        assert_eq!(fs.retained.len(), retained);
    }
    limit(&mut service, owner, 2);
    fs.retain_failure_at = Some(fs.retained.len() + 2);
    assert_eq!(service.prepare_fork(owner, &mut fs), Err(-5));
    fs.retain_failure_at = None;
    // Failed snapshot preparation must not consume the only available slot.
    let token = service.prepare_fork(owner, &mut fs).unwrap();
    assert_eq!(
        service.prepare_fork(owner, &mut fs),
        Err(protocol::STATUS_EAGAIN)
    );
    service.cancel_fork(owner, token, &mut fs).unwrap();
    let token = service.prepare_fork(owner, &mut fs).unwrap();
    service.cancel_fork(owner, token, &mut fs).unwrap();
}

#[test]
fn same_real_uid_competes_for_reserved_slots_but_other_users_do_not() {
    let authority = peer(810, 0);
    let first = peer(811, 501);
    let second = peer(812, 501);
    let other = peer(813, 502);
    let mut service = service_for(authority);
    for owner in [first, second, other] {
        add(&mut service, authority, owner);
        limit(&mut service, owner, 3);
    }
    let mut fs = RecordingFilesystem::default();
    let token = service.prepare_fork(first, &mut fs).unwrap();
    assert_eq!(
        service.prepare_fork(second, &mut fs),
        Err(protocol::STATUS_EAGAIN)
    );
    let other_token = service.prepare_fork(other, &mut fs).unwrap();
    assert_eq!(
        service.cancel_fork(second, token, &mut fs),
        Err(protocol::STATUS_EPERM)
    );
    assert_eq!(
        service.prepare_fork(second, &mut fs),
        Err(protocol::STATUS_EAGAIN)
    );
    service.cancel_fork(first, token, &mut fs).unwrap();
    let second_token = service.prepare_fork(second, &mut fs).unwrap();
    service.cancel_fork(second, second_token, &mut fs).unwrap();
    service.cancel_fork(other, other_token, &mut fs).unwrap();
}

#[test]
fn failed_commit_keeps_the_reservation_and_success_does_not_double_charge() {
    let owner = peer(820, 501);
    let mut service = service_for(owner);
    let mut fs = RecordingFilesystem::default();
    limit(&mut service, owner, 3);
    let token = service.prepare_fork(owner, &mut fs).unwrap();
    assert_eq!(
        service.commit_fork(
            owner,
            token,
            AuthenticatedProcess {
                process_id: owner.process_id,
                handle: 999,
            }
        ),
        Err(STATUS_EINVAL)
    );
    let second = service.prepare_fork(owner, &mut fs).unwrap();
    assert_eq!(
        service.prepare_fork(owner, &mut fs),
        Err(protocol::STATUS_EAGAIN)
    );
    service.cancel_fork(owner, second, &mut fs).unwrap();
    service
        .commit_fork(
            owner,
            token,
            AuthenticatedProcess {
                process_id: 821,
                handle: 1821,
            },
        )
        .unwrap();
    let token = service.prepare_fork(owner, &mut fs).unwrap();
    assert_eq!(
        service.prepare_fork(owner, &mut fs),
        Err(protocol::STATUS_EAGAIN)
    );
    service.cancel_fork(owner, token, &mut fs).unwrap();
    limit(&mut service, owner, 2);
    let mut processes = RecordingProcesses::default();
    processes
        .states
        .insert(1821, ProcessLifecycle::Exited { exit_code: 0 });
    service
        .refresh_child_exit_notifications(&mut processes)
        .unwrap();
    // A zombie is still a process until wait consumes its status.
    assert_eq!(
        service.prepare_fork(owner, &mut fs),
        Err(protocol::STATUS_EAGAIN)
    );
    let waited = service
        .wait_child(
            owner,
            protocol::WaitRequest {
                selector: 821,
                options: 0,
            },
            &mut fs,
            &mut processes,
        )
        .unwrap();
    assert_eq!(waited.process_id, 821);
    let token = service.prepare_fork(owner, &mut fs).unwrap();
    service.cancel_fork(owner, token, &mut fs).unwrap();
}

#[test]
fn stored_real_uid_not_effective_or_peer_claims_controls_accounting() {
    let root = peer(830, 0);
    let owner = peer(831, 501);
    let mut service = service_for(root);
    add(&mut service, root, owner);
    let mut fs = RecordingFilesystem::default();
    limit(&mut service, root, 0);
    // Changing only effective UID does not remove the real-root exemption.
    uid(&mut service, root, protocol::OP_SET_EFFECTIVE_UID, 501);
    let token = service.prepare_fork(root, &mut fs).unwrap();
    service.cancel_fork(root, token, &mut fs).unwrap();
    limit(&mut service, owner, 1);
    assert_eq!(
        service.prepare_fork(
            PeerIdentity {
                effective_uid: 0,
                ..owner
            },
            &mut fs
        ),
        Err(protocol::STATUS_EAGAIN)
    );
    uid(&mut service, root, protocol::OP_SET_EFFECTIVE_UID, 0);
    // Same effective UID as root but a nonzero real UID must not be exempt.
    let mut ids = [0; protocol::CREDENTIAL_PAIR_PAYLOAD_LEN];
    protocol::encode_credential_pair(501, protocol::CREDENTIAL_ID_UNCHANGED, &mut ids).unwrap();
    assert_eq!(
        service
            .handle(
                root,
                protocol::Header {
                    opcode: protocol::OP_SET_REAL_EFFECTIVE_UID,
                    ..Default::default()
                },
                &ids
            )
            .header
            .status,
        0
    );
    assert_eq!(
        service.prepare_fork(root, &mut fs),
        Err(protocol::STATUS_EAGAIN)
    );
}

#[test]
fn pending_child_keeps_its_frozen_uid_when_owner_changes_credentials() {
    let root = peer(840, 0);
    let owner = peer(841, 501);
    let mut service = service_for(root);
    add(&mut service, root, owner);
    let mut fs = RecordingFilesystem::default();
    let token = service.prepare_fork(root, &mut fs).unwrap();
    uid(&mut service, root, protocol::OP_SET_UID, 501);
    limit(&mut service, owner, 3);
    // Two real-UID-501 processes; the pending child still belongs to UID zero.
    let other = service.prepare_fork(owner, &mut fs).unwrap();
    assert_eq!(
        service.prepare_fork(owner, &mut fs),
        Err(protocol::STATUS_EAGAIN)
    );
    service
        .commit_fork(
            root,
            token,
            AuthenticatedProcess {
                process_id: 842,
                handle: 1842,
            },
        )
        .unwrap();
    assert_eq!(service.session(842).unwrap().real_uid, 0);
    service.cancel_fork(owner, other, &mut fs).unwrap();
    let retry = service.prepare_fork(owner, &mut fs).unwrap();
    service.cancel_fork(owner, retry, &mut fs).unwrap();
}

#[test]
fn lowering_limit_does_not_revoke_an_admitted_child_but_blocks_new_preparations() {
    let owner = peer(850, 501);
    let mut service = service_for(owner);
    let mut fs = RecordingFilesystem::default();
    let token = service.prepare_fork(owner, &mut fs).unwrap();
    limit(&mut service, owner, 0);
    assert_eq!(
        service.prepare_fork(owner, &mut fs),
        Err(protocol::STATUS_EAGAIN)
    );
    service
        .commit_fork(
            owner,
            token,
            AuthenticatedProcess {
                process_id: 851,
                handle: 1851,
            },
        )
        .unwrap();
    // The child inherits the policy frozen at preparation, not the later zero.
    let child = peer(851, 501);
    let child_token = service.prepare_fork(child, &mut fs).unwrap();
    service.cancel_fork(child, child_token, &mut fs).unwrap();
    limit(&mut service, owner, protocol::RLIM_INFINITY);
    let token = service.prepare_fork(owner, &mut fs).unwrap();
    service.cancel_fork(owner, token, &mut fs).unwrap();
}

#[test]
fn abandoned_preparation_is_released_only_after_authenticated_native_exit() {
    let root = peer(860, 0);
    let first = peer(861, 501);
    let second = peer(862, 501);
    let mut service = service_for(root);
    for owner in [first, second] {
        add(&mut service, root, owner);
        limit(&mut service, owner, 3);
    }
    let mut fs = RecordingFilesystem::default();
    let token = service.prepare_fork(first, &mut fs).unwrap();
    let mut processes = RecordingProcesses::default();
    assert_eq!(
        service.reap_abandoned_forks(&mut fs, &mut processes),
        Err(protocol::STATUS_ESRCH)
    );
    assert_eq!(
        service.prepare_fork(second, &mut fs),
        Err(protocol::STATUS_EAGAIN)
    );
    processes.states.insert(861, ProcessLifecycle::Running);
    assert_eq!(service.reap_abandoned_forks(&mut fs, &mut processes), Ok(0));
    processes
        .states
        .insert(861, ProcessLifecycle::Exited { exit_code: 0 });
    assert_eq!(service.reap_abandoned_forks(&mut fs, &mut processes), Ok(1));
    assert_eq!(
        service.cancel_fork(first, token, &mut fs),
        Err(protocol::STATUS_ESRCH)
    );
    let token = service.prepare_fork(second, &mut fs).unwrap();
    service.cancel_fork(second, token, &mut fs).unwrap();
}
