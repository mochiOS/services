use super::*;

#[test]
fn foreground_relation_binds_session_group_and_native_process_object() {
    let leader = PeerIdentity {
        process_id: 141,
        effective_uid: 505,
        effective_gid: 24,
    };
    let member = PeerIdentity {
        process_id: 142,
        ..leader
    };
    let mut service = service_for(leader);
    let mut fs = RecordingFilesystem::default();
    let process = |id| AuthenticatedProcess {
        handle: id as u32,
        process_id: id,
    };
    service
        .adopt_child(leader, process(member.process_id), &mut fs)
        .unwrap();
    let header = |opcode| protocol::Header {
        opcode,
        ..Default::default()
    };
    assert_eq!(
        service
            .handle_terminal(
                leader,
                terminal_identity(leader),
                header(protocol::OP_TERMINAL_ACQUIRE),
                &[],
                77
            )
            .header
            .status,
        0
    );
    let query = |service: &PosixService, process| {
        service.terminal_process_foreground(leader, process, 77, |a, b| Ok(a == b))
    };
    assert_eq!(
        service.process_has_terminal(leader, process(141), |a, b| Ok(a == b)),
        Ok(true)
    );
    assert_eq!(
        service.process_has_terminal(leader, process(142), |a, b| Ok(a == b)),
        Ok(true)
    );
    assert_eq!(query(&service, process(141)), Ok(true));
    assert_eq!(query(&service, process(142)), Ok(true));
    assert_eq!(
        service.terminal_process_foreground(leader, process(142), 78, |a, b| Ok(a == b)),
        Ok(false)
    );
    assert_eq!(
        query(
            &service,
            AuthenticatedProcess {
                handle: 999,
                process_id: 142
            }
        ),
        Err(protocol::STATUS_EPERM)
    );
    let mut payload = [0; protocol::PROCESS_ID_REQUEST_LEN];
    protocol::encode_process_id_request(0, &mut payload).unwrap();
    assert_eq!(
        service
            .handle(member, header(protocol::OP_CREATE_SESSION), &[])
            .header
            .status,
        0
    );
    assert_eq!(query(&service, process(142)), Ok(false));
    assert_eq!(
        service.process_has_terminal(leader, process(142), |a, b| Ok(a == b)),
        Ok(false)
    );
    assert_eq!(query(&service, process(999)), Err(protocol::STATUS_ESRCH));
}

#[test]
fn foreground_relation_preserves_posix_credential_policy_and_observation_errors() {
    let root = PeerIdentity {
        process_id: 1,
        effective_uid: 0,
        effective_gid: 0,
    };
    let mut service = service_for(root);
    let target = AuthenticatedProcess {
        handle: 2,
        process_id: 2,
    };
    service
        .initialize_process(root, target, 1001, 1001, &[])
        .unwrap();
    let other = AuthenticatedProcess {
        handle: 3,
        process_id: 3,
    };
    service
        .initialize_process(root, other, 1000, 1000, &[])
        .unwrap();
    let caller = PeerIdentity {
        process_id: 3,
        effective_uid: 0,
        effective_gid: 0,
    };
    assert_eq!(
        service.terminal_process_foreground(caller, target, 77, |a, b| Ok(a == b)),
        Err(protocol::STATUS_EPERM)
    );
    assert_eq!(
        service.terminal_process_foreground(root, target, 77, |_, _| Err(-5)),
        Err(-5)
    );
}
