use super::*;

#[test]
fn detailed_exit_captures_real_uid_before_reap_and_preserves_legacy_result_wire() {
    let (mut service, _, parent, child, mut fs, mut processes) = orphan_family();
    processes
        .states
        .insert(142, ProcessLifecycle::Exited { exit_code: 37 });
    let request = protocol::WaitRequest {
        selector: child.process_id as i64,
        options: protocol::WAIT_NOWAIT,
    };
    let first = service
        .wait_child_info(parent, request, &mut fs, &mut processes)
        .unwrap();
    assert_eq!(first.real_uid, 505);
    assert_eq!(
        (first.result.process_id, first.result.status),
        (child.process_id, 37 << 8)
    );
    let reaped = service
        .wait_child_info(
            PeerIdentity {
                effective_uid: 0,
                ..parent
            },
            protocol::WaitRequest {
                options: 0,
                ..request
            },
            &mut fs,
            &mut processes,
        )
        .unwrap();
    assert_eq!(reaped, first);
    assert!(service.session(child.process_id).is_none());
    let mut bytes = [0; protocol::WAIT_INFO_LEN];
    protocol::encode_wait_info(reaped, &mut bytes).unwrap();
    assert_eq!(protocol::decode_wait_info(&bytes).unwrap(), first);
    assert_eq!(
        protocol::decode_wait_result(&bytes[..protocol::WAIT_RESULT_LEN]).unwrap(),
        first.result
    );
    assert!(protocol::decode_wait_info(&bytes[..16]).is_err());
    bytes[20] = 1;
    assert!(protocol::decode_wait_info(&bytes).is_err());
}

#[test]
fn explicit_group_one_is_not_confused_with_all_children() {
    let (mut service, _, parent, child, mut fs, mut processes) = orphan_family();
    let options = protocol::WAIT_SELECT_GROUP
        | protocol::WAIT_SELECT_EVENTS
        | protocol::WAIT_EXITED
        | protocol::WAIT_NOHANG;
    assert_eq!(
        service.wait_child_info(
            parent,
            protocol::WaitRequest {
                selector: 1,
                options
            },
            &mut fs,
            &mut processes
        ),
        Err(protocol::STATUS_ECHILD)
    );
    assert_eq!(
        service.wait_child_info(
            parent,
            protocol::WaitRequest {
                selector: -1,
                options
            },
            &mut fs,
            &mut processes
        ),
        Err(STATUS_EINVAL)
    );
    for selector in [0] {
        let info = service
            .wait_child_info(
                parent,
                protocol::WaitRequest { selector, options },
                &mut fs,
                &mut processes,
            )
            .unwrap();
        assert_eq!(info, protocol::WaitInfo::default());
    }
    assert!(service.session(child.process_id).is_some());
}
