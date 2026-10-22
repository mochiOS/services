use super::*;

fn parent_image(revision: u64) -> mnu_abi::ProcessStatus {
    mnu_abi::ProcessStatus {
        process_id: 1401,
        image_revision: revision,
        state: mnu_abi::PROCESS_STATE_RUNNING,
        ..Default::default()
    }
}

fn stop_delivery(
    service: &mut PosixService,
    parent: PeerIdentity,
    child: PeerIdentity,
) -> [u8; protocol::SIGNAL_DELIVERY_LEN] {
    let delivery = deliver_signal(service, parent, child, protocol::SIGNAL_STOP);
    let mut bytes = [0; protocol::SIGNAL_DELIVERY_LEN];
    protocol::encode_signal_delivery(delivery, &mut bytes).unwrap();
    bytes
}

#[test]
fn stop_notification_uses_parents_committed_image_without_a_parent_request() {
    for revision in [0, 1] {
        let (mut service, _, parent, child, mut fs, mut processes) = orphan_family();
        set_child_signal_policy(
            &mut service,
            parent,
            protocol::SIGNAL_DISPOSITION_CAUGHT,
            protocol::SIGNAL_CHILD_OPTION_NOCLDSTOP,
        );
        let bytes = stop_delivery(&mut service, parent, child);
        processes.images.insert(141, Ok(parent_image(revision)));
        service
            .report_process_stopped(child, &bytes, &mut processes)
            .unwrap();
        assert_eq!(processes.suspended, vec![142]);
        let chld = 1u64 << (protocol::SIGNAL_CHLD - 1);
        assert_eq!(
            service.signal_state(parent.process_id).unwrap().pending() & chld != 0,
            revision == 1
        );
        // Resetting the parent's caught disposition does not lose wait status.
        let result = service
            .wait_child(
                parent,
                protocol::WaitRequest {
                    selector: child.process_id as i64,
                    options: protocol::WAIT_NOHANG | protocol::WAIT_UNTRACED,
                },
                &mut fs,
                &mut processes,
            )
            .unwrap();
        assert_eq!(result.process_id, child.process_id);
        assert_eq!(result.status, (protocol::SIGNAL_STOP << 8) | 0x7f);
    }
}

#[test]
fn failed_parent_observation_preserves_stop_token_for_retry() {
    let (mut service, _, parent, child, _, mut processes) = orphan_family();
    set_child_signal_disposition(&mut service, parent, protocol::SIGNAL_DISPOSITION_CAUGHT);
    let bytes = stop_delivery(&mut service, parent, child);
    processes.images.insert(141, Err(protocol::STATUS_EIO));
    assert_eq!(
        service.report_process_stopped(child, &bytes, &mut processes),
        Err(protocol::STATUS_EIO)
    );
    assert!(processes.suspended.is_empty());
    assert_eq!(
        service.signal_state(parent.process_id).unwrap().pending(),
        0
    );
    processes.images.insert(141, Ok(parent_image(1)));
    assert_eq!(
        service.report_process_stopped(child, &bytes, &mut processes),
        Ok(())
    );
    assert_eq!(processes.suspended, vec![142]);
    assert_eq!(
        service.signal_state(parent.process_id).unwrap().pending(),
        1u64 << (protocol::SIGNAL_CHLD - 1)
    );
    assert_eq!(
        service.report_process_stopped(child, &bytes, &mut processes),
        Err(protocol::STATUS_EAGAIN)
    );
    assert_eq!(processes.image_reads, vec![141, 141]);
}

#[test]
fn forged_stop_token_cannot_observe_or_reset_the_parent_image() {
    let (mut service, _, parent, child, _, mut processes) = orphan_family();
    set_child_signal_disposition(&mut service, parent, protocol::SIGNAL_DISPOSITION_CAUGHT);
    let valid = stop_delivery(&mut service, parent, child);
    let mut forged = protocol::decode_signal_delivery(&valid).unwrap();
    forged.token += 1;
    let mut bytes = [0; protocol::SIGNAL_DELIVERY_LEN];
    protocol::encode_signal_delivery(forged, &mut bytes).unwrap();
    processes.images.insert(141, Ok(parent_image(1)));
    assert_eq!(
        service.report_process_stopped(child, &bytes, &mut processes),
        Err(protocol::STATUS_EAGAIN)
    );
    assert!(processes.image_reads.is_empty());
    assert!(processes.suspended.is_empty());
    // A failed forged request leaves the actual delivery available.
    assert_eq!(
        service.report_process_stopped(child, &valid, &mut processes),
        Ok(())
    );
}

#[test]
fn failed_native_suspend_keeps_the_authenticated_stop_retryable() {
    let (mut service, _, parent, child, _, mut processes) = orphan_family();
    let bytes = stop_delivery(&mut service, parent, child);
    processes.suspend_error = Some(protocol::STATUS_EIO);
    assert_eq!(
        service.report_process_stopped(child, &bytes, &mut processes),
        Err(protocol::STATUS_EIO)
    );
    assert!(processes.suspended.is_empty());
    assert_eq!(
        service.signal_state(parent.process_id).unwrap().pending(),
        0
    );
    processes.suspend_error = None;
    assert_eq!(
        service.report_process_stopped(child, &bytes, &mut processes),
        Ok(())
    );
    assert_eq!(processes.suspended, vec![142]);
    assert_eq!(
        service.report_process_stopped(child, &bytes, &mut processes),
        Err(protocol::STATUS_EAGAIN)
    );
    assert_eq!(processes.suspended, vec![142]);
}
