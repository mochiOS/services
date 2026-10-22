use super::*;

fn native_image(process_id: u64, revision: u64) -> mnu_abi::ProcessStatus {
    mnu_abi::ProcessStatus {
        process_id,
        image_revision: revision,
        state: mnu_abi::PROCESS_STATE_RUNNING,
        ..Default::default()
    }
}

#[test]
fn old_request_cannot_reap_a_child_after_exec_but_the_new_image_can() {
    let (mut service, _, parent, child, mut fs, mut processes) = orphan_family();
    let old = service.capture_request_image(parent).unwrap();
    processes
        .images
        .insert(141, Ok(native_image(parent.process_id, 1)));
    processes
        .states
        .insert(142, ProcessLifecycle::Exited { exit_code: 37 });
    let request = protocol::WaitRequest {
        selector: child.process_id as i64,
        options: protocol::WAIT_NOHANG,
    };
    let result = service
        .validate_request_image(parent, old, &mut processes)
        .and_then(|()| service.wait_child(parent, request, &mut fs, &mut processes));
    assert_eq!(result, Err(protocol::STATUS_ESRCH));
    assert!(processes.released.is_empty());
    assert!(service.session(child.process_id).is_some());
    let fresh = service.capture_request_image(parent).unwrap();
    service
        .validate_request_image(parent, fresh, &mut processes)
        .unwrap();
    let waited = service
        .wait_child(parent, request, &mut fs, &mut processes)
        .unwrap();
    assert_eq!(
        (waited.process_id, waited.status),
        (child.process_id, 37 << 8)
    );
    assert_eq!(processes.released, vec![142]);
}

#[test]
fn old_sigwait_cannot_take_a_pending_signal_from_a_surviving_thread() {
    let (mut service, _, parent, _, _, mut processes) = orphan_family();
    let sender = mnu_abi::ExecutionIdentity {
        process_id: parent.process_id,
        thread_id: 901,
    };
    let mask = 1u64 << 9;
    terminal_mask(&mut service, parent, sender.thread_id, mask);
    let old = service.capture_request_image(parent).unwrap();
    send_signal(&mut service, parent, parent, 10);
    processes
        .images
        .insert(141, Ok(native_image(parent.process_id, 1)));
    // Delivery epoch and native TID have not changed; neither alone detects exec.
    let result = service
        .validate_request_image(parent, old, &mut processes)
        .and_then(|()| service.try_wait_signal_info(parent, sender, mask, 0));
    assert_eq!(result, Err(protocol::STATUS_ESRCH));
    assert_eq!(
        service.signal_state(parent.process_id).unwrap().pending(),
        mask
    );
    let fresh = service.capture_request_image(parent).unwrap();
    service
        .validate_request_image(parent, fresh, &mut processes)
        .unwrap();
    assert_eq!(
        service
            .try_wait_signal_info(parent, sender, mask, 0)
            .unwrap()
            .signal,
        10
    );
    assert_eq!(
        service.signal_state(parent.process_id).unwrap().pending(),
        0
    );
}

#[test]
fn foreign_image_provenance_cannot_trigger_a_native_observation() {
    let (mut service, _, parent, child, _, mut processes) = orphan_family();
    let image = service.capture_request_image(parent).unwrap();
    assert_eq!(
        service.validate_request_image(child, image, &mut processes),
        Err(protocol::STATUS_EPERM)
    );
    assert!(processes.image_reads.is_empty());
}

#[test]
fn failed_observation_does_not_consume_events_or_invalidate_a_same_image_request() {
    let (mut service, _, parent, child, mut fs, mut processes) = orphan_family();
    let image = service.capture_request_image(parent).unwrap();
    processes
        .states
        .insert(142, ProcessLifecycle::Exited { exit_code: 37 });
    processes.images.insert(141, Err(protocol::STATUS_EIO));
    assert_eq!(
        service.validate_request_image(parent, image, &mut processes),
        Err(protocol::STATUS_EIO)
    );
    assert!(processes.released.is_empty());
    assert!(service.session(child.process_id).is_some());
    processes.images.remove(&141);
    service
        .validate_request_image(parent, image, &mut processes)
        .unwrap();
    assert_eq!(
        service
            .wait_child(
                parent,
                protocol::WaitRequest {
                    selector: child.process_id as i64,
                    options: protocol::WAIT_NOHANG,
                },
                &mut fs,
                &mut processes
            )
            .unwrap()
            .status,
        37 << 8
    );
}
