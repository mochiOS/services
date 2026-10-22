use super::*;

fn stopped_family() -> (PosixService, PeerIdentity, PeerIdentity, RecordingProcesses) {
    let (mut service, _, parent, child, _, mut processes) = orphan_family();
    set_child_signal_policy(
        &mut service,
        parent,
        protocol::SIGNAL_DISPOSITION_CAUGHT,
        protocol::SIGNAL_CHILD_OPTION_NOCLDSTOP,
    );
    stop_job_member(&mut service, parent, child, &mut processes);
    assert_eq!(
        service.signal_state(parent.process_id).unwrap().pending(),
        0
    );
    (service, parent, child, processes)
}

fn next_parent_image() -> mnu_abi::ProcessStatus {
    mnu_abi::ProcessStatus {
        process_id: 1401,
        image_revision: 1,
        state: mnu_abi::PROCESS_STATE_RUNNING,
        ..Default::default()
    }
}

#[test]
fn continued_notification_observes_exec_that_removed_nocldstop_without_parent_rpc() {
    let (mut service, parent, child, mut processes) = stopped_family();
    processes.images.insert(141, Ok(next_parent_image()));
    // A different authenticated process resumes the child; the new parent
    // image has not entered request admission at all.
    let sender = service.registered_peer(1400).unwrap();
    send_signal(&mut service, sender, child, protocol::SIGNAL_CONT);
    service
        .apply_process_resume(child.process_id, &mut processes)
        .unwrap();
    assert_eq!(
        service.refresh_child_exit_notifications(&mut processes),
        Ok(0)
    );
    assert_eq!(
        service.signal_state(parent.process_id).unwrap().pending(),
        1u64 << (protocol::SIGNAL_CHLD - 1)
    );
}

#[test]
fn parent_observation_failure_keeps_continued_notification_for_retry() {
    let (mut service, parent, child, mut processes) = stopped_family();
    processes.images.insert(141, Err(protocol::STATUS_EIO));
    let sender = service.registered_peer(1400).unwrap();
    send_signal(&mut service, sender, child, protocol::SIGNAL_CONT);
    service
        .apply_process_resume(child.process_id, &mut processes)
        .unwrap();
    assert_eq!(
        service.refresh_child_exit_notifications(&mut processes),
        Err(protocol::STATUS_EIO)
    );
    assert_eq!(
        service.signal_state(parent.process_id).unwrap().pending(),
        0
    );
    processes.images.insert(141, Ok(next_parent_image()));
    assert_eq!(
        service.refresh_child_exit_notifications(&mut processes),
        Ok(0)
    );
    assert_eq!(
        service.signal_state(parent.process_id).unwrap().pending(),
        1u64 << (protocol::SIGNAL_CHLD - 1)
    );
}

#[test]
fn same_image_action_changes_do_not_rewrite_already_generated_notifications() {
    for suppress_at_generation in [false, true] {
        let (mut service, parent, child, mut processes) = stopped_family();
        let flags = |suppress| {
            if suppress {
                protocol::SIGNAL_CHILD_OPTION_NOCLDSTOP
            } else {
                0
            }
        };
        set_child_signal_policy(
            &mut service,
            parent,
            protocol::SIGNAL_DISPOSITION_CAUGHT,
            flags(suppress_at_generation),
        );
        send_signal(&mut service, parent, child, protocol::SIGNAL_CONT);
        service
            .apply_process_resume(child.process_id, &mut processes)
            .unwrap();
        set_child_signal_policy(
            &mut service,
            parent,
            protocol::SIGNAL_DISPOSITION_CAUGHT,
            flags(!suppress_at_generation),
        );
        assert_eq!(service.refresh_child_notifications(&mut processes), Ok(1));
        assert!(!service.has_deferred_child_notifications());
        assert_eq!(
            service.signal_state(parent.process_id).unwrap().pending() != 0,
            !suppress_at_generation
        );
    }
}

#[test]
fn continued_event_precedes_a_later_stop_and_failed_observation_keeps_both_retryable() {
    let (mut service, parent, child, mut processes) = stopped_family();
    set_child_signal_policy(&mut service, parent, protocol::SIGNAL_DISPOSITION_CAUGHT, 0);
    send_signal(&mut service, parent, child, protocol::SIGNAL_CONT);
    let delivery = deliver_signal(&mut service, parent, child, protocol::SIGNAL_STOP);
    let mut bytes = [0; protocol::SIGNAL_DELIVERY_LEN];
    protocol::encode_signal_delivery(delivery, &mut bytes).unwrap();
    processes.images.insert(141, Err(protocol::STATUS_EIO));
    assert_eq!(
        service.report_process_stopped(child, &bytes, &mut processes),
        Err(protocol::STATUS_EIO)
    );
    assert_eq!(processes.suspended, vec![142]);
    assert!(service.has_deferred_child_notifications());
    processes.images.remove(&141);
    service
        .report_process_stopped(child, &bytes, &mut processes)
        .unwrap();
    assert_eq!(processes.suspended, vec![142, 142]);
    assert!(!service.has_deferred_child_notifications());
    let origin = child_signal_info::notification(&mut service, parent);
    assert_eq!(origin.process_id, child.process_id);
    assert_eq!(origin.child.event, protocol::signal_origin::CONTINUED);
    assert_eq!(origin.child.status, protocol::SIGNAL_CONT);
}

#[test]
fn direct_wait_flushes_the_earlier_continue_before_reaping_the_child() {
    let (mut service, parent, child, mut processes) = stopped_family();
    set_child_signal_policy(&mut service, parent, protocol::SIGNAL_DISPOSITION_CAUGHT, 0);
    send_signal(&mut service, parent, child, protocol::SIGNAL_CONT);
    service
        .apply_process_resume(child.process_id, &mut processes)
        .unwrap();
    processes
        .states
        .insert(142, ProcessLifecycle::Exited { exit_code: 37 });
    let result = service
        .wait_child(
            parent,
            protocol::WaitRequest {
                selector: child.process_id as i64,
                options: protocol::WAIT_NOHANG,
            },
            &mut RecordingFilesystem::default(),
            &mut processes,
        )
        .unwrap();
    assert_eq!(result.status, 37 << 8);
    assert!(service.session(child.process_id).is_none());
    let origin = child_signal_info::notification(&mut service, parent);
    assert_eq!(origin.child.event, protocol::signal_origin::CONTINUED);
    assert_eq!(origin.process_id, child.process_id);
    assert_eq!(origin.real_uid, 505);
    assert!(!service.has_deferred_child_notifications());
}

#[test]
fn one_failed_parent_does_not_block_another_parents_notification() {
    let (mut service, parent, child, mut processes) = stopped_family();
    let grandchild = PeerIdentity {
        process_id: 1403,
        ..child
    };
    service
        .adopt_child(
            child,
            AuthenticatedProcess {
                handle: 143,
                process_id: 1403,
            },
            &mut RecordingFilesystem::default(),
        )
        .unwrap();
    processes.states.insert(143, ProcessLifecycle::Running);
    processes.identities.insert(143, 1403);
    set_child_signal_policy(
        &mut service,
        child,
        protocol::SIGNAL_DISPOSITION_CAUGHT,
        protocol::SIGNAL_CHILD_OPTION_NOCLDSTOP,
    );
    stop_job_member(&mut service, child, grandchild, &mut processes);
    set_child_signal_policy(&mut service, parent, protocol::SIGNAL_DISPOSITION_CAUGHT, 0);
    set_child_signal_policy(&mut service, child, protocol::SIGNAL_DISPOSITION_CAUGHT, 0);
    send_signal(&mut service, parent, child, protocol::SIGNAL_CONT);
    send_signal(&mut service, child, grandchild, protocol::SIGNAL_CONT);
    service
        .apply_process_resume(child.process_id, &mut processes)
        .unwrap();
    service
        .apply_process_resume(grandchild.process_id, &mut processes)
        .unwrap();
    processes.images.insert(141, Err(protocol::STATUS_EIO));
    assert_eq!(
        service.refresh_child_notifications(&mut processes),
        Err(protocol::STATUS_EIO)
    );
    let chld = 1u64 << (protocol::SIGNAL_CHLD - 1);
    assert_eq!(
        service.signal_state(parent.process_id).unwrap().pending() & chld,
        0
    );
    assert_eq!(
        service.signal_state(child.process_id).unwrap().pending() & chld,
        chld
    );
    assert!(service.has_deferred_child_notifications());
    processes.images.remove(&141);
    assert_eq!(service.refresh_child_notifications(&mut processes), Ok(1));
    assert_eq!(service.refresh_child_notifications(&mut processes), Ok(0));
    assert!(!service.has_deferred_child_notifications());
}

#[test]
fn repeated_continue_for_an_already_running_child_does_not_accumulate_events() {
    let (mut service, parent, child, mut processes) = stopped_family();
    for _ in 0..100 {
        send_signal(&mut service, parent, child, protocol::SIGNAL_CONT);
    }
    assert!(!service.has_deferred_child_notifications());
    assert_eq!(service.refresh_child_notifications(&mut processes), Ok(0));
    service
        .apply_process_resume(child.process_id, &mut processes)
        .unwrap();
    assert!(service.has_deferred_child_notifications());
    assert_eq!(service.refresh_child_notifications(&mut processes), Ok(1));
    assert!(!service.has_deferred_child_notifications());
    assert_eq!(service.refresh_child_notifications(&mut processes), Ok(0));
    for _ in 0..100 {
        send_signal(&mut service, parent, child, protocol::SIGNAL_CONT);
    }
    service
        .apply_process_resume(child.process_id, &mut processes)
        .unwrap();
    assert!(!service.has_deferred_child_notifications());
    assert_eq!(service.refresh_child_notifications(&mut processes), Ok(0));
}
