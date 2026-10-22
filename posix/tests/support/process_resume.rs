use super::*;

fn stopped() -> (
    PosixService,
    PeerIdentity,
    PeerIdentity,
    RecordingFilesystem,
    RecordingProcesses,
) {
    let (mut service, _, parent, child, fs, mut processes) = orphan_family();
    set_child_signal_policy(
        &mut service,
        parent,
        protocol::SIGNAL_DISPOSITION_CAUGHT,
        protocol::SIGNAL_CHILD_OPTION_NOCLDSTOP,
    );
    stop_job_member(&mut service, parent, child, &mut processes);
    set_child_signal_policy(&mut service, parent, protocol::SIGNAL_DISPOSITION_CAUGHT, 0);
    (service, parent, child, fs, processes)
}

fn wait(
    service: &mut PosixService,
    parent: PeerIdentity,
    child: PeerIdentity,
    options: u32,
    fs: &mut RecordingFilesystem,
    processes: &mut RecordingProcesses,
) -> protocol::WaitResult {
    service
        .wait_child(
            parent,
            protocol::WaitRequest {
                selector: child.process_id as i64,
                options: options | protocol::WAIT_NOHANG,
            },
            fs,
            processes,
        )
        .unwrap()
}

#[test]
fn failed_resume_keeps_the_child_stopped_and_publishes_no_continued_event() {
    let (mut service, parent, child, mut fs, mut processes) = stopped();
    send_signal(&mut service, parent, child, protocol::SIGNAL_CONT);
    for error in [
        protocol::STATUS_EAGAIN,
        protocol::STATUS_EIO,
        protocol::STATUS_ESRCH,
        protocol::STATUS_ENOSYS,
    ] {
        processes.resume_error = Some(error);
        assert_eq!(
            service.apply_process_resume(child.process_id, &mut processes),
            Err(error)
        );
        assert!(processes.resumed.is_empty());
        assert_eq!(
            service
                .process_resume_notification_processes()
                .collect::<Vec<_>>(),
            [child.process_id]
        );
        assert_eq!(service.refresh_child_notifications(&mut processes), Ok(0));
        assert!(!service.has_deferred_child_notifications());
        assert_eq!(
            service.signal_state(parent.process_id).unwrap().pending(),
            0
        );
        assert_eq!(
            wait(
                &mut service,
                parent,
                child,
                protocol::WAIT_CONTINUED,
                &mut fs,
                &mut processes
            ),
            protocol::WaitResult::default()
        );
        assert_eq!(
            wait(
                &mut service,
                parent,
                child,
                protocol::WAIT_UNTRACED | protocol::WAIT_NOWAIT,
                &mut fs,
                &mut processes
            )
            .status,
            (protocol::SIGNAL_STOP << 8) | 0x7f
        );
    }
    processes.resume_error = None;
    assert_eq!(
        service.apply_process_resume(child.process_id, &mut processes),
        Ok(true)
    );
    assert_eq!(processes.resumed, [142]);
    assert!(
        service
            .process_resume_notification_processes()
            .next()
            .is_none()
    );
    assert_eq!(service.refresh_child_notifications(&mut processes), Ok(1));
    let origin = child_signal_info::notification(&mut service, parent);
    assert_eq!(origin.process_id, child.process_id);
    assert_eq!(origin.child.event, protocol::signal_origin::CONTINUED);
    assert_eq!(
        wait(
            &mut service,
            parent,
            child,
            protocol::WAIT_CONTINUED,
            &mut fs,
            &mut processes
        )
        .status,
        protocol::WAIT_STATUS_CONTINUED
    );
    assert_eq!(
        service.apply_process_resume(child.process_id, &mut processes),
        Ok(false)
    );
    assert_eq!(processes.resumed, [142]);
    assert_eq!(
        wait(
            &mut service,
            parent,
            child,
            protocol::WAIT_CONTINUED,
            &mut fs,
            &mut processes
        ),
        protocol::WaitResult::default()
    );
}

#[test]
fn failed_lifecycle_observation_keeps_resume_owned_for_retry() {
    let (mut service, parent, child, _, mut processes) = stopped();
    send_signal(&mut service, parent, child, protocol::SIGNAL_CONT);
    processes.states.remove(&142);
    assert_eq!(
        service.apply_process_resume(child.process_id, &mut processes),
        Err(protocol::STATUS_ESRCH)
    );
    assert!(processes.resumed.is_empty());
    assert_eq!(
        service.signal_state(parent.process_id).unwrap().pending(),
        0
    );
    processes.states.insert(142, ProcessLifecycle::Running);
    assert_eq!(
        service.apply_process_resume(child.process_id, &mut processes),
        Ok(true)
    );
    assert_eq!(processes.resumed, [142]);
}

#[test]
fn failed_resume_does_not_freeze_parent_policy_before_the_real_transition() {
    for suppress_before in [false, true] {
        let (mut service, parent, child, _, mut processes) = stopped();
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
            flags(suppress_before),
        );
        send_signal(&mut service, parent, child, protocol::SIGNAL_CONT);
        processes.resume_error = Some(protocol::STATUS_EIO);
        assert_eq!(
            service.apply_process_resume(child.process_id, &mut processes),
            Err(protocol::STATUS_EIO)
        );
        set_child_signal_policy(
            &mut service,
            parent,
            protocol::SIGNAL_DISPOSITION_CAUGHT,
            flags(!suppress_before),
        );
        processes.resume_error = None;
        service
            .apply_process_resume(child.process_id, &mut processes)
            .unwrap();
        assert_eq!(service.refresh_child_notifications(&mut processes), Ok(1));
        assert_eq!(
            service.signal_state(parent.process_id).unwrap().pending() != 0,
            suppress_before
        );
    }
}

#[test]
fn resumed_child_notifies_the_new_parent_when_reparented_before_confirmation() {
    let (mut service, parent, child, _, mut processes) = stopped();
    let init = service.registered_peer(1400).unwrap();
    set_child_signal_policy(&mut service, init, protocol::SIGNAL_DISPOSITION_CAUGHT, 0);
    send_signal(&mut service, parent, child, protocol::SIGNAL_CONT);
    processes.resume_error = Some(protocol::STATUS_EIO);
    assert_eq!(
        service.apply_process_resume(child.process_id, &mut processes),
        Err(protocol::STATUS_EIO)
    );
    processes
        .states
        .insert(141, ProcessLifecycle::Exited { exit_code: 0 });
    assert_eq!(
        service.refresh_child_exit_notifications(&mut processes),
        Ok(1)
    );
    assert_eq!(service.parent_id(child.process_id), Some(init.process_id));
    assert_eq!(
        child_signal_info::notification(&mut service, init).process_id,
        parent.process_id
    );
    processes.resume_error = None;
    service
        .apply_process_resume(child.process_id, &mut processes)
        .unwrap();
    assert_eq!(service.refresh_child_notifications(&mut processes), Ok(1));
    let origin = child_signal_info::notification(&mut service, init);
    assert_eq!(origin.process_id, child.process_id);
    assert_eq!(origin.child.event, protocol::signal_origin::CONTINUED);
    assert_eq!(
        service.signal_state(parent.process_id).unwrap().pending(),
        0
    );
}

#[test]
fn native_exit_before_resume_does_not_fabricate_a_continued_transition() {
    let (mut service, parent, child, mut fs, mut processes) = stopped();
    send_signal(&mut service, parent, child, protocol::SIGNAL_CONT);
    // The object can exit between the first lifecycle query and resume.
    processes.resume_error = Some(protocol::STATUS_ESRCH);
    assert_eq!(
        service.apply_process_resume(child.process_id, &mut processes),
        Err(protocol::STATUS_ESRCH)
    );
    processes
        .states
        .insert(142, ProcessLifecycle::Exited { exit_code: 37 });
    assert_eq!(
        service.apply_process_resume(child.process_id, &mut processes),
        Ok(true)
    );
    assert!(processes.resumed.is_empty());
    assert!(
        service
            .process_resume_notification_processes()
            .next()
            .is_none()
    );
    assert!(!service.has_deferred_child_notifications());
    assert_eq!(
        service.refresh_child_exit_notifications(&mut processes),
        Ok(1)
    );
    let origin = child_signal_info::notification(&mut service, parent);
    assert_eq!(origin.child.event, protocol::signal_origin::EXITED);
    assert_eq!(origin.child.status, 37);
    assert_eq!(
        wait(&mut service, parent, child, 0, &mut fs, &mut processes).status,
        37 << 8
    );
    assert!(!service.has_deferred_child_notifications());
}

#[test]
fn later_stop_cannot_overtake_resume_and_its_new_token_survives_completion() {
    let (mut service, parent, child, mut fs, mut processes) = stopped();
    send_signal(&mut service, parent, child, protocol::SIGNAL_CONT);
    let delivery = deliver_signal(&mut service, parent, child, protocol::SIGNAL_STOP);
    let mut bytes = [0; protocol::SIGNAL_DELIVERY_LEN];
    protocol::encode_signal_delivery(delivery, &mut bytes).unwrap();
    processes.resume_error = Some(protocol::STATUS_EIO);
    assert_eq!(
        service.report_process_stopped(child, &bytes, &mut processes),
        Err(protocol::STATUS_EIO)
    );
    assert_eq!(processes.control_events, [(142, "suspend")]);
    assert_eq!(
        service.signal_state(parent.process_id).unwrap().pending(),
        0
    );
    processes.resume_error = None;
    service
        .report_process_stopped(child, &bytes, &mut processes)
        .unwrap();
    assert_eq!(
        processes.control_events,
        [(142, "suspend"), (142, "resume"), (142, "suspend")]
    );
    assert_eq!(
        service.report_process_stopped(child, &bytes, &mut processes),
        Err(protocol::STATUS_EAGAIN)
    );
    let origin = child_signal_info::notification(&mut service, parent);
    assert_eq!(origin.child.event, protocol::signal_origin::CONTINUED);
    assert_eq!(
        wait(
            &mut service,
            parent,
            child,
            protocol::WAIT_UNTRACED,
            &mut fs,
            &mut processes
        )
        .status,
        (protocol::SIGNAL_STOP << 8) | 0x7f
    );
    assert_eq!(
        wait(
            &mut service,
            parent,
            child,
            protocol::WAIT_CONTINUED,
            &mut fs,
            &mut processes
        ),
        protocol::WaitResult::default()
    );
}

#[test]
fn failed_resume_cannot_block_another_child_of_the_same_parent() {
    let (mut service, [_, parent, first, second, _], mut fs, mut processes) = orphan_job_family();
    set_child_signal_policy(
        &mut service,
        parent,
        protocol::SIGNAL_DISPOSITION_CAUGHT,
        protocol::SIGNAL_CHILD_OPTION_NOCLDSTOP,
    );
    for child in [first, second] {
        stop_job_member(&mut service, parent, child, &mut processes);
    }
    set_child_signal_policy(&mut service, parent, protocol::SIGNAL_DISPOSITION_CAUGHT, 0);
    for child in [first, second] {
        send_signal(&mut service, parent, child, protocol::SIGNAL_CONT);
    }
    processes.resume_failure = Some((first.process_id as u32, protocol::STATUS_EIO));
    assert_eq!(
        service.apply_process_resume(first.process_id, &mut processes),
        Err(protocol::STATUS_EIO)
    );
    assert_eq!(
        service.apply_process_resume(second.process_id, &mut processes),
        Ok(true)
    );
    assert_eq!(service.refresh_child_notifications(&mut processes), Ok(1));
    assert_eq!(
        child_signal_info::notification(&mut service, parent).process_id,
        second.process_id
    );
    assert_eq!(
        wait(
            &mut service,
            parent,
            first,
            protocol::WAIT_CONTINUED,
            &mut fs,
            &mut processes
        ),
        protocol::WaitResult::default()
    );
    assert_eq!(
        wait(
            &mut service,
            parent,
            second,
            protocol::WAIT_CONTINUED,
            &mut fs,
            &mut processes
        )
        .status,
        protocol::WAIT_STATUS_CONTINUED
    );
    processes.resume_failure = None;
    assert_eq!(
        service.apply_process_resume(first.process_id, &mut processes),
        Ok(true)
    );
    assert_eq!(service.refresh_child_notifications(&mut processes), Ok(1));
    assert_eq!(
        child_signal_info::notification(&mut service, parent).process_id,
        first.process_id
    );
}

#[test]
fn sigkill_resume_does_not_generate_a_sigcont_child_event() {
    let (mut service, parent, child, mut fs, mut processes) = stopped();
    send_signal(&mut service, parent, child, protocol::SIGNAL_KILL);
    service
        .apply_process_resume(child.process_id, &mut processes)
        .unwrap();
    assert_eq!(processes.resumed, [142]);
    assert_eq!(service.refresh_child_notifications(&mut processes), Ok(0));
    assert_eq!(
        wait(
            &mut service,
            parent,
            child,
            protocol::WAIT_CONTINUED,
            &mut fs,
            &mut processes
        ),
        protocol::WaitResult::default()
    );
    let delivery = dequeue_signal(&mut service, child);
    assert_eq!(delivery.signal, protocol::SIGNAL_KILL);
    let mut bytes = [0; protocol::SIGNAL_DELIVERY_LEN];
    protocol::encode_signal_delivery(delivery, &mut bytes).unwrap();
    service
        .report_process_signaled(child, &bytes, &mut processes)
        .unwrap();
    assert_eq!(
        service.refresh_child_exit_notifications(&mut processes),
        Ok(1)
    );
    assert_eq!(
        child_signal_info::notification(&mut service, parent)
            .child
            .event,
        protocol::signal_origin::KILLED
    );
}

#[test]
fn runtime_uses_confirmed_resume_and_retries_even_without_a_child_notification() {
    let runtime = include_str!("../../src/main.rs");
    let drain = runtime
        .split("fn deliver_process_resume_notifications(")
        .nth(1)
        .unwrap()
        .split("#[cfg")
        .next()
        .unwrap();
    assert!(drain.contains("service.apply_process_resume(process_id, processes)"));
    assert!(!drain.contains("acknowledge_process_resume"));
    assert!(!drain.contains("resume_handle"));
    let deadline = runtime
        .split("let child_notification_deadline =")
        .nth(1)
        .unwrap()
        .split("let deadline =")
        .next()
        .unwrap();
    assert!(deadline.contains("process_resume_notification_processes().next().is_some()"));
    assert!(deadline.contains("now.saturating_add(10_000_000)"));
}
