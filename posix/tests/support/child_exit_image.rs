use super::*;

fn family(
    revision: u64,
) -> (
    PosixService,
    PeerIdentity,
    PeerIdentity,
    RecordingFilesystem,
    RecordingProcesses,
) {
    let (mut service, _, parent, child, filesystem, mut processes) = orphan_family();
    let mut bytes = [0; protocol::SIGNAL_DISPOSITION_LEN];
    protocol::encode_signal_disposition(
        protocol::SignalDisposition {
            signal: protocol::SIGNAL_CHLD,
            kind: protocol::SIGNAL_DISPOSITION_CAUGHT,
            child_options: protocol::SIGNAL_CHILD_OPTION_NOCLDWAIT,
        },
        &mut bytes,
    )
    .unwrap();
    assert_eq!(
        service
            .handle(
                parent,
                protocol::Header {
                    opcode: protocol::OP_SIGNAL_DISPOSITION,
                    flags: protocol::SIGNAL_DISPOSITION_SET,
                    ..Default::default()
                },
                &bytes
            )
            .header
            .status,
        0
    );
    for (handle, process_id, image_revision) in [(140, 1400, 0), (141, 1401, revision)] {
        processes.images.insert(
            handle,
            Ok(mnu_abi::ProcessStatus {
                process_id,
                image_revision,
                state: mnu_abi::PROCESS_STATE_RUNNING,
                ..Default::default()
            }),
        );
    }
    processes
        .states
        .insert(142, ProcessLifecycle::Exited { exit_code: 37 });
    (service, parent, child, filesystem, processes)
}

#[test]
fn child_exit_refreshes_parents_new_image_before_applying_nocldwait() {
    let (mut service, parent, child, mut fs, mut processes) = family(1);
    // No request/startup notification from the new parent image is issued.
    service
        .refresh_child_exit_notifications(&mut processes)
        .unwrap();
    assert_eq!(
        service.reap_discarded_children(&mut fs, &mut processes),
        Ok(0)
    );
    assert!(service.session(child.process_id).is_some());
    let waited = service
        .wait_child(
            parent,
            protocol::WaitRequest {
                selector: child.process_id as i64,
                options: protocol::WAIT_NOHANG,
            },
            &mut fs,
            &mut processes,
        )
        .unwrap();
    assert_eq!(waited.process_id, child.process_id);
    assert_eq!(waited.status, 37 << 8);
}

#[test]
fn direct_discard_sweep_also_rechecks_parent_without_a_prior_lifecycle_sweep() {
    for revision in [0, 1] {
        let (mut service, _, child, mut fs, mut processes) = family(revision);
        assert_eq!(
            service.reap_discarded_children(&mut fs, &mut processes),
            Ok(usize::from(revision == 0))
        );
        assert_eq!(service.session(child.process_id).is_some(), revision != 0);
    }
}

#[test]
fn failed_parent_image_observation_cannot_discard_an_unreported_exit() {
    let (mut service, parent, child, mut fs, mut processes) = family(1);
    let valid = processes.images[&141];
    processes.images.insert(141, Err(protocol::STATUS_EIO));
    assert_eq!(
        service.refresh_child_exit_notifications(&mut processes),
        Err(protocol::STATUS_EIO)
    );
    assert_eq!(
        service.reap_discarded_children(&mut fs, &mut processes),
        Err(protocol::STATUS_EIO)
    );
    assert!(service.session(child.process_id).is_some());
    assert!(processes.released.is_empty());
    processes.images.insert(141, valid);
    service
        .refresh_child_exit_notifications(&mut processes)
        .unwrap();
    let waited = service
        .wait_child(
            parent,
            protocol::WaitRequest {
                selector: child.process_id as i64,
                options: protocol::WAIT_NOHANG,
            },
            &mut fs,
            &mut processes,
        )
        .unwrap();
    assert_eq!(waited.status, 37 << 8);
}

#[test]
fn direct_wait_observes_exec_without_a_startup_request_or_reactor_pass() {
    let (mut service, parent, child, mut fs, mut processes) = family(1);
    let result = service
        .wait_child(
            parent,
            protocol::WaitRequest {
                selector: child.process_id as i64,
                options: protocol::WAIT_NOHANG,
            },
            &mut fs,
            &mut processes,
        )
        .unwrap();
    assert_eq!(result.process_id, child.process_id);
    assert_eq!(result.status, 37 << 8);
}

#[test]
fn retained_exited_parent_metadata_is_usable_during_background_cleanup() {
    let (mut service, parent, child, mut fs, mut processes) = family(1);
    processes
        .states
        .insert(141, ProcessLifecycle::Exited { exit_code: 50 });
    processes
        .images
        .get_mut(&141)
        .unwrap()
        .as_mut()
        .unwrap()
        .state = mnu_abi::PROCESS_STATE_EXITED;
    // This is not a request authorized on behalf of the dead parent. It is
    // service-owned cleanup using its still-retained native process object.
    assert_eq!(
        service.reap_discarded_children(&mut fs, &mut processes),
        Ok(0)
    );
    assert!(service.session(child.process_id).is_some());
    assert!(processes.released.is_empty());
    // User request admission still rejects an exited caller.
    assert_eq!(
        service.refresh_image_state(parent, &mut processes),
        Err(protocol::STATUS_ESRCH)
    );
}

#[test]
fn exec_does_not_resurrect_a_status_discarded_by_an_earlier_observation() {
    let (mut service, _, child, mut fs, mut processes) = family(0);
    service
        .refresh_child_exit_notifications(&mut processes)
        .unwrap();
    processes
        .images
        .get_mut(&141)
        .unwrap()
        .as_mut()
        .unwrap()
        .image_revision = 1;
    assert_eq!(
        service.reap_discarded_children(&mut fs, &mut processes),
        Ok(1)
    );
    assert!(service.session(child.process_id).is_none());
}

#[test]
fn exec_between_parent_observations_cannot_turn_a_stale_candidate_into_discard() {
    let (mut service, _, child, mut fs, mut processes) = family(1);
    let mut previous = processes.images[&141].unwrap();
    previous.image_revision = 0;
    processes
        .image_script
        .insert(141, std::collections::VecDeque::from([Ok(previous)]));
    // The initial candidate check sees the old image. The later parent read,
    // after native child exit confirmation, sees the committed new image.
    assert_eq!(
        service.reap_discarded_children(&mut fs, &mut processes),
        Ok(0)
    );
    assert!(service.session(child.process_id).is_some());
    assert!(processes.released.is_empty());
}
