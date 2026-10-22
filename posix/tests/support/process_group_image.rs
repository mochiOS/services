use super::*;

struct NoImageObservation;
impl ProcessBackend<u32> for NoImageObservation {
    fn status(&mut self, _: u32) -> Result<ProcessLifecycle, i32> {
        panic!("no lifecycle fallback")
    }
    fn execution_usage(&mut self, _: u32) -> Result<mnu_abi::ProcessExecutionUsage, i32> {
        panic!("no CPU fallback")
    }
    fn suspend(&mut self, _: u32) -> Result<(), i32> {
        panic!("no suspension")
    }
    fn terminate(&mut self, _: u32, _: u64) -> Result<(), i32> {
        panic!("no termination")
    }
    fn release(&mut self, _: u32) {
        panic!("retain the owned reference")
    }
}

fn family() -> (PosixService, PeerIdentity, PeerIdentity, RecordingProcesses) {
    let parent = PeerIdentity {
        process_id: 2201,
        effective_uid: 501,
        effective_gid: 20,
    };
    let child = PeerIdentity {
        process_id: 2202,
        ..parent
    };
    let mut service = service_for(parent);
    service
        .adopt_child(
            parent,
            AuthenticatedProcess {
                handle: 91,
                process_id: child.process_id,
            },
            &mut RecordingFilesystem::default(),
        )
        .unwrap();
    let mut processes = RecordingProcesses::default();
    processes.images.insert(
        91,
        Ok(mnu_abi::ProcessStatus {
            process_id: child.process_id,
            state: mnu_abi::PROCESS_STATE_RUNNING,
            ..Default::default()
        }),
    );
    (service, parent, child, processes)
}

fn request(
    service: &mut PosixService,
    caller: PeerIdentity,
    target: i64,
    group: i64,
    processes: &mut RecordingProcesses,
) -> i32 {
    let mut payload = [0; protocol::PROCESS_GROUP_REQUEST_LEN];
    protocol::encode_process_group_request(target, group, &mut payload).unwrap();
    let response = service.handle_process_group_request(
        caller,
        protocol::Header {
            opcode: protocol::OP_SET_PROCESS_GROUP,
            request_id: 77,
            ..Default::default()
        },
        &payload,
        &[],
        processes,
    );
    assert_eq!(response.response.header.request_id, 77);
    assert!(response.handles.is_empty());
    assert!(response.response.payload.is_empty());
    response.response.header.status
}

fn group(service: &mut PosixService, caller: PeerIdentity, target: u64) -> u64 {
    let mut payload = [0; protocol::PROCESS_ID_REQUEST_LEN];
    protocol::encode_process_id_request(target as i64, &mut payload).unwrap();
    let response = service.handle(
        caller,
        protocol::Header {
            opcode: protocol::OP_PROCESS_INFO,
            ..Default::default()
        },
        &payload,
    );
    assert_eq!(response.header.status, 0);
    protocol::decode_process_info(&response.payload)
        .unwrap()
        .process_group_id
}

#[test]
fn parent_changes_only_pre_exec_child_and_observes_retained_not_claimed_identity() {
    let (mut service, parent, child, mut processes) = family();
    assert_eq!(
        request(
            &mut service,
            parent,
            child.process_id as i64,
            0,
            &mut processes
        ),
        0
    );
    assert_eq!(processes.image_reads, [91]); // Native selector is not the PID.
    assert_eq!(
        group(&mut service, parent, child.process_id),
        child.process_id
    );
    processes
        .images
        .get_mut(&91)
        .unwrap()
        .as_mut()
        .unwrap()
        .image_revision = 1;
    assert_eq!(
        request(
            &mut service,
            parent,
            child.process_id as i64,
            parent.process_id as i64,
            &mut processes
        ),
        -13
    );
    assert_eq!(
        group(&mut service, parent, child.process_id),
        child.process_id
    );
    // The child itself may still move after exec, without a native metadata RPC.
    processes.image_reads.clear();
    assert_eq!(
        request(
            &mut service,
            child,
            0,
            parent.process_id as i64,
            &mut processes
        ),
        0
    );
    assert!(processes.image_reads.is_empty());
    assert_eq!(
        group(&mut service, parent, child.process_id),
        parent.process_id
    );
}

#[test]
fn failed_or_malformed_observations_cannot_change_groups() {
    let original = family().3.images[&91].unwrap();
    for (observation, error) in [
        (Err(protocol::STATUS_ENOSYS), protocol::STATUS_ENOSYS),
        (Err(protocol::STATUS_EIO), protocol::STATUS_EIO),
        (Err(-13), -13),
        (
            Ok(mnu_abi::ProcessStatus {
                process_id: 999,
                ..original
            }),
            protocol::STATUS_EIO,
        ),
        (
            Ok(mnu_abi::ProcessStatus {
                reserved: 1,
                ..original
            }),
            protocol::STATUS_EIO,
        ),
        (
            Ok(mnu_abi::ProcessStatus {
                state: 99,
                ..original
            }),
            protocol::STATUS_EIO,
        ),
        (
            Ok(mnu_abi::ProcessStatus {
                state: mnu_abi::PROCESS_STATE_EXITED,
                ..original
            }),
            protocol::STATUS_ESRCH,
        ),
        (
            Ok(mnu_abi::ProcessStatus {
                image_revision: u64::MAX,
                ..original
            }),
            -13,
        ),
    ] {
        let (mut service, parent, child, mut processes) = family();
        processes.images.insert(91, observation);
        assert_eq!(
            request(
                &mut service,
                parent,
                child.process_id as i64,
                0,
                &mut processes
            ),
            error
        );
        assert_eq!(
            group(&mut service, parent, child.process_id),
            parent.process_id
        );
        assert_eq!(processes.image_reads, [91]);
    }
}

#[test]
fn a_freshly_loaded_child_is_past_exec_but_its_own_fork_child_is_not() {
    for broker in [false, true] {
        let parent = PeerIdentity {
            process_id: 2301,
            effective_uid: 0,
            effective_gid: 0,
        };
        let child = PeerIdentity {
            process_id: 2302,
            ..parent
        };
        let grandchild = PeerIdentity {
            process_id: 2303,
            ..parent
        };
        let mut service = service_for(parent);
        let mut filesystem = RecordingFilesystem::default();
        let executable = AuthenticatedProcess {
            handle: 92,
            process_id: child.process_id,
        };
        if broker {
            service
                .adopt_launched_child(
                    parent,
                    AuthenticatedProcess {
                        handle: 2301,
                        process_id: parent.process_id,
                    },
                    executable,
                    &mut filesystem,
                )
                .unwrap();
        } else {
            service
                .adopt_spawned_child(parent, executable, 0, 0, &[], &mut filesystem)
                .unwrap();
        }
        let mut processes = RecordingProcesses::default();
        for (handle, process_id) in [(92, child.process_id), (93, grandchild.process_id)] {
            processes.images.insert(
                handle,
                Ok(mnu_abi::ProcessStatus {
                    process_id,
                    state: mnu_abi::PROCESS_STATE_RUNNING,
                    ..Default::default()
                }),
            );
        }
        assert_eq!(
            request(
                &mut service,
                parent,
                child.process_id as i64,
                0,
                &mut processes
            ),
            -13
        );
        assert_eq!(
            group(&mut service, parent, child.process_id),
            parent.process_id
        );
        assert_eq!(request(&mut service, child, 0, 0, &mut processes), 0);
        service
            .adopt_child(
                child,
                AuthenticatedProcess {
                    handle: 93,
                    process_id: grandchild.process_id,
                },
                &mut filesystem,
            )
            .unwrap();
        assert_eq!(
            request(
                &mut service,
                child,
                grandchild.process_id as i64,
                0,
                &mut processes
            ),
            0
        );
        assert_eq!(
            group(&mut service, child, grandchild.process_id),
            grandchild.process_id
        );
    }
}

#[test]
fn invalid_targets_and_caller_supplied_objects_never_select_a_native_process() {
    let (mut service, parent, child, mut processes) = family();
    for (target, pgid, error) in [
        (-1, 0, STATUS_EINVAL),
        (999, 0, protocol::STATUS_ESRCH),
        (child.process_id as i64, -1, STATUS_EINVAL),
    ] {
        assert_eq!(
            request(&mut service, parent, target, pgid, &mut processes),
            error
        );
    }
    assert!(processes.image_reads.is_empty());
    let mut payload = [0; protocol::PROCESS_GROUP_REQUEST_LEN];
    protocol::encode_process_group_request(child.process_id as i64, 0, &mut payload).unwrap();
    let header = protocol::Header {
        opcode: protocol::OP_SET_PROCESS_GROUP,
        ..Default::default()
    };
    let response = service.handle_process_group_request(
        parent,
        header,
        &payload,
        &[AttachedObject {
            handle: 123,
            rights: u64::MAX,
        }],
        &mut processes,
    );
    assert_eq!(response.response.header.status, STATUS_EINVAL);
    for header in [
        protocol::Header { flags: 1, ..header },
        protocol::Header {
            status: 1,
            ..header
        },
    ] {
        let response =
            service.handle_process_group_request(parent, header, &payload, &[], &mut processes);
        assert_eq!(response.response.header.status, STATUS_EINVAL);
    }
    assert!(processes.image_reads.is_empty());
    // The backend-free policy handler must not bypass image observation.
    assert_eq!(
        service.handle(parent, header, &payload).header.status,
        protocol::STATUS_ENOSYS
    );
    let unavailable = service.handle_process_group_request(
        parent,
        header,
        &payload,
        &[],
        &mut NoImageObservation,
    );
    assert_eq!(unavailable.response.header.status, protocol::STATUS_ENOSYS);
    assert_eq!(
        group(&mut service, parent, child.process_id),
        parent.process_id
    );
}
