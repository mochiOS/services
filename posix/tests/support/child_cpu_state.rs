use super::*;
use posix_service::WaitedChildCpuUsage;

#[test]
fn wire_queries_only_the_authenticated_callers_history_and_rejects_extra_authority() {
    let (mut service, init, parent, child, mut fs, mut processes) = orphan_family();
    processes
        .states
        .insert(142, ProcessLifecycle::Exited { exit_code: 0 });
    processes.usage.insert(142, Ok(sample(9, 4)));
    wait(
        &mut service,
        parent,
        child.process_id,
        &mut fs,
        &mut processes,
    )
    .unwrap();
    let header = protocol::Header {
        opcode: protocol::OP_WAITED_CHILD_CPU_USAGE,
        ..Default::default()
    };
    let reply = service.handle(parent, header, &[]);
    assert_eq!(reply.header.status, 0);
    assert_eq!(
        protocol::decode_waited_child_cpu_usage(&reply.payload)
            .unwrap()
            .user_ticks,
        9
    );
    let other = service.handle(init, header, &[]);
    assert_eq!(
        protocol::decode_waited_child_cpu_usage(&other.payload)
            .unwrap()
            .user_ticks,
        0
    );
    assert_eq!(
        service
            .handle(parent, header, &parent.process_id.to_le_bytes())
            .header
            .status,
        STATUS_EINVAL
    );
    assert_eq!(
        service
            .handle(parent, protocol::Header { flags: 1, ..header }, &[])
            .header
            .status,
        STATUS_EINVAL
    );
    assert_eq!(
        service
            .handle(
                PeerIdentity {
                    process_id: 9999,
                    ..parent
                },
                header,
                &[]
            )
            .header
            .status,
        protocol::STATUS_ESRCH
    );
    let reply = service.handle_objects(
        parent,
        header,
        &[],
        &[AttachedObject {
            handle: 42,
            rights: 16,
        }],
        &mut fs,
    );
    assert_eq!(reply.response.header.status, STATUS_EINVAL);
}

fn sample(user_ticks: u64, kernel_ticks: u64) -> mnu_abi::ProcessExecutionUsage {
    mnu_abi::ProcessExecutionUsage {
        user_ticks,
        kernel_ticks,
        ticks_per_second: 500,
        reserved: 0,
    }
}

fn wait(
    service: &mut PosixService,
    parent: PeerIdentity,
    child: u64,
    filesystem: &mut RecordingFilesystem,
    processes: &mut RecordingProcesses,
) -> Result<protocol::WaitResult, i32> {
    service.wait_child(
        parent,
        protocol::WaitRequest {
            selector: child as i64,
            options: 0,
        },
        filesystem,
        processes,
    )
}

#[test]
fn charges_only_successful_exit_wait_once_and_not_live_nohang_queries() {
    let (mut service, _, parent, child, mut fs, mut processes) = orphan_family();
    processes.usage.insert(142, Ok(sample(9, 4)));
    let nohang = service
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
    assert_eq!(nohang.process_id, 0);
    assert_eq!(
        service.waited_child_cpu_usage(parent).unwrap(),
        WaitedChildCpuUsage::default()
    );
    processes
        .states
        .insert(142, ProcessLifecycle::Exited { exit_code: 7 });
    assert_eq!(
        service.waited_child_cpu_usage(parent).unwrap().user_ticks,
        0
    );
    assert_eq!(
        wait(
            &mut service,
            parent,
            child.process_id,
            &mut fs,
            &mut processes
        )
        .unwrap()
        .status,
        7 << 8
    );
    let accounted = WaitedChildCpuUsage {
        user_ticks: 9,
        kernel_ticks: 4,
        ticks_per_second: 500,
    };
    assert_eq!(service.waited_child_cpu_usage(parent).unwrap(), accounted);
    assert_eq!(
        wait(
            &mut service,
            parent,
            child.process_id,
            &mut fs,
            &mut processes
        ),
        Err(protocol::STATUS_ECHILD)
    );
    assert_eq!(service.waited_child_cpu_usage(parent).unwrap(), accounted);
    assert_eq!(processes.released, vec![142]);
}

#[test]
fn failed_or_invalid_native_samples_preserve_waitability_and_previous_time() {
    let (mut service, _, parent, child, mut fs, mut processes) = orphan_family();
    processes
        .states
        .insert(142, ProcessLifecycle::Exited { exit_code: 3 });
    for (usage, expected) in [
        (Err(-13), -13),
        (
            Ok(mnu_abi::ProcessExecutionUsage {
                ticks_per_second: 0,
                ..sample(9, 4)
            }),
            -5,
        ),
        (
            Ok(mnu_abi::ProcessExecutionUsage {
                reserved: 1,
                ..sample(9, 4)
            }),
            -5,
        ),
    ] {
        processes.usage.insert(142, usage);
        assert_eq!(
            wait(
                &mut service,
                parent,
                child.process_id,
                &mut fs,
                &mut processes
            ),
            Err(expected)
        );
        assert!(service.is_child(parent.process_id, child.process_id));
        assert_eq!(
            service.waited_child_cpu_usage(parent).unwrap(),
            WaitedChildCpuUsage::default()
        );
        assert!(processes.released.is_empty());
    }
    processes.usage.insert(142, Ok(sample(9, 4)));
    wait(
        &mut service,
        parent,
        child.process_id,
        &mut fs,
        &mut processes,
    )
    .unwrap();
    assert_eq!(
        service.waited_child_cpu_usage(parent).unwrap().user_ticks,
        9
    );
}

#[test]
fn includes_only_descendants_which_the_child_itself_waited_for() {
    for child_waited in [false, true] {
        let (mut service, _, parent, child, mut fs, mut processes) = orphan_family();
        service
            .adopt_child(
                child,
                AuthenticatedProcess {
                    process_id: 1403,
                    handle: 143,
                },
                &mut fs,
            )
            .unwrap();
        processes
            .states
            .insert(143, ProcessLifecycle::Exited { exit_code: 0 });
        processes.usage.insert(143, Ok(sample(2, 3)));
        if child_waited {
            wait(&mut service, child, 1403, &mut fs, &mut processes).unwrap();
        }
        processes
            .states
            .insert(142, ProcessLifecycle::Exited { exit_code: 0 });
        processes.usage.insert(142, Ok(sample(7, 11)));
        wait(
            &mut service,
            parent,
            child.process_id,
            &mut fs,
            &mut processes,
        )
        .unwrap();
        let usage = service.waited_child_cpu_usage(parent).unwrap();
        assert_eq!(
            (usage.user_ticks, usage.kernel_ticks),
            if child_waited { (9, 14) } else { (7, 11) }
        );
    }
}

#[test]
fn explicit_ignore_and_no_cld_wait_cleanup_do_not_charge_unwaited_children() {
    for (kind, options) in [
        (protocol::SIGNAL_DISPOSITION_IGNORE, 0),
        (
            protocol::SIGNAL_DISPOSITION_CAUGHT,
            protocol::SIGNAL_CHILD_OPTION_NOCLDWAIT,
        ),
    ] {
        let (mut service, _, parent, child, mut fs, mut processes) = orphan_family();
        set_child_signal_policy(&mut service, parent, kind, options);
        processes
            .states
            .insert(142, ProcessLifecycle::Exited { exit_code: 0 });
        processes.usage.insert(142, Ok(sample(99, 77)));
        service
            .reap_discarded_children(&mut fs, &mut processes)
            .unwrap();
        assert_eq!(
            wait(
                &mut service,
                parent,
                child.process_id,
                &mut fs,
                &mut processes
            ),
            Err(protocol::STATUS_ECHILD)
        );
        assert_eq!(
            service.waited_child_cpu_usage(parent).unwrap(),
            WaitedChildCpuUsage::default()
        );
    }
}

#[test]
fn fork_starts_an_empty_accumulator_and_exec_preserves_the_callers_history() {
    let (mut service, _, parent, child, mut fs, mut processes) = orphan_family();
    processes
        .states
        .insert(142, ProcessLifecycle::Exited { exit_code: 0 });
    processes.usage.insert(142, Ok(sample(9, 4)));
    wait(
        &mut service,
        parent,
        child.process_id,
        &mut fs,
        &mut processes,
    )
    .unwrap();
    let history = service.waited_child_cpu_usage(parent).unwrap();
    service
        .adopt_child(
            parent,
            AuthenticatedProcess {
                process_id: 1404,
                handle: 144,
            },
            &mut fs,
        )
        .unwrap();
    assert_eq!(
        service
            .waited_child_cpu_usage(PeerIdentity {
                process_id: 1404,
                ..parent
            })
            .unwrap(),
        WaitedChildCpuUsage::default()
    );
    let response = service.handle_thread_signal_request(
        parent,
        mnu_abi::ExecutionIdentity {
            process_id: parent.process_id,
            thread_id: 77,
        },
        protocol::Header {
            opcode: protocol::OP_SIGNAL_IMAGE_STARTED,
            ..Default::default()
        },
        &[],
    );
    assert_eq!(response.header.status, 0);
    assert_eq!(service.waited_child_cpu_usage(parent).unwrap(), history);
}
