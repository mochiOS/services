use super::*;

#[test]
fn selected_child_usage_is_published_atomically_and_not_charged_on_reply_failure() {
    let (mut service, _, parent, child, mut fs, mut processes) = orphan_family();
    processes
        .states
        .insert(142, ProcessLifecycle::Exited { exit_code: 37 });
    processes.usage.insert(
        142,
        Ok(mnu_abi::ProcessExecutionUsage {
            user_ticks: 9,
            kernel_ticks: 4,
            ticks_per_second: 500,
            reserved: 0,
        }),
    );
    processes.memory_usage.insert(
        142,
        Ok(mnu_abi::ProcessMemoryUsage {
            current_bytes: 0,
            peak_bytes: 32768,
        }),
    );
    let request = protocol::WaitRequest {
        selector: child.process_id as i64,
        options: 0,
    };
    for accepted in [false, false, true] {
        let result = service
            .wait_child_usage_with_reply(parent, request, &mut fs, &mut processes, |info, usage| {
                assert_eq!(
                    (info.result.process_id, info.result.status, info.real_uid),
                    (child.process_id, 37 << 8, 505)
                );
                assert_eq!(
                    (
                        usage.cpu.user_ticks,
                        usage.cpu.kernel_ticks,
                        usage.cpu.ticks_per_second
                    ),
                    (9, 4, 500)
                );
                assert_eq!(usage.peak_resident_bytes, 32768);
                accepted
            })
            .unwrap();
        assert_eq!(result.is_some(), accepted);
        assert_eq!(
            service.waited_child_cpu_usage(parent).unwrap().user_ticks,
            if accepted { 9 } else { 0 }
        );
        assert_eq!(
            service
                .waited_child_usage(parent)
                .unwrap()
                .peak_resident_bytes,
            if accepted { 32768 } else { 0 }
        );
        assert_eq!(processes.released.len(), usize::from(accepted));
    }
    assert_eq!(
        service.wait_child_usage_with_reply(
            parent,
            request,
            &mut fs,
            &mut processes,
            |_, _| panic!("duplicate event")
        ),
        Err(protocol::STATUS_ECHILD)
    );
}

#[test]
fn usage_observation_failure_and_nowait_preserve_the_child_for_another_waiter() {
    let (mut service, _, parent, child, mut fs, mut processes) = orphan_family();
    processes
        .states
        .insert(142, ProcessLifecycle::Exited { exit_code: 17 });
    let request = protocol::WaitRequest {
        selector: child.process_id as i64,
        options: protocol::WAIT_NOWAIT,
    };
    for usage in [
        Err(protocol::STATUS_EIO),
        Ok(mnu_abi::ProcessExecutionUsage {
            ticks_per_second: 0,
            ..Default::default()
        }),
        Ok(mnu_abi::ProcessExecutionUsage {
            ticks_per_second: 500,
            reserved: 1,
            ..Default::default()
        }),
    ] {
        processes.usage.insert(142, usage);
        assert_eq!(
            service.wait_child_usage_with_reply(
                parent,
                request,
                &mut fs,
                &mut processes,
                |_, _| panic!("unavailable accounting")
            ),
            Err(protocol::STATUS_EIO)
        );
        assert!(service.session(child.process_id).is_some());
        assert!(processes.released.is_empty());
    }
    processes.usage.insert(
        142,
        Ok(mnu_abi::ProcessExecutionUsage {
            user_ticks: 11,
            kernel_ticks: 6,
            ticks_per_second: 500,
            reserved: 0,
        }),
    );
    for _ in 0..2 {
        service
            .wait_child_usage_with_reply(parent, request, &mut fs, &mut processes, |info, usage| {
                assert_eq!(info.result.status, 17 << 8);
                assert_eq!((usage.cpu.user_ticks, usage.cpu.kernel_ticks), (11, 6));
                true
            })
            .unwrap()
            .unwrap();
        assert!(processes.released.is_empty());
        assert_eq!(
            service.waited_child_cpu_usage(parent).unwrap().user_ticks,
            0
        );
    }
    let unrelated = PeerIdentity {
        process_id: 9999,
        ..parent
    };
    assert!(
        service
            .wait_child_usage_with_reply(
                unrelated,
                request,
                &mut fs,
                &mut processes,
                |_, _| panic!("foreign child")
            )
            .is_err()
    );
    service
        .wait_child(
            parent,
            protocol::WaitRequest {
                options: 0,
                ..request
            },
            &mut fs,
            &mut processes,
        )
        .unwrap();
    assert_eq!(
        service.waited_child_cpu_usage(parent).unwrap().user_ticks,
        11
    );
}

#[test]
fn selected_child_cpu_includes_only_descendants_it_actually_waited_for() {
    let (mut service, _, parent, child, mut fs, mut processes) = orphan_family();
    let grandchild = child.process_id + 1;
    service
        .adopt_spawned_child(
            child,
            AuthenticatedProcess {
                process_id: grandchild,
                handle: 143,
            },
            505,
            24,
            &[],
            &mut fs,
        )
        .unwrap();
    processes
        .states
        .insert(143, ProcessLifecycle::Exited { exit_code: 0 });
    processes.usage.insert(
        143,
        Ok(mnu_abi::ProcessExecutionUsage {
            user_ticks: 13,
            kernel_ticks: 7,
            ticks_per_second: 500,
            reserved: 0,
        }),
    );
    service
        .wait_child(
            child,
            protocol::WaitRequest {
                selector: grandchild as i64,
                options: 0,
            },
            &mut fs,
            &mut processes,
        )
        .unwrap();
    processes
        .states
        .insert(142, ProcessLifecycle::Exited { exit_code: 0 });
    processes.usage.insert(
        142,
        Ok(mnu_abi::ProcessExecutionUsage {
            user_ticks: 5,
            kernel_ticks: 3,
            ticks_per_second: 500,
            reserved: 0,
        }),
    );
    service
        .wait_child_usage_with_reply(
            parent,
            protocol::WaitRequest {
                selector: child.process_id as i64,
                options: 0,
            },
            &mut fs,
            &mut processes,
            |_, usage| {
                assert_eq!(
                    (
                        usage.cpu.user_ticks,
                        usage.cpu.kernel_ticks,
                        usage.cpu.ticks_per_second
                    ),
                    (18, 10, 500)
                );
                true
            },
        )
        .unwrap()
        .unwrap();
    assert_eq!(
        service.waited_child_cpu_usage(parent).unwrap().user_ticks,
        18
    );
}

#[test]
fn stopped_child_usage_failure_does_not_consume_the_event_and_nohang_needs_no_sample() {
    let (mut service, _, parent, child, mut fs, mut processes) = orphan_family();
    stop_job_member(&mut service, parent, child, &mut processes);
    let request = protocol::WaitRequest {
        selector: child.process_id as i64,
        options: protocol::WAIT_UNTRACED | protocol::WAIT_NOHANG,
    };
    processes.usage.insert(142, Err(protocol::STATUS_EIO));
    assert_eq!(
        service.wait_child_usage_with_reply(
            parent,
            request,
            &mut fs,
            &mut processes,
            |_, _| panic!("no sample")
        ),
        Err(protocol::STATUS_EIO)
    );
    processes.usage.insert(
        142,
        Ok(mnu_abi::ProcessExecutionUsage {
            user_ticks: 8,
            ticks_per_second: 500,
            ..Default::default()
        }),
    );
    service
        .wait_child_usage_with_reply(parent, request, &mut fs, &mut processes, |info, usage| {
            assert_eq!(info.result.status, (protocol::SIGNAL_STOP << 8) | 0x7f);
            assert_eq!(usage.cpu.user_ticks, 8);
            true
        })
        .unwrap()
        .unwrap();
    processes.usage.insert(142, Err(protocol::STATUS_EIO));
    service
        .wait_child_usage_with_reply(parent, request, &mut fs, &mut processes, |info, usage| {
            assert_eq!(info.result.process_id, 0);
            assert_eq!(usage, Default::default());
            true
        })
        .unwrap()
        .unwrap();
    assert!(processes.released.is_empty());
    assert_eq!(
        service.waited_child_cpu_usage(parent).unwrap().user_ticks,
        0
    );
}

#[test]
fn rejected_exit_reply_preserves_identity_handles_and_cpu_time_until_one_successful_reply() {
    let (mut service, _, parent, child, mut fs, mut processes) = orphan_family();
    processes
        .states
        .insert(142, ProcessLifecycle::Exited { exit_code: 37 });
    processes.usage.insert(
        142,
        Ok(mnu_abi::ProcessExecutionUsage {
            user_ticks: 9,
            kernel_ticks: 4,
            ticks_per_second: 500,
            reserved: 0,
        }),
    );
    let request = protocol::WaitRequest {
        selector: child.process_id as i64,
        options: 0,
    };
    for _ in 0..3 {
        assert_eq!(
            service.wait_child_info_with_reply(parent, request, &mut fs, &mut processes, |info| {
                assert_eq!(info.result.status, 37 << 8);
                assert_eq!(info.real_uid, 505);
                false
            }),
            Ok(None)
        );
        assert!(service.session(child.process_id).is_some());
        assert!(processes.released.is_empty());
        assert!(fs.released.is_empty());
        assert_eq!(
            service.waited_child_cpu_usage(parent).unwrap().user_ticks,
            0
        );
    }
    assert!(
        service
            .wait_child_info_with_reply(parent, request, &mut fs, &mut processes, |_| true)
            .unwrap()
            .is_some()
    );
    assert_eq!(processes.released, vec![142]);
    let cpu = service.waited_child_cpu_usage(parent).unwrap();
    assert_eq!((cpu.user_ticks, cpu.kernel_ticks), (9, 4));
    assert_eq!(
        service.wait_child_info_with_reply(parent, request, &mut fs, &mut processes, |_| panic!(
            "no second event"
        )),
        Err(protocol::STATUS_ECHILD)
    );
}

#[test]
fn rejected_stop_and_continue_replies_leave_the_exact_event_available() {
    let (mut service, _, parent, child, mut fs, mut processes) = orphan_family();
    stop_job_member(&mut service, parent, child, &mut processes);
    for (options, status) in [
        (protocol::WAIT_UNTRACED, (protocol::SIGNAL_STOP << 8) | 0x7f),
        (protocol::WAIT_CONTINUED, protocol::WAIT_STATUS_CONTINUED),
    ] {
        if options == protocol::WAIT_CONTINUED {
            send_signal(&mut service, parent, child, protocol::SIGNAL_CONT);
            service
                .apply_process_resume(child.process_id, &mut processes)
                .unwrap();
        }
        let request = protocol::WaitRequest {
            selector: child.process_id as i64,
            options: options | protocol::WAIT_NOHANG,
        };
        assert_eq!(
            service.wait_child_info_with_reply(parent, request, &mut fs, &mut processes, |info| {
                assert_eq!(info.result.status, status);
                false
            }),
            Ok(None)
        );
        assert_eq!(
            service
                .wait_child_info_with_reply(parent, request, &mut fs, &mut processes, |_| true)
                .unwrap()
                .unwrap()
                .result
                .status,
            status
        );
        assert_eq!(
            service
                .wait_child(parent, request, &mut fs, &mut processes)
                .unwrap()
                .process_id,
            0
        );
    }
}

#[test]
fn failed_exit_preparation_never_publishes_or_consumes_the_status() {
    let (mut service, _, parent, child, mut fs, mut processes) = orphan_family();
    processes
        .states
        .insert(142, ProcessLifecycle::Exited { exit_code: 37 });
    processes.usage.insert(142, Err(protocol::STATUS_EIO));
    let request = protocol::WaitRequest {
        selector: child.process_id as i64,
        options: 0,
    };
    assert_eq!(
        service.wait_child_info_with_reply(parent, request, &mut fs, &mut processes, |_| panic!(
            "failed preparation published"
        )),
        Err(protocol::STATUS_EIO)
    );
    assert!(processes.released.is_empty());
    // WNOWAIT still needs no accounting sample and never consumes even when published.
    let observed = protocol::WaitRequest {
        options: protocol::WAIT_NOWAIT,
        ..request
    };
    assert_eq!(
        service
            .wait_child_info_with_reply(parent, observed, &mut fs, &mut processes, |_| true)
            .unwrap()
            .unwrap()
            .result
            .status,
        37 << 8
    );
    assert!(processes.released.is_empty());
}

#[test]
fn child_memory_failure_preserves_event_and_history_until_a_valid_sample() {
    let (mut service, _, parent, child, mut fs, mut processes) = orphan_family();
    processes
        .states
        .insert(142, ProcessLifecycle::Exited { exit_code: 3 });
    let request = protocol::WaitRequest {
        selector: child.process_id as i64,
        options: 0,
    };
    for (sample, error) in [
        (Err(protocol::STATUS_EAGAIN), protocol::STATUS_EAGAIN),
        (
            Ok(mnu_abi::ProcessMemoryUsage {
                current_bytes: 8192,
                peak_bytes: 4096,
            }),
            protocol::STATUS_EIO,
        ),
    ] {
        processes.memory_usage.insert(142, sample);
        assert_eq!(
            service.wait_child_usage_with_reply(
                parent,
                request,
                &mut fs,
                &mut processes,
                |_, _| panic!("invalid sample published")
            ),
            Err(error)
        );
        assert!(service.is_child(parent.process_id, child.process_id));
        assert!(processes.released.is_empty());
        assert_eq!(
            service.waited_child_usage(parent).unwrap(),
            Default::default()
        );
    }
    processes.memory_usage.insert(
        142,
        Ok(mnu_abi::ProcessMemoryUsage {
            current_bytes: 0,
            peak_bytes: 65536,
        }),
    );
    for options in [protocol::WAIT_NOWAIT, protocol::WAIT_NOWAIT, 0] {
        service
            .wait_child_usage_with_reply(
                parent,
                protocol::WaitRequest { options, ..request },
                &mut fs,
                &mut processes,
                |_, usage| {
                    assert_eq!(usage.peak_resident_bytes, 65536);
                    true
                },
            )
            .unwrap()
            .unwrap();
        assert_eq!(
            service
                .waited_child_usage(parent)
                .unwrap()
                .peak_resident_bytes,
            if options == 0 { 65536 } else { 0 }
        );
    }
}

#[test]
fn waited_memory_is_the_largest_child_or_waited_descendant_not_a_sum() {
    let (mut service, init, parent, child, mut fs, mut processes) = orphan_family();
    for (owner, id, handle, peak) in [(child, 1403, 143, 65536), (parent, 1404, 144, 32768)] {
        service
            .adopt_child(
                owner,
                AuthenticatedProcess {
                    process_id: id,
                    handle,
                },
                &mut fs,
            )
            .unwrap();
        processes
            .states
            .insert(handle, ProcessLifecycle::Exited { exit_code: 0 });
        processes.memory_usage.insert(
            handle,
            Ok(mnu_abi::ProcessMemoryUsage {
                current_bytes: 0,
                peak_bytes: peak,
            }),
        );
        service
            .wait_child(
                owner,
                protocol::WaitRequest {
                    selector: id as i64,
                    options: 0,
                },
                &mut fs,
                &mut processes,
            )
            .unwrap();
    }
    assert_eq!(
        service
            .waited_child_usage(parent)
            .unwrap()
            .peak_resident_bytes,
        32768
    );
    processes
        .states
        .insert(142, ProcessLifecycle::Exited { exit_code: 0 });
    processes.memory_usage.insert(
        142,
        Ok(mnu_abi::ProcessMemoryUsage {
            current_bytes: 0,
            peak_bytes: 4096,
        }),
    );
    service
        .wait_child(
            parent,
            protocol::WaitRequest {
                selector: child.process_id as i64,
                options: 0,
            },
            &mut fs,
            &mut processes,
        )
        .unwrap();
    assert_eq!(
        service
            .waited_child_usage(parent)
            .unwrap()
            .peak_resident_bytes,
        65536
    );
    let header = protocol::Header {
        opcode: protocol::OP_WAITED_CHILD_USAGE,
        ..Default::default()
    };
    let response = service.handle(parent, header, &[]);
    assert_eq!(response.header.status, 0);
    assert_eq!(
        protocol::wait_usage::decode_usage(&response.payload)
            .unwrap()
            .peak_resident_bytes,
        65536
    );
    assert_eq!(
        protocol::wait_usage::decode_usage(&service.handle(init, header, &[]).payload).unwrap(),
        Default::default()
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
    assert_eq!(
        service
            .handle_objects(
                parent,
                header,
                &[],
                &[AttachedObject {
                    handle: 42,
                    rights: 16
                }],
                &mut fs
            )
            .response
            .header
            .status,
        STATUS_EINVAL
    );
}
