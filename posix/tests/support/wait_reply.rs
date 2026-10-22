use super::*;

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
