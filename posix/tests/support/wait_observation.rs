use super::*;

#[test]
fn observation_option_survives_guarded_wire_and_keeps_live_children_waitable() {
    let request = protocol::WaitRequest {
        selector: -1,
        options: protocol::WAIT_NOWAIT,
    };
    let mut bytes = [0; protocol::WAIT_GUARDED_REQUEST_LEN];
    protocol::encode_guarded_wait_request(request, 23, &mut bytes).unwrap();
    let (decoded, epoch) = protocol::decode_guarded_wait_request(&bytes).unwrap();
    assert_eq!(
        (decoded.selector, decoded.options, epoch),
        (-1, protocol::WAIT_NOWAIT, 23)
    );
    let (mut service, _, parent, child, mut fs, mut processes) = orphan_family();
    assert_eq!(
        wait(
            &mut service,
            parent,
            child,
            protocol::WAIT_NOWAIT,
            &mut fs,
            &mut processes
        ),
        Err(protocol::STATUS_EAGAIN)
    );
    assert_eq!(
        wait(
            &mut service,
            parent,
            child,
            protocol::WAIT_NOWAIT | protocol::WAIT_NOHANG,
            &mut fs,
            &mut processes
        )
        .unwrap()
        .process_id,
        0
    );
    assert!(service.session(child.process_id).is_some());
    assert!(!processes.released.contains(&142));
    assert_eq!(
        wait(
            &mut service,
            parent,
            child,
            1 << 31,
            &mut fs,
            &mut processes
        ),
        Err(STATUS_EINVAL)
    );
}

fn wait(
    service: &mut PosixService,
    parent: PeerIdentity,
    child: PeerIdentity,
    options: u32,
    fs: &mut RecordingFilesystem,
    processes: &mut RecordingProcesses,
) -> Result<protocol::WaitResult, i32> {
    service.wait_child(
        parent,
        protocol::WaitRequest {
            selector: child.process_id as i64,
            options,
        },
        fs,
        processes,
    )
}

#[test]
fn observing_exit_does_not_reap_close_or_charge_and_can_be_repeated() {
    let (mut service, init, parent, child, mut fs, mut processes) = orphan_family();
    processes
        .states
        .insert(142, ProcessLifecycle::Exited { exit_code: 37 });
    // Merely observing an exit must not need the accounting backend at all.
    processes.usage.insert(142, Err(-5));
    for _ in 0..3 {
        let result = wait(
            &mut service,
            parent,
            child,
            protocol::WAIT_NOWAIT,
            &mut fs,
            &mut processes,
        )
        .unwrap();
        assert_eq!(
            (result.process_id, result.status),
            (child.process_id, 37 << 8)
        );
        assert!(service.session(child.process_id).is_some());
        assert!(!processes.released.contains(&142));
        assert_eq!(
            service.waited_child_cpu_usage(parent).unwrap().user_ticks,
            0
        );
    }
    // An ancestor's authority or knowledge of the child id is not parenthood.
    assert_eq!(
        wait(
            &mut service,
            init,
            child,
            protocol::WAIT_NOWAIT,
            &mut fs,
            &mut processes
        ),
        Err(protocol::STATUS_ECHILD)
    );
    assert_eq!(
        wait(&mut service, parent, child, 0, &mut fs, &mut processes),
        Err(-5)
    );
    assert!(service.session(child.process_id).is_some());
    processes.usage.insert(
        142,
        Ok(mnu_abi::ProcessExecutionUsage {
            user_ticks: 9,
            kernel_ticks: 4,
            ticks_per_second: 500,
            reserved: 0,
        }),
    );
    assert_eq!(
        wait(&mut service, parent, child, 0, &mut fs, &mut processes)
            .unwrap()
            .status,
        37 << 8
    );
    assert!(service.session(child.process_id).is_none());
    assert_eq!(
        processes
            .released
            .iter()
            .filter(|handle| **handle == 142)
            .count(),
        1
    );
    assert_eq!(
        service.waited_child_cpu_usage(parent).unwrap().user_ticks,
        9
    );
    assert_eq!(
        wait(
            &mut service,
            parent,
            child,
            protocol::WAIT_NOWAIT,
            &mut fs,
            &mut processes
        ),
        Err(protocol::STATUS_ECHILD)
    );
}

#[test]
fn observing_stop_and_continue_does_not_consume_the_next_waitpid_event() {
    let (mut service, _, parent, child, mut fs, mut processes) = orphan_family();
    let delivery = deliver_signal(&mut service, parent, child, protocol::SIGNAL_STOP);
    let mut bytes = [0; protocol::SIGNAL_DELIVERY_LEN];
    protocol::encode_signal_delivery(delivery, &mut bytes).unwrap();
    service
        .report_process_stopped(child, &bytes, &mut processes)
        .unwrap();
    let stopped = protocol::WAIT_NOHANG | protocol::WAIT_UNTRACED;
    for _ in 0..3 {
        assert_eq!(
            wait(
                &mut service,
                parent,
                child,
                stopped | protocol::WAIT_NOWAIT,
                &mut fs,
                &mut processes
            )
            .unwrap()
            .status,
            (protocol::SIGNAL_STOP << 8) | 0x7f
        );
    }
    assert_ne!(
        wait(
            &mut service,
            parent,
            child,
            stopped,
            &mut fs,
            &mut processes
        )
        .unwrap()
        .process_id,
        0
    );
    assert_eq!(
        wait(
            &mut service,
            parent,
            child,
            stopped | protocol::WAIT_NOWAIT,
            &mut fs,
            &mut processes
        )
        .unwrap()
        .process_id,
        0
    );
    send_signal(&mut service, parent, child, protocol::SIGNAL_CONT);
    service
        .apply_process_resume(child.process_id, &mut processes)
        .unwrap();
    let continued = protocol::WAIT_NOHANG | protocol::WAIT_CONTINUED;
    for _ in 0..3 {
        assert_eq!(
            wait(
                &mut service,
                parent,
                child,
                continued | protocol::WAIT_NOWAIT,
                &mut fs,
                &mut processes
            )
            .unwrap()
            .status,
            protocol::WAIT_STATUS_CONTINUED
        );
    }
    assert_ne!(
        wait(
            &mut service,
            parent,
            child,
            continued,
            &mut fs,
            &mut processes
        )
        .unwrap()
        .process_id,
        0
    );
    assert_eq!(
        wait(
            &mut service,
            parent,
            child,
            continued | protocol::WAIT_NOWAIT,
            &mut fs,
            &mut processes
        )
        .unwrap()
        .process_id,
        0
    );
}
