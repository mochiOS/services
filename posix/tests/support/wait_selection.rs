use super::*;

fn selected_wait(
    service: &mut PosixService,
    parent: PeerIdentity,
    selector: i64,
    options: u32,
    fs: &mut RecordingFilesystem,
    processes: &mut RecordingProcesses,
) -> Result<protocol::WaitResult, i32> {
    service.wait_child(
        parent,
        protocol::WaitRequest {
            selector,
            options: options | protocol::WAIT_SELECT_EVENTS,
        },
        fs,
        processes,
    )
}

#[test]
fn explicit_wait_requires_an_event_kind_but_legacy_wait_still_selects_exit() {
    assert!(protocol::wait_options_valid(0));
    assert!(protocol::wait_selects_exit(0));
    for modifiers in [
        0,
        protocol::WAIT_NOHANG,
        protocol::WAIT_NOWAIT,
        protocol::WAIT_NOHANG | protocol::WAIT_NOWAIT,
    ] {
        assert!(!protocol::wait_options_valid(
            protocol::WAIT_SELECT_EVENTS | modifiers
        ));
        for event in [
            protocol::WAIT_EXITED,
            protocol::WAIT_UNTRACED,
            protocol::WAIT_CONTINUED,
        ] {
            let options = protocol::WAIT_SELECT_EVENTS | modifiers | event;
            assert!(protocol::wait_options_valid(options));
            assert_eq!(
                protocol::wait_selects_exit(options),
                event == protocol::WAIT_EXITED
            );
            let mut bytes = [0; protocol::WAIT_REQUEST_LEN];
            protocol::encode_wait_request(
                protocol::WaitRequest {
                    selector: -1,
                    options,
                },
                &mut bytes,
            )
            .unwrap();
            assert_eq!(
                protocol::decode_wait_request(&bytes).unwrap().options,
                options
            );
        }
    }
    let (mut service, _, parent, child, mut fs, mut processes) = orphan_family();
    assert_eq!(
        selected_wait(
            &mut service,
            parent,
            child.process_id as i64,
            protocol::WAIT_NOHANG,
            &mut fs,
            &mut processes
        ),
        Err(STATUS_EINVAL)
    );
}

#[test]
fn unselected_stops_and_continues_remain_available_to_a_later_wait() {
    let (mut service, _, parent, child, mut fs, mut processes) = orphan_family();
    let delivery = deliver_signal(&mut service, parent, child, protocol::SIGNAL_STOP);
    let mut bytes = [0; protocol::SIGNAL_DELIVERY_LEN];
    protocol::encode_signal_delivery(delivery, &mut bytes).unwrap();
    service
        .report_process_stopped(child, &bytes, &mut processes)
        .unwrap();
    for _ in 0..2 {
        assert_eq!(
            selected_wait(
                &mut service,
                parent,
                child.process_id as i64,
                protocol::WAIT_EXITED | protocol::WAIT_NOHANG,
                &mut fs,
                &mut processes
            )
            .unwrap()
            .process_id,
            0
        );
    }
    let stopped = selected_wait(
        &mut service,
        parent,
        child.process_id as i64,
        protocol::WAIT_UNTRACED,
        &mut fs,
        &mut processes,
    )
    .unwrap();
    assert_eq!(stopped.status, (protocol::SIGNAL_STOP << 8) | 0x7f);
    send_signal(&mut service, parent, child, protocol::SIGNAL_CONT);
    service
        .apply_process_resume(child.process_id, &mut processes)
        .unwrap();
    assert_eq!(
        selected_wait(
            &mut service,
            parent,
            child.process_id as i64,
            protocol::WAIT_EXITED | protocol::WAIT_NOHANG,
            &mut fs,
            &mut processes
        )
        .unwrap()
        .process_id,
        0
    );
    assert_eq!(
        selected_wait(
            &mut service,
            parent,
            child.process_id as i64,
            protocol::WAIT_CONTINUED,
            &mut fs,
            &mut processes
        )
        .unwrap()
        .status,
        protocol::WAIT_STATUS_CONTINUED
    );
}

#[test]
fn an_exit_cannot_satisfy_a_stop_wait_and_is_not_reaped_by_it() {
    let (mut service, _, parent, child, mut fs, mut processes) = orphan_family();
    processes
        .states
        .insert(142, ProcessLifecycle::Exited { exit_code: 37 });
    for options in [
        protocol::WAIT_UNTRACED,
        protocol::WAIT_CONTINUED | protocol::WAIT_NOHANG,
    ] {
        assert_eq!(
            selected_wait(
                &mut service,
                parent,
                child.process_id as i64,
                options,
                &mut fs,
                &mut processes
            ),
            Err(protocol::STATUS_ECHILD)
        );
        assert!(service.session(child.process_id).is_some());
        assert!(!processes.released.contains(&142));
        assert_eq!(
            service.waited_child_cpu_usage(parent).unwrap().user_ticks,
            0
        );
        assert!(
            service
                .wait_handles(
                    parent,
                    protocol::WaitRequest {
                        selector: -1,
                        options: protocol::WAIT_SELECT_EVENTS | options
                    }
                )
                .unwrap()
                .is_empty()
        );
    }
    assert_eq!(
        selected_wait(
            &mut service,
            parent,
            child.process_id as i64,
            protocol::WAIT_EXITED | protocol::WAIT_NOWAIT,
            &mut fs,
            &mut processes
        )
        .unwrap()
        .status,
        37 << 8
    );
    // Existing waitpid semantics still reap this same exit with options zero.
    assert_eq!(
        service
            .wait_child(
                parent,
                protocol::WaitRequest {
                    selector: -1,
                    options: 0
                },
                &mut fs,
                &mut processes
            )
            .unwrap()
            .process_id,
        child.process_id
    );
}

#[test]
fn an_unselected_exit_does_not_hide_a_live_sibling_or_keep_its_handle_ready() {
    let (mut service, init, parent, child, mut fs, mut processes) = orphan_family();
    let sibling = PeerIdentity {
        process_id: child.process_id + 1,
        ..child
    };
    service
        .adopt_launched_child(
            init,
            AuthenticatedProcess {
                handle: 141,
                process_id: parent.process_id,
            },
            AuthenticatedProcess {
                handle: 143,
                process_id: sibling.process_id,
            },
            &mut fs,
        )
        .unwrap();
    processes
        .states
        .insert(142, ProcessLifecycle::Exited { exit_code: 37 });
    processes.states.insert(143, ProcessLifecycle::Running);
    assert_eq!(
        selected_wait(
            &mut service,
            parent,
            -1,
            protocol::WAIT_UNTRACED,
            &mut fs,
            &mut processes
        ),
        Err(protocol::STATUS_EAGAIN)
    );
    assert_eq!(
        service
            .wait_handles(
                parent,
                protocol::WaitRequest {
                    selector: -1,
                    options: protocol::WAIT_SELECT_EVENTS | protocol::WAIT_UNTRACED
                }
            )
            .unwrap(),
        vec![143]
    );
    let delivery = deliver_signal(&mut service, parent, sibling, protocol::SIGNAL_STOP);
    let mut bytes = [0; protocol::SIGNAL_DELIVERY_LEN];
    protocol::encode_signal_delivery(delivery, &mut bytes).unwrap();
    service
        .report_process_stopped(sibling, &bytes, &mut processes)
        .unwrap();
    assert_eq!(
        selected_wait(
            &mut service,
            parent,
            -1,
            protocol::WAIT_UNTRACED | protocol::WAIT_NOWAIT,
            &mut fs,
            &mut processes
        )
        .unwrap()
        .process_id,
        sibling.process_id
    );
    assert!(service.session(child.process_id).is_some());
}
