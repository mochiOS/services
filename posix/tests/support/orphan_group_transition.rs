use super::*;

fn child(
    service: &mut PosixService,
    filesystem: &mut RecordingFilesystem,
    parent: PeerIdentity,
    process_id: u64,
) -> PeerIdentity {
    let child = PeerIdentity {
        process_id,
        ..parent
    };
    service
        .adopt_child(
            parent,
            AuthenticatedProcess {
                handle: process_id as u32,
                process_id,
            },
            filesystem,
        )
        .unwrap();
    child
}

fn session(service: &mut PosixService, caller: PeerIdentity) -> i32 {
    service
        .handle(
            caller,
            protocol::Header {
                opcode: protocol::OP_CREATE_SESSION,
                ..Default::default()
            },
            &[],
        )
        .header
        .status
}

fn group(service: &mut PosixService, caller: PeerIdentity, group: u64) -> i32 {
    let mut request = [0; protocol::PROCESS_GROUP_REQUEST_LEN];
    protocol::encode_process_group_request(0, group as i64, &mut request).unwrap();
    service
        .handle(
            caller,
            protocol::Header {
                opcode: protocol::OP_SET_PROCESS_GROUP,
                ..Default::default()
            },
            &request,
        )
        .header
        .status
}

#[test]
fn setsid_hangs_up_and_continues_a_newly_orphaned_stopped_child_job_once() {
    for stopped in [false, true] {
        let (mut service, [_, _, first, second, parent], mut filesystem, mut processes) =
            orphan_job_family();
        let job = child(&mut service, &mut filesystem, parent, 4110);
        processes.states.insert(4110, ProcessLifecycle::Running);
        set_own_job_group(&mut service, job);
        if stopped {
            stop_job_member(&mut service, parent, job, &mut processes);
        }
        assert_eq!(session(&mut service, parent), 0);
        assert_eq!(service.parent_id(job.process_id), Some(parent.process_id));
        if stopped {
            consume_job_hangup_and_continue(&mut service, job);
            assert!(
                service
                    .process_resume_notification_processes()
                    .any(|pid| pid == job.process_id)
            );
        }
        assert_eq!(service.signal_state(job.process_id).unwrap().pending(), 0);
        // Rejected or no-op transitions cannot send another notification.
        assert_eq!(session(&mut service, parent), protocol::STATUS_EPERM);
        assert_eq!(group(&mut service, job, job.process_id), 0);
        assert_eq!(service.signal_state(job.process_id).unwrap().pending(), 0);
        for unaffected in [first, second] {
            assert_eq!(
                service
                    .signal_state(unaffected.process_id)
                    .unwrap()
                    .pending(),
                0
            );
        }
    }
}

#[test]
fn setpgid_notifies_every_live_member_when_the_last_outside_parent_link_disappears() {
    let (mut service, [_, leader, _, sibling, outside], mut filesystem, mut processes) =
        orphan_job_family();
    let parent = child(&mut service, &mut filesystem, outside, 4111);
    let job = child(&mut service, &mut filesystem, parent, 4112);
    for process in [parent, job] {
        processes
            .states
            .insert(process.process_id as u32, ProcessLifecycle::Running);
    }
    // Leave parent and job in the original session while the grandparent
    // creates a different session. It no longer connects their job control.
    assert_eq!(group(&mut service, outside, leader.process_id), 0);
    assert_eq!(session(&mut service, outside), 0);
    set_own_job_group(&mut service, job);
    stop_job_member(&mut service, parent, job, &mut processes);
    assert_eq!(
        group(&mut service, parent, u64::MAX >> 1),
        protocol::STATUS_EPERM
    );
    assert_eq!(service.signal_state(job.process_id).unwrap().pending(), 0);
    // Joining the child's group removes its final same-session external
    // parent. The running parent must receive both signals as well.
    assert_eq!(group(&mut service, parent, job.process_id), 0);
    for member in [parent, job] {
        consume_job_hangup_and_continue(&mut service, member);
        assert_eq!(
            service.signal_state(member.process_id).unwrap().pending()
                & !(1 << (protocol::SIGNAL_CHLD - 1)),
            0
        );
    }
    assert_eq!(group(&mut service, parent, job.process_id), 0);
    assert_eq!(service.signal_state(job.process_id).unwrap().pending(), 0);
    assert_eq!(
        service.signal_state(parent.process_id).unwrap().pending()
            & !(1 << (protocol::SIGNAL_CHLD - 1)),
        0
    );
    assert_eq!(
        service.signal_state(sibling.process_id).unwrap().pending(),
        0
    );
}
