use super::*;
use posix_service::process_timer::{
    Clock, MAX_OVERRUN, MAX_TIMERS_PER_PROCESS, Notification, Samples,
};

fn sample(now: u128) -> Samples {
    Samples {
        monotonic_ns: now,
        realtime_ns: now.min(i128::MAX as u128) as i128,
        process_cpu_ns: now,
        thread_cpu_ns: 0,
    }
}

fn peer() -> PeerIdentity {
    PeerIdentity {
        process_id: 2801,
        effective_uid: 501,
        effective_gid: 20,
    }
}

#[test]
fn process_owned_timer_ids_do_not_grant_cross_process_or_root_access() {
    let (mut service, root, parent, child, _, _) = orphan_family();
    let id = service
        .process_timers(parent)
        .unwrap()
        .create(Clock::Monotonic, Notification::Default)
        .unwrap();
    for other in [root, child] {
        let mut timers = service.process_timers(other).unwrap();
        assert_eq!(timers.clock(id), Err(STATUS_EINVAL));
        assert_eq!(timers.delete(id), Err(STATUS_EINVAL));
        assert_eq!(timers.set(id, sample(0), 1, 1, false), Err(STATUS_EINVAL));
    }
    let mut timers = service.process_timers(parent).unwrap();
    assert_eq!(timers.clock(id), Ok(Clock::Monotonic));
    timers.set(id, sample(0), 1, 0, false).unwrap();
    let event = timers.observe(id, sample(1)).unwrap().unwrap();
    assert_eq!(
        event.notification,
        Notification::Signal {
            signal: protocol::SIGNAL_ALRM,
            value: id.raw(),
        }
    );
    // A token selected for the parent's timer does not authorize its UID-zero
    // neighbor, even if public metadata is altered to name that neighbor.
    let mut root_timers = service.process_timers(root).unwrap();
    assert_eq!(root_timers.accept(event, sample(1)), Err(STATUS_EINVAL));
    let root_id = root_timers
        .create(Clock::Monotonic, Notification::Default)
        .unwrap();
    root_timers.set(root_id, sample(0), 1, 0, false).unwrap();
    let root_event = root_timers.observe(root_id, sample(1)).unwrap().unwrap();
    let mut altered = event;
    altered.timer = root_id;
    altered.notification = root_event.notification;
    assert_eq!(
        root_timers.accept(altered, sample(u128::MAX)),
        Err(protocol::STATUS_EAGAIN)
    );
    assert_eq!(
        root_timers.observe(root_id, sample(1)),
        Ok(Some(root_event))
    );
    let unknown = PeerIdentity {
        process_id: 9999,
        ..root
    };
    assert_eq!(
        service.process_timers(unknown).err(),
        Some(protocol::STATUS_ESRCH)
    );
}

#[test]
fn admission_is_bounded_and_reused_storage_never_reuses_timer_identity() {
    let peer = peer();
    let mut service = service_for(peer);
    let mut timers = service.process_timers(peer).unwrap();
    for notification in [
        Notification::Signal {
            signal: 0,
            value: 0,
        },
        Notification::Signal {
            signal: protocol::SIGNAL_MAX + 1,
            value: 0,
        },
        Notification::Thread { cookie: 0 },
    ] {
        assert_eq!(
            timers.create(Clock::Realtime, notification),
            Err(STATUS_EINVAL)
        );
    }
    let mut ids = Vec::new();
    for _ in 0..MAX_TIMERS_PER_PROCESS {
        ids.push(timers.create(Clock::Realtime, Notification::None).unwrap());
    }
    assert_eq!(
        timers.create(Clock::Realtime, Notification::None),
        Err(protocol::STATUS_EAGAIN)
    );
    let retired = ids[0];
    timers.delete(retired).unwrap();
    let replacement = timers.create(Clock::Realtime, Notification::None).unwrap();
    assert!(replacement.raw() > ids.last().unwrap().raw());
    assert_eq!(timers.clock(retired), Err(STATUS_EINVAL));
    assert_eq!(timers.clock(replacement), Ok(Clock::Realtime));
}

#[test]
fn pending_notification_coalesces_expirations_and_accept_latches_current_overrun() {
    let peer = peer();
    let mut service = service_for(peer);
    let mut timers = service.process_timers(peer).unwrap();
    let id = timers
        .create(Clock::Monotonic, Notification::Default)
        .unwrap();
    timers.set(id, sample(100), 10, 10, false).unwrap();
    assert_eq!(timers.observe(id, sample(109)), Ok(None));
    let selected = timers.observe(id, sample(110)).unwrap().unwrap();
    assert_eq!(selected.overrun(), 0);
    let updated = timers.observe(id, sample(150)).unwrap().unwrap();
    assert_eq!(updated.overrun(), 4);
    assert_eq!(timers.overrun(id), Ok(0));
    assert_eq!(timers.accept(selected, sample(159)).unwrap().overrun(), 4);
    assert_eq!(timers.overrun(id), Ok(4));
    let next = timers.observe(id, sample(160)).unwrap().unwrap();
    assert_ne!(next, selected);
    assert_eq!(
        timers.accept(selected, sample(u128::MAX)),
        Err(protocol::STATUS_EAGAIN)
    );
    assert_eq!(timers.observe(id, sample(160)), Ok(Some(next)));
    assert_eq!(timers.accept(next, sample(160)).unwrap().overrun(), 0);
    assert_eq!(timers.overrun(id), Ok(0));
}

#[test]
fn equal_signals_and_callback_cookies_keep_independent_pending_events() {
    let peer = peer();
    let mut service = service_for(peer);
    let mut timers = service.process_timers(peer).unwrap();
    let notifications = [
        Notification::Signal {
            signal: protocol::SIGNAL_ALRM,
            value: 17,
        },
        Notification::Signal {
            signal: protocol::SIGNAL_ALRM,
            value: 18,
        },
        Notification::Thread { cookie: 0xa5 },
    ];
    let mut selected = Vec::new();
    for notification in notifications {
        let id = timers.create(Clock::ProcessCpu, notification).unwrap();
        timers.set(id, sample(0), 1, 0, false).unwrap();
        let pending = timers.observe(id, sample(1)).unwrap().unwrap();
        assert_eq!(pending.notification, notification);
        selected.push(pending);
    }
    for pending in selected.into_iter().rev() {
        assert_eq!(
            timers.accept(pending, sample(1)).unwrap().notification,
            pending.notification
        );
    }
}

#[test]
fn acceptance_observes_expirations_since_the_last_reactor_sample() {
    let peer = peer();
    let mut service = service_for(peer);
    let mut timers = service.process_timers(peer).unwrap();
    let id = timers
        .create(Clock::Monotonic, Notification::Default)
        .unwrap();
    timers.set(id, sample(0), 10, 10, false).unwrap();
    let selected = timers.observe(id, sample(10)).unwrap().unwrap();
    // No reactor observation between 10 and delivery at 79.
    assert_eq!(timers.accept(selected, sample(79)).unwrap().overrun(), 6);
    assert_eq!(timers.overrun(id), Ok(6));
    assert_eq!(timers.value(id, sample(79)).unwrap().remaining_ns, 1);
    assert_eq!(timers.observe(id, sample(79)), Ok(None));
}

#[test]
fn reset_discard_and_failed_replacement_do_not_consume_wrong_notifications() {
    let peer = peer();
    let mut service = service_for(peer);
    let mut timers = service.process_timers(peer).unwrap();
    let id = timers
        .create(Clock::Monotonic, Notification::Default)
        .unwrap();
    timers.set(id, sample(0), 10, 10, false).unwrap();
    let old = timers.observe(id, sample(50)).unwrap().unwrap();
    assert_eq!(old.overrun(), 4);
    assert_eq!(
        timers.set(id, sample(u128::MAX), 1, 0, false),
        Err(posix_service::STATUS_EOVERFLOW)
    );
    assert_eq!(timers.observe(id, sample(50)), Ok(Some(old)));
    assert_eq!(timers.accept(old, sample(50)).unwrap().overrun(), 4);
    let pending = timers.observe(id, sample(60)).unwrap().unwrap();
    timers.set(id, sample(60), 1, 0, false).unwrap();
    let replacement = timers.observe(id, sample(61)).unwrap().unwrap();
    assert_eq!(
        timers.discard(pending, sample(u128::MAX)),
        Err(protocol::STATUS_EAGAIN)
    );
    timers.discard(replacement, sample(61)).unwrap();
    assert_eq!(timers.overrun(id), Ok(4));
    timers.set(id, sample(61), 1, 0, false).unwrap();
    let deleted = timers.observe(id, sample(62)).unwrap().unwrap();
    timers.delete(id).unwrap();
    assert_eq!(timers.accept(deleted, sample(62)), Err(STATUS_EINVAL));
}

#[test]
fn no_notification_disarms_cleanly_and_overruns_saturate_only_at_public_boundary() {
    let peer = peer();
    let mut service = service_for(peer);
    let mut timers = service.process_timers(peer).unwrap();
    let none = timers.create(Clock::Realtime, Notification::None).unwrap();
    timers.set(none, sample(0), 1, 1, false).unwrap();
    assert_eq!(timers.observe(none, sample(100)), Ok(None));
    assert_eq!(timers.value(none, sample(100)).unwrap().remaining_ns, 1);
    timers.set(none, sample(100), 0, 7, true).unwrap();
    let value = timers.value(none, sample(u128::MAX)).unwrap();
    assert_eq!((value.remaining_ns, value.interval_ns), (0, 7));
    assert_eq!(timers.overrun(none), Ok(0));
    let id = timers
        .create(Clock::Monotonic, Notification::Default)
        .unwrap();
    timers.set(id, sample(0), 1, 1, false).unwrap();
    let selected = timers.observe(id, sample(u128::MAX)).unwrap().unwrap();
    assert_eq!(selected.overrun(), MAX_OVERRUN);
    assert_eq!(
        timers
            .accept(selected, sample(u128::MAX))
            .unwrap()
            .overrun(),
        MAX_OVERRUN
    );
    assert_eq!(timers.overrun(id), Ok(MAX_OVERRUN));
}

#[test]
fn relative_realtime_uses_monotonic_but_absolute_realtime_tracks_clock_adjustment() {
    let peer = peer();
    let mut service = service_for(peer);
    let mut timers = service.process_timers(peer).unwrap();
    let id = timers.create(Clock::Realtime, Notification::None).unwrap();
    let mut clocks = Samples {
        realtime_ns: 1_000,
        monotonic_ns: 10,
        process_cpu_ns: 2,
        thread_cpu_ns: 0,
    };
    timers.set(id, clocks, 20, 0, false).unwrap();
    clocks.realtime_ns = 50_000;
    clocks.monotonic_ns = 15;
    assert_eq!(timers.value(id, clocks).unwrap().remaining_ns, 15);
    let previous = timers.set(id, clocks, 50_020, 0, true).unwrap();
    assert_eq!(previous.remaining_ns, 15); // Old value uses its old clock.
    assert_eq!(timers.value(id, clocks).unwrap().remaining_ns, 20);
    clocks.realtime_ns = 49_900;
    clocks.monotonic_ns = 20;
    assert_eq!(timers.value(id, clocks).unwrap().remaining_ns, 120);
    let previous = timers.set(id, clocks, 7, 0, false).unwrap();
    assert_eq!(previous.remaining_ns, 120);
    clocks.realtime_ns = -50_000;
    clocks.monotonic_ns = 21;
    assert_eq!(timers.value(id, clocks).unwrap().remaining_ns, 6);
    let cpu = timers
        .create(Clock::ProcessCpu, Notification::None)
        .unwrap();
    timers.set(cpu, clocks, 5, 0, false).unwrap();
    clocks.realtime_ns = i128::MAX;
    clocks.monotonic_ns = u128::MAX;
    clocks.process_cpu_ns = 3;
    assert_eq!(timers.value(cpu, clocks).unwrap().remaining_ns, 4);
}

#[test]
fn absolute_realtime_handles_pre_epoch_clocks_without_treating_epoch_zero_as_armed() {
    let peer = peer();
    let mut service = service_for(peer);
    let mut timers = service.process_timers(peer).unwrap();
    let id = timers
        .create(Clock::Realtime, Notification::Default)
        .unwrap();
    let mut clocks = Samples {
        realtime_ns: -50,
        monotonic_ns: 0,
        process_cpu_ns: 0,
        thread_cpu_ns: 0,
    };
    timers.set(id, clocks, 50, 0, true).unwrap();
    assert_eq!(timers.value(id, clocks).unwrap().remaining_ns, 100);
    clocks.realtime_ns = -10;
    assert_eq!(timers.value(id, clocks).unwrap().remaining_ns, 60);
    clocks.realtime_ns = 50;
    let pending = timers.observe(id, clocks).unwrap().unwrap();
    timers.accept(pending, clocks).unwrap();
    clocks.realtime_ns = -100;
    timers.set(id, clocks, 0, 7, true).unwrap();
    clocks.realtime_ns = i128::MAX;
    assert_eq!(timers.observe(id, clocks), Ok(None));
    let value = timers.value(id, clocks).unwrap();
    assert_eq!((value.remaining_ns, value.interval_ns), (0, 7));
}

#[test]
fn fork_does_not_copy_timers_and_only_native_exec_commit_deletes_them() {
    let parent = peer();
    let mut service = service_for(parent).with_monotonic_clock(|| Ok(0));
    let mut filesystem = RecordingFilesystem::default();
    let reply = service.handle(
        parent,
        protocol::Header {
            opcode: protocol::OP_ALARM,
            ..Default::default()
        },
        &1u32.to_le_bytes(),
    );
    assert_eq!(reply.header.status, 0);
    let id = service
        .process_timers(parent)
        .unwrap()
        .create(Clock::Monotonic, Notification::Default)
        .unwrap();
    let child = PeerIdentity {
        process_id: 2802,
        ..parent
    };
    service
        .adopt_child(
            parent,
            AuthenticatedProcess {
                process_id: child.process_id,
                handle: child.process_id as u32,
            },
            &mut filesystem,
        )
        .unwrap();
    assert_eq!(
        service.process_timers(child).unwrap().clock(id),
        Err(STATUS_EINVAL)
    );
    let child_timer = service
        .process_timers(child)
        .unwrap()
        .create(Clock::Monotonic, Notification::None)
        .unwrap();
    let mut processes = RecordingProcesses::default();
    // An uncommitted exec or startup announcement cannot reset timers.
    service.refresh_image_state(parent, &mut processes).unwrap();
    assert_eq!(
        thread_signal_request(&mut service, parent, protocol::OP_SIGNAL_IMAGE_STARTED, &[])
            .header
            .status,
        0
    );
    assert_eq!(
        service.process_timers(parent).unwrap().clock(id),
        Ok(Clock::Monotonic)
    );
    processes
        .images
        .insert(parent.process_id as u32, Err(protocol::STATUS_EIO));
    assert_eq!(
        service.refresh_image_state(parent, &mut processes),
        Err(protocol::STATUS_EIO)
    );
    assert_eq!(
        service.process_timers(parent).unwrap().clock(id),
        Ok(Clock::Monotonic)
    );
    processes.images.insert(
        parent.process_id as u32,
        Ok(mnu_abi::ProcessStatus {
            process_id: parent.process_id,
            state: mnu_abi::PROCESS_STATE_RUNNING,
            image_revision: 1,
            ..Default::default()
        }),
    );
    service.refresh_image_state(parent, &mut processes).unwrap();
    assert_eq!(
        service.process_timers(parent).unwrap().clock(id),
        Err(STATUS_EINVAL)
    );
    assert_eq!(
        service.process_timers(child).unwrap().clock(child_timer),
        Ok(Clock::Monotonic)
    );
    // The exec rule is specific to timer_create objects, not alarm/setitimer.
    assert_eq!(service.next_alarm_deadline(), Some(1_000_000_000));
}

#[test]
fn even_disarmed_root_owned_timers_keep_exit_observation_live_until_reclaimed() {
    let parent = peer();
    let mut service = service_for(parent);
    let mut processes = RecordingProcesses::default();
    service
        .process_timers(parent)
        .unwrap()
        .create(Clock::Monotonic, Notification::None)
        .unwrap();
    assert!(
        service
            .child_lifecycle_handles()
            .contains(&(parent.process_id as u32))
    );
    processes.states.insert(
        parent.process_id as u32,
        ProcessLifecycle::Exited { exit_code: 0 },
    );
    service
        .refresh_child_exit_notifications(&mut processes)
        .unwrap();
    assert!(
        !service
            .child_lifecycle_handles()
            .contains(&(parent.process_id as u32))
    );
    assert_eq!(
        service.process_timers(parent).err(),
        Some(protocol::STATUS_ESRCH)
    );
}
