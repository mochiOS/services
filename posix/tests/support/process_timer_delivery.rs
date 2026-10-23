use super::*;

fn clocks(now: u128) -> Samples {
    Samples {
        realtime_ns: 1_000,
        monotonic_ns: now,
        process_cpu_ns: 2,
        thread_cpu_ns: 0,
    }
}
fn bit(signal: u32) -> u64 {
    1u64 << (signal - 1)
}

#[test]
fn failed_publication_keeps_event_and_last_overrun_while_retry_resamples() {
    let (client, environment) = setup();
    let peer = client.transport().peer;
    let mut environment = environment.borrow_mut();
    let Environment { service, processes } = &mut *environment;
    let id = arm_internal(
        service,
        peer,
        Clock::Monotonic,
        Notification::Default,
        10,
        10,
        false,
    );
    service.observe_process_timers(processes).unwrap();
    let selected = service
        .process_timers(peer)
        .unwrap()
        .select_pending_signal(bit(protocol::SIGNAL_ALRM))
        .unwrap();
    let image = service.capture_request_image(peer).unwrap();
    CLOCKS.with(|c| c.borrow_mut().samples.monotonic_ns = 35);
    let calls = Cell::new(0);
    assert_eq!(
        service.accept_timer_signal_with_reply(peer, image, selected, processes, |pending| {
            calls.set(calls.get() + 1);
            assert_eq!(pending.overrun(), 2);
            false
        }),
        Ok(None)
    );
    assert_eq!(calls.get(), 1);
    assert_eq!(service.process_timers(peer).unwrap().overrun(id), Ok(0));
    let queued = service
        .process_timers(peer)
        .unwrap()
        .select_pending_signal(u64::MAX)
        .unwrap();
    assert_eq!(queued.overrun(), 2);
    CLOCKS.with(|c| c.borrow_mut().samples.monotonic_ns = 55);
    let mut altered = selected;
    altered.notification = Notification::Signal {
        signal: 1,
        value: 0xdead,
    };
    let delivered = service
        .accept_timer_signal_with_reply(peer, image, altered, processes, |pending| {
            calls.set(calls.get() + 1);
            assert_eq!(pending.overrun(), 4);
            assert_eq!(
                pending.notification,
                Notification::Signal {
                    signal: protocol::SIGNAL_ALRM,
                    value: id.raw(),
                }
            );
            true
        })
        .unwrap()
        .unwrap();
    assert_eq!(delivered.overrun(), 4);
    assert_eq!(calls.get(), 2);
    assert_eq!(service.process_timers(peer).unwrap().overrun(id), Ok(4));
    assert!(
        service
            .process_timers(peer)
            .unwrap()
            .select_pending_signal(u64::MAX)
            .is_none()
    );
    CLOCKS.with(|c| assert_eq!(c.borrow().reads, vec![(2901, Clock::Monotonic); 3]));
}

#[test]
fn foreign_stale_and_wrong_kind_selections_never_read_a_clock_or_publish() {
    let _ = setup();
    let (mut service, root, parent, _, _, mut processes) = orphan_family();
    let id = arm_internal(
        &mut service,
        parent,
        Clock::Monotonic,
        Notification::Default,
        10,
        10,
        false,
    );
    service.observe_process_timers(&mut processes).unwrap();
    let selected = service
        .process_timers(parent)
        .unwrap()
        .select_pending_signal(u64::MAX)
        .unwrap();
    CLOCKS.with(|c| c.borrow_mut().reads.clear());
    let image = service.capture_request_image(root).unwrap();
    assert_eq!(
        service.accept_timer_signal_with_reply(root, image, selected, &mut processes, |_| panic!(
            "foreign event published"
        )),
        Err(STATUS_EINVAL)
    );
    assert_eq!(
        service.accept_timer_signal_with_reply(
            parent,
            image,
            selected,
            &mut processes,
            |_| panic!("foreign image published")
        ),
        Err(protocol::STATUS_EPERM)
    );
    let image = service.capture_request_image(parent).unwrap();
    let mut timers = service.process_timers(parent).unwrap();
    timers.set(id, clocks(10), 1, 1, false).unwrap();
    let replacement = timers.observe(id, clocks(11)).unwrap().unwrap();
    assert_eq!(
        service.accept_timer_signal_with_reply(
            parent,
            image,
            selected,
            &mut processes,
            |_| panic!("stale event published")
        ),
        Err(protocol::STATUS_EAGAIN)
    );
    let callback = arm_internal(
        &mut service,
        parent,
        Clock::Monotonic,
        Notification::Thread { cookie: 17 },
        1,
        0,
        false,
    );
    let mut callback = service
        .process_timers(parent)
        .unwrap()
        .observe(callback, clocks(1))
        .unwrap()
        .unwrap();
    callback.notification = Notification::Signal {
        signal: protocol::SIGNAL_ALRM,
        value: 17,
    };
    assert_eq!(
        service.accept_timer_signal_with_reply(
            parent,
            image,
            callback,
            &mut processes,
            |_| panic!("callback disguised as a signal")
        ),
        Err(STATUS_EINVAL)
    );
    CLOCKS.with(|c| assert!(c.borrow().reads.is_empty()));
    assert!(
        service
            .process_timers(parent)
            .unwrap()
            .pending_notifications()
            .any(|pending| pending == replacement)
    );
}

#[test]
fn failed_native_sample_or_exec_during_acceptance_never_publish_or_latch_an_overrun() {
    let (client, environment) = setup();
    let peer = client.transport().peer;
    let mut environment = environment.borrow_mut();
    let Environment { service, processes } = &mut *environment;
    let id = arm_internal(
        service,
        peer,
        Clock::Monotonic,
        Notification::Default,
        10,
        10,
        false,
    );
    service.observe_process_timers(processes).unwrap();
    let selected = service
        .process_timers(peer)
        .unwrap()
        .select_pending_signal(u64::MAX)
        .unwrap();
    let image = service.capture_request_image(peer).unwrap();
    CLOCKS.with(|c| c.borrow_mut().fail = true);
    assert_eq!(
        service.accept_timer_signal_with_reply(peer, image, selected, processes, |_| panic!(
            "sample failure published"
        )),
        Err(protocol::STATUS_EIO)
    );
    assert_eq!(service.process_timers(peer).unwrap().overrun(id), Ok(0));
    assert_eq!(
        service
            .process_timers(peer)
            .unwrap()
            .select_pending_signal(u64::MAX),
        Some(selected)
    );
    CLOCKS.with(|c| {
        c.borrow_mut().fail = false;
        c.borrow_mut().exec = true;
    });
    assert_eq!(
        service.accept_timer_signal_with_reply(peer, image, selected, processes, |_| panic!(
            "old image published"
        )),
        Err(protocol::STATUS_ESRCH)
    );
    assert_eq!(
        service.process_timers(peer).unwrap().clock(id),
        Err(STATUS_EINVAL)
    );
    assert!(
        service
            .process_timers(peer)
            .unwrap()
            .select_pending_signal(u64::MAX)
            .is_none()
    );
}

#[test]
fn candidate_ordering_and_masks_keep_equal_signals_and_callback_events_independent() {
    let (client, environment) = setup();
    let peer = client.transport().peer;
    let mut environment = environment.borrow_mut();
    let Environment { service, processes } = &mut *environment;
    let high = arm_internal(
        service,
        peer,
        Clock::Monotonic,
        Notification::Signal {
            signal: 35,
            value: 1,
        },
        1,
        0,
        false,
    );
    let low = arm_internal(
        service,
        peer,
        Clock::Monotonic,
        Notification::Signal {
            signal: 33,
            value: 2,
        },
        1,
        0,
        false,
    );
    let equal = arm_internal(
        service,
        peer,
        Clock::Monotonic,
        Notification::Signal {
            signal: 33,
            value: 3,
        },
        1,
        0,
        false,
    );
    arm_internal(
        service,
        peer,
        Clock::Monotonic,
        Notification::Thread { cookie: 4 },
        1,
        0,
        false,
    );
    service.observe_process_timers(processes).unwrap();
    let mut timers = service.process_timers(peer).unwrap();
    assert!(timers.select_pending_signal(0).is_none());
    assert!(timers.select_pending_signal(bit(34)).is_none());
    assert_eq!(timers.select_pending_signal(bit(35)).unwrap().timer, high);
    let selected = timers.select_pending_signal(u64::MAX).unwrap();
    assert_eq!(selected.timer, low);
    timers
        .accept_with_reply(selected, clocks(10), |_| true)
        .unwrap()
        .unwrap();
    let next = timers.select_pending_signal(u64::MAX).unwrap();
    assert_eq!(next.timer, equal);
    assert_eq!(
        timers.accept_with_reply(next, clocks(10), |_| false),
        Ok(None)
    );
    assert_eq!(timers.select_pending_signal(u64::MAX), Some(next));
    timers.discard(next, clocks(10)).unwrap();
    assert_eq!(timers.select_pending_signal(u64::MAX).unwrap().timer, high);
    assert_eq!(timers.pending_notifications().count(), 2); // Signal + callback.
}

#[test]
fn successful_publication_is_followed_only_by_infallible_acceptance() {
    let (client, environment) = setup();
    let peer = client.transport().peer;
    let mut environment = environment.borrow_mut();
    let Environment { service, processes } = &mut *environment;
    let id = arm_internal(
        service,
        peer,
        Clock::Monotonic,
        Notification::Default,
        1,
        1,
        false,
    );
    let selected = service
        .process_timers(peer)
        .unwrap()
        .observe(id, clocks(1))
        .unwrap()
        .unwrap();
    let image = service.capture_request_image(peer).unwrap();
    processes.image_reads.clear();
    CLOCKS.with(|c| c.borrow_mut().reads.clear());
    let replies = Cell::new(0);
    let accepted = service
        .accept_timer_signal_with_reply(peer, image, selected, processes, |_| {
            replies.set(replies.get() + 1);
            // Any later clock query would fail. No query/validation belongs after
            // publication, when reporting an error would permit duplicate delivery.
            CLOCKS.with(|c| c.borrow_mut().fail = true);
            true
        })
        .unwrap()
        .unwrap();
    assert_eq!(accepted.overrun(), 9);
    assert_eq!(replies.get(), 1);
    assert_eq!(processes.image_reads, vec![2901, 2901]);
    CLOCKS.with(|c| assert_eq!(c.borrow().reads, vec![(2901, Clock::Monotonic)]));
    assert_eq!(service.process_timers(peer).unwrap().overrun(id), Ok(9));
}

#[test]
fn unwinding_before_publication_does_not_consume_a_timer_notification() {
    let (client, environment) = setup();
    let peer = client.transport().peer;
    let mut environment = environment.borrow_mut();
    let Environment { service, .. } = &mut *environment;
    let id = arm_internal(
        service,
        peer,
        Clock::Monotonic,
        Notification::Default,
        10,
        10,
        false,
    );
    let mut timers = service.process_timers(peer).unwrap();
    let selected = timers.observe(id, clocks(10)).unwrap().unwrap();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = timers.accept_with_reply(selected, clocks(35), |_| panic!("publication failed"));
    }));
    assert!(result.is_err());
    assert_eq!(timers.overrun(id), Ok(0));
    assert_eq!(timers.select_pending_signal(u64::MAX).unwrap().overrun(), 2);
    assert_eq!(
        timers
            .accept_with_reply(selected, clocks(40), |_| true)
            .unwrap()
            .unwrap()
            .overrun(),
        3
    );
}

#[test]
fn serialized_timer_info_snapshots_the_accepted_attempt_not_an_earlier_failed_reply() {
    let (client, environment) = setup();
    let peer = client.transport().peer;
    let mut environment = environment.borrow_mut();
    let Environment { service, processes } = &mut *environment;
    let id = arm_internal(
        service,
        peer,
        Clock::Monotonic,
        Notification::Default,
        10,
        10,
        false,
    );
    service.observe_process_timers(processes).unwrap();
    let selected = service
        .process_timers(peer)
        .unwrap()
        .select_pending_signal(u64::MAX)
        .unwrap();
    let image = service.capture_request_image(peer).unwrap();
    let attempts = RefCell::new(Vec::new());
    for (now, published, overrun) in [(35, false, 2), (55, true, 4)] {
        CLOCKS.with(|c| c.borrow_mut().samples.monotonic_ns = now);
        let result = service
            .accept_timer_signal_with_reply(peer, image, selected, processes, |pending| {
                let origin = pending.signal_origin().unwrap();
                let accepted = protocol::signal_wait::Accepted {
                    signal: protocol::SIGNAL_ALRM,
                    origin,
                };
                let mut bytes = vec![0; protocol::signal_wait::encoded_len(accepted)];
                protocol::signal_wait::encode(accepted, &mut bytes).unwrap();
                attempts.borrow_mut().push(bytes);
                published
            })
            .unwrap();
        assert_eq!(result.is_some(), published);
        let accepted = protocol::signal_wait::decode(attempts.borrow().last().unwrap()).unwrap();
        let timer = accepted.origin.timer.unwrap();
        assert_eq!(
            (timer.timer_id, timer.value_token, timer.overrun),
            (id.raw(), id.raw(), overrun)
        );
    }
    assert_eq!(service.process_timers(peer).unwrap().overrun(id), Ok(4));
    assert!(
        service
            .process_timers(peer)
            .unwrap()
            .select_pending_signal(u64::MAX)
            .is_none()
    );
}
