use super::*;
use posix_service::{RequestImage, timer_callback::Completion};
use protocol::timer_callback::{self as callback, Event};

fn sender(peer: PeerIdentity) -> mnu_abi::ExecutionIdentity {
    mnu_abi::ExecutionIdentity {
        process_id: peer.process_id,
        thread_id: 17,
    }
}
fn header() -> protocol::Header {
    protocol::Header {
        opcode: protocol::OP_TIMER_THREAD_WAIT,
        payload_len: callback::REQUEST_LEN as u32,
        ..Default::default()
    }
}
fn poll(
    service: &mut PosixService,
    peer: PeerIdentity,
    image: RequestImage,
    processes: &mut RecordingProcesses,
    reply: impl FnOnce(Event) -> bool,
) -> Result<Completion, i32> {
    service.poll_timer_callback(
        peer,
        image,
        sender(peer),
        header(),
        &callback::REQUEST,
        &[],
        processes,
        reply,
    )
}
fn arm(
    service: &mut PosixService,
    peer: PeerIdentity,
    cookie: u64,
) -> posix_service::process_timer::TimerId {
    arm_internal(
        service,
        peer,
        Clock::Monotonic,
        Notification::Thread { cookie },
        5,
        5,
        false,
    )
}

#[test]
fn canonical_callback_records_reject_truncation_reserved_bits_and_invalid_tokens() {
    let event = Event {
        timer: u64::MAX,
        cookie: u64::MAX,
        overrun: i32::MAX as u32,
    };
    let mut bytes = [0; callback::REPLY_LEN];
    callback::encode(event, &mut bytes).unwrap();
    assert_eq!(callback::decode(&bytes), Ok(event));
    for length in 0..bytes.len() {
        assert!(callback::decode(&bytes[..length]).is_err());
    }
    for offset in [0, 2, 3, 4, 5, 6, 7, 28, 29, 30, 31] {
        let mut invalid = bytes;
        invalid[offset] ^= 0x80;
        assert!(callback::decode(&invalid).is_err(), "offset {offset}");
    }
    for event in [
        Event { timer: 0, ..event },
        Event { cookie: 0, ..event },
        Event {
            overrun: 1 << 31,
            ..event
        },
    ] {
        assert!(callback::encode(event, &mut bytes).is_err());
    }
    for length in 0..callback::REQUEST_LEN {
        assert!(callback::decode_request(&callback::REQUEST[..length]).is_err());
    }
    let mut request = callback::REQUEST;
    for offset in 0..request.len() {
        request[offset] ^= 0x80;
        assert!(callback::decode_request(&request).is_err());
        request[offset] ^= 0x80;
    }
}

#[test]
fn blocked_signals_do_not_block_callbacks_and_failed_reply_retains_updated_overrun() {
    let (client, environment) = setup();
    let peer = client.transport().peer;
    let mut env = environment.borrow_mut();
    let Environment { service, processes } = &mut *env;
    terminal_mask(service, peer, 17, u64::MAX);
    let id = arm(service, peer, 123);
    let signal = arm_internal(
        service,
        peer,
        Clock::Monotonic,
        Notification::Signal {
            signal: 30,
            value: 321,
        },
        5,
        5,
        false,
    );
    let image = service.capture_request_image(peer).unwrap();
    assert_eq!(
        poll(service, peer, image, processes, |_| panic!(
            "not yet observed"
        )),
        Ok(Completion::Pending)
    );
    service.observe_process_timers(processes).unwrap();
    CLOCKS.with(|c| c.borrow_mut().samples.monotonic_ns = 25);
    let expected = Event {
        timer: id.raw(),
        cookie: 123,
        overrun: 4,
    };
    assert_eq!(
        poll(service, peer, image, processes, |event| {
            assert_eq!(event, expected);
            false
        }),
        Ok(Completion::Disconnected)
    );
    assert_eq!(service.process_timers(peer).unwrap().overrun(id), Ok(0));
    assert_eq!(
        poll(service, peer, image, processes, |event| {
            assert_eq!(event, expected);
            true
        }),
        Ok(Completion::Published)
    );
    assert_eq!(service.process_timers(peer).unwrap().overrun(id), Ok(4));
    assert_eq!(
        poll(service, peer, image, processes, |_| panic!(
            "duplicate delivery"
        )),
        Ok(Completion::Pending)
    );
    assert!(
        service
            .process_timers(peer)
            .unwrap()
            .pending_notifications()
            .any(|event| event.timer == signal)
    );
}

#[test]
fn oldest_pending_callback_is_selected_before_a_rearmed_lower_timer_id() {
    let (client, environment) = setup();
    let peer = client.transport().peer;
    let mut env = environment.borrow_mut();
    let Environment { service, processes } = &mut *env;
    terminal_mask(service, peer, 17, 0);
    let first = arm(service, peer, 1);
    let second = arm(service, peer, 2);
    let image = service.capture_request_image(peer).unwrap();
    service.observe_process_timers(processes).unwrap();
    assert_eq!(
        poll(service, peer, image, processes, |e| {
            assert_eq!(e.timer, first.raw());
            true
        }),
        Ok(Completion::Published)
    );
    CLOCKS.with(|c| c.borrow_mut().samples.monotonic_ns = 20);
    service.observe_process_timers(processes).unwrap();
    assert_eq!(
        poll(service, peer, image, processes, |e| {
            assert_eq!(e.timer, second.raw());
            true
        }),
        Ok(Completion::Published)
    );
    assert_eq!(
        poll(service, peer, image, processes, |e| {
            assert_eq!(e.timer, first.raw());
            true
        }),
        Ok(Completion::Published)
    );
}

#[test]
fn invalid_frame_sender_or_receiver_registration_never_consumes_an_event() {
    let (client, environment) = setup();
    let peer = client.transport().peer;
    let mut env = environment.borrow_mut();
    let Environment { service, processes } = &mut *env;
    terminal_mask(service, peer, 17, 0);
    let id = arm(service, peer, 1);
    service.observe_process_timers(processes).unwrap();
    let image = service.capture_request_image(peer).unwrap();
    for mode in 0..9 {
        let mut header = header();
        let mut sender = sender(peer);
        let mut bytes = callback::REQUEST;
        let mut attachments = Vec::new();
        let expected = match mode {
            0 => {
                header.opcode = protocol::OP_TIMER_GET;
                protocol::STATUS_ENOSYS
            }
            1 => {
                header.flags = 1;
                STATUS_EINVAL
            }
            2 => {
                header.status = -1;
                STATUS_EINVAL
            }
            3 => {
                header.payload_len -= 1;
                STATUS_EINVAL
            }
            4 => {
                attachments.push(AttachedObject {
                    handle: 44,
                    rights: 1,
                });
                STATUS_EINVAL
            }
            5 => {
                bytes[7] = 1;
                STATUS_EINVAL
            }
            6 => {
                sender.process_id += 1;
                protocol::STATUS_EPERM
            }
            7 => {
                sender.thread_id = 0;
                protocol::STATUS_EPERM
            }
            _ => {
                sender.thread_id = 88;
                protocol::STATUS_ESRCH
            }
        };
        assert_eq!(
            service.poll_timer_callback(
                peer,
                image,
                sender,
                header,
                &bytes,
                &attachments,
                processes,
                |_| panic!("invalid admission")
            ),
            Err(expected)
        );
    }
    assert_eq!(
        poll(service, peer, image, processes, |e| {
            assert_eq!(e.timer, id.raw());
            true
        }),
        Ok(Completion::Published)
    );
}

#[test]
fn failed_sampling_unwind_and_exec_do_not_publish_or_latch_events() {
    for mode in 0..3 {
        let (client, environment) = setup();
        let peer = client.transport().peer;
        let mut env = environment.borrow_mut();
        let Environment { service, processes } = &mut *env;
        terminal_mask(service, peer, 17, 0);
        let id = arm(service, peer, 1);
        service.observe_process_timers(processes).unwrap();
        let image = service.capture_request_image(peer).unwrap();
        if mode == 0 {
            assert!(
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| poll(
                    service,
                    peer,
                    image,
                    processes,
                    |_| panic!("failed reply")
                )))
                .is_err()
            );
        } else {
            CLOCKS.with(|c| {
                let mut c = c.borrow_mut();
                c.fail = mode == 1;
                c.exec = mode == 2;
            });
            assert_eq!(
                poll(service, peer, image, processes, |_| panic!(
                    "failed admission"
                )),
                Err(if mode == 1 {
                    protocol::STATUS_EIO
                } else {
                    protocol::STATUS_ESRCH
                })
            );
        }
        if mode < 2 {
            CLOCKS.with(|c| c.borrow_mut().fail = false);
            assert_eq!(service.process_timers(peer).unwrap().overrun(id), Ok(0));
            assert_eq!(
                poll(service, peer, image, processes, |_| true),
                Ok(Completion::Published)
            );
        } else {
            assert!(
                service
                    .process_timers(peer)
                    .unwrap()
                    .pending_notifications()
                    .next()
                    .is_none()
            );
        }
    }
}

#[test]
fn deletion_and_recreation_do_not_retarget_a_pending_event() {
    let (client, environment) = setup();
    let peer = client.transport().peer;
    let mut env = environment.borrow_mut();
    let Environment { service, processes } = &mut *env;
    terminal_mask(service, peer, 17, 0);
    let old = arm(service, peer, 1);
    service.observe_process_timers(processes).unwrap();
    service.process_timers(peer).unwrap().delete(old).unwrap();
    let new = arm(service, peer, 2);
    assert_ne!(old, new);
    let image = service.capture_request_image(peer).unwrap();
    assert_eq!(
        poll(service, peer, image, processes, |_| panic!("retired event")),
        Ok(Completion::Pending)
    );
    service.observe_process_timers(processes).unwrap();
    assert_eq!(
        poll(service, peer, image, processes, |e| {
            assert_eq!((e.timer, e.cookie), (new.raw(), 2));
            true
        }),
        Ok(Completion::Published)
    );
}

#[test]
fn a_root_receiver_cannot_consume_another_process_callback() {
    let (client, environment) = setup();
    let peer = client.transport().peer;
    let root = PeerIdentity {
        process_id: 1,
        effective_uid: 0,
        effective_gid: 0,
    };
    let mut service = service_for(root);
    service
        .initialize_process(
            root,
            AuthenticatedProcess {
                process_id: peer.process_id,
                handle: peer.process_id as u32,
            },
            peer.effective_uid,
            peer.effective_gid,
            &[],
        )
        .unwrap();
    let mut env = environment.borrow_mut();
    env.service = service;
    let Environment { service, processes } = &mut *env;
    terminal_mask(service, peer, 17, 0);
    terminal_mask(service, root, 17, 0);
    arm(service, peer, 123);
    service.observe_process_timers(processes).unwrap();
    let image = service.capture_request_image(root).unwrap();
    assert_eq!(
        poll(service, root, image, processes, |_| panic!(
            "foreign callback"
        )),
        Ok(Completion::Pending)
    );
    let image = service.capture_request_image(peer).unwrap();
    assert_eq!(
        poll(service, peer, image, processes, |e| {
            assert_eq!(e.cookie, 123);
            true
        }),
        Ok(Completion::Published)
    );
}

#[test]
fn client_rejects_malformed_or_handle_carrying_callback_replies() {
    for bad in 0..5 {
        let (client, environment) = setup();
        let peer = client.transport().peer;
        {
            let mut env = environment.borrow_mut();
            let Environment { service, processes } = &mut *env;
            terminal_mask(service, peer, 17, 0);
            arm(service, peer, 123);
            service.observe_process_timers(processes).unwrap();
        }
        client.transport().bad_reply.set(bad);
        let event = client.timer_wait_callback();
        if bad == 0 {
            assert_eq!(event.unwrap().cookie, 123);
        } else {
            assert!(event.is_err());
        }
        assert_eq!(
            client.transport().closed.borrow().as_slice(),
            if bad == 1 { &[71][..] } else { &[] }
        );
    }
}
