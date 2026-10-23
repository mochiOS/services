use super::*;

fn request(clock: Clock) -> (protocol::Header, [u8; wire::CREATE_LEN]) {
    let mut payload = [0; wire::CREATE_LEN];
    wire::encode_create(clock, Notification::None, &mut payload).unwrap();
    (
        protocol::Header {
            opcode: protocol::OP_TIMER_CREATE,
            payload_len: payload.len() as u32,
            ..Default::default()
        },
        payload,
    )
}
fn sender(peer: PeerIdentity) -> Option<mnu_abi::ExecutionIdentity> {
    Some(mnu_abi::ExecutionIdentity {
        process_id: peer.process_id,
        thread_id: 17,
    })
}
fn get(
    service: &mut PosixService,
    processes: &mut RecordingProcesses,
    peer: PeerIdentity,
    id: u64,
) -> i32 {
    let image = service.capture_request_image(peer).unwrap();
    service
        .handle_process_timer_request(
            peer,
            image,
            protocol::Header {
                opcode: protocol::OP_TIMER_GET,
                payload_len: 8,
                ..Default::default()
            },
            &id.to_le_bytes(),
            &[],
            processes,
        )
        .response
        .header
        .status
}

#[test]
fn unpublished_creations_release_quota_preserve_existing_timers_and_never_reuse_ids() {
    let (client, environment) = setup();
    let existing = client
        .timer_create(Clock::Monotonic, Notification::None)
        .unwrap();
    let peer = client.transport().peer;
    let mut state = environment.borrow_mut();
    let Environment { service, processes } = &mut *state;
    let image = service.capture_request_image(peer).unwrap();
    let mut previous = existing;
    for index in 0..300 {
        let clock = if index % 2 == 0 {
            Clock::ThreadCpu
        } else {
            Clock::ProcessCpu
        };
        let (header, payload) = request(clock);
        let mut discarded = 0;
        assert_eq!(
            service.create_process_timer_with_reply(
                peer,
                image,
                sender(peer),
                header,
                &payload,
                &[],
                processes,
                |id| {
                    discarded = id;
                    false
                }
            ),
            Ok(false)
        );
        assert!(discarded > previous);
        previous = discarded;
        assert_eq!(get(service, processes, peer, discarded), STATUS_EINVAL);
        assert_eq!(get(service, processes, peer, existing), 0);
    }
    let (header, payload) = request(Clock::Monotonic);
    let mut accepted = Vec::new();
    for _ in 0..posix_service::process_timer::MAX_TIMERS_PER_PROCESS - 1 {
        assert_eq!(
            service.create_process_timer_with_reply(
                peer,
                image,
                None,
                header,
                &payload,
                &[],
                processes,
                |id| {
                    assert!(id > previous);
                    previous = id;
                    accepted.push(id);
                    true
                }
            ),
            Ok(true)
        );
    }
    assert_eq!(
        service.create_process_timer_with_reply(
            peer,
            image,
            None,
            header,
            &payload,
            &[],
            processes,
            |_| panic!("quota cannot publish")
        ),
        Err(protocol::STATUS_EAGAIN)
    );
    assert_eq!(get(service, processes, peer, existing), 0);
    for id in accepted {
        assert_eq!(get(service, processes, peer, id), 0);
    }
}

#[test]
fn publication_unwind_retires_tentative_ids_and_success_has_no_fallible_post_step() {
    let (client, environment) = setup();
    let peer = client.transport().peer;
    let mut state = environment.borrow_mut();
    let Environment { service, processes } = &mut *state;
    service.refresh_image_state(peer, processes).unwrap();
    let image = service.capture_request_image(peer).unwrap();
    let (header, payload) = request(Clock::ThreadCpu);
    assert_eq!(
        service
            .handle_process_timer_request(peer, image, header, &payload, &[], processes)
            .response
            .header
            .status,
        protocol::STATUS_ENOSYS,
        "a detached response builder must not create an unpublished object"
    );
    let mut previous = 0;
    for _ in 0..150 {
        let mut discarded = 0;
        assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            service.create_process_timer_with_reply(
                peer,
                image,
                sender(peer),
                header,
                &payload,
                &[],
                processes,
                |id| {
                    discarded = id;
                    panic!("publication failed before enqueue")
                },
            )
        }))
        .is_err());
        assert!(discarded > previous);
        previous = discarded;
        assert_eq!(get(service, processes, peer, discarded), STATUS_EINVAL);
    }
    let mut accepted = 0;
    assert_eq!(
        service.create_process_timer_with_reply(
            peer,
            image,
            sender(peer),
            header,
            &payload,
            &[],
            processes,
            |id| {
                accepted = id;
                CLOCKS.with(|state| state.borrow_mut().fail = true);
                true
            }
        ),
        Ok(true)
    );
    assert!(accepted > previous);
    CLOCKS.with(|state| state.borrow_mut().fail = false);
    assert_eq!(get(service, processes, peer, accepted), 0);
}

#[test]
fn malformed_or_unadmitted_creation_never_invokes_publication() {
    let (client, environment) = setup();
    let peer = client.transport().peer;
    let mut state = environment.borrow_mut();
    let Environment { service, processes } = &mut *state;
    service.refresh_image_state(peer, processes).unwrap();
    let image = service.capture_request_image(peer).unwrap();
    let (header, payload) = request(Clock::ThreadCpu);
    for invalid in [
        protocol::Header { flags: 1, ..header },
        protocol::Header {
            status: 1,
            ..header
        },
        protocol::Header {
            payload_len: 0,
            ..header
        },
    ] {
        assert_eq!(
            service.create_process_timer_with_reply(
                peer,
                image,
                sender(peer),
                invalid,
                &payload,
                &[],
                processes,
                |_| panic!("invalid frame")
            ),
            Err(STATUS_EINVAL)
        );
    }
    assert_eq!(
        service.create_process_timer_with_reply(
            peer,
            image,
            None,
            header,
            &payload,
            &[],
            processes,
            |_| panic!("missing native sender")
        ),
        Err(protocol::STATUS_EPERM)
    );
    let attached = AttachedObject {
        handle: 999,
        rights: 1,
    };
    assert_eq!(
        service.create_process_timer_with_reply(
            peer,
            image,
            sender(peer),
            header,
            &payload,
            &[attached],
            processes,
            |_| panic!("unexpected attachment")
        ),
        Err(STATUS_EINVAL)
    );
    CLOCKS.with(|state| state.borrow_mut().exec = true);
    assert!(service
        .create_process_timer_with_reply(
            peer,
            image,
            sender(peer),
            header,
            &payload,
            &[],
            processes,
            |_| panic!("replaced image")
        )
        .is_err());
}
