use super::*;

fn payload() -> [u8; protocol::cpu_sleep::REQUEST_LEN] {
    let mut bytes = [0; protocol::cpu_sleep::REQUEST_LEN];
    protocol::cpu_sleep::encode_request(
        protocol::cpu_sleep::Request {
            process: 0,
            absolute: false,
            nanoseconds: 50,
        },
        &mut bytes,
    )
    .unwrap();
    bytes
}
fn sender() -> mnu_abi::ExecutionIdentity {
    mnu_abi::ExecutionIdentity {
        process_id: 2901,
        thread_id: 17,
    }
}
fn header() -> protocol::Header {
    protocol::Header {
        opcode: protocol::OP_THREAD_CPU_SLEEP,
        payload_len: payload().len() as u32,
        ..Default::default()
    }
}
fn start(
    registry: &mut Registry<Channel>,
    environment: &Rc<RefCell<Environment>>,
    peer: PeerIdentity,
    endpoint: Channel,
    reply: impl FnOnce(u128) -> bool,
) -> Result<bool, i32> {
    let mut environment = environment.borrow_mut();
    let Environment { service, processes } = &mut *environment;
    let image = service.capture_request_image(peer)?;
    registry.begin_thread_request_with_reply(
        service,
        peer,
        image,
        Some(sender()),
        header(),
        &payload(),
        &[AttachedObject {
            handle: 818,
            rights: mnu_abi::HANDLE_RIGHT_WAIT,
        }],
        endpoint,
        processes,
        reply,
    )
}
fn setup_thread() -> (PeerIdentity, Rc<RefCell<Environment>>) {
    let (client, environment) = setup();
    subject(&environment, 2902, 501);
    CLOCKS.with(|c| {
        let mut c = c.borrow_mut();
        c.process_samples = vec![(2901, 10_000)];
        c.thread_samples = vec![(2901, 18, 100)];
    });
    (client.transport().peer, environment)
}

#[test]
fn only_the_attached_thread_clock_advances_the_wait() {
    let (peer, environment) = setup_thread();
    let mut registry = Registry::new();
    let (endpoint, state) = channel();
    assert_eq!(
        start(&mut registry, &environment, peer, endpoint, |deadline| {
            assert_eq!(deadline, 150);
            true
        }),
        Ok(true)
    );
    CLOCKS.with(|c| {
        let mut c = c.borrow_mut();
        c.process_samples = vec![(2901, 1_000_000)];
        c.thread_samples = vec![(2901, 18, 149)];
        c.thread_reads.clear();
        c.reads.clear();
    });
    assert_eq!(observe(&mut registry, &environment), Ok(0));
    assert_eq!(state.borrow().attempts, 0);
    CLOCKS.with(|c| {
        assert_eq!(c.borrow().thread_reads, [(2901, 18)]);
        assert!(c.borrow().reads.is_empty());
        c.borrow_mut().thread_samples = vec![(2901, 18, 150)];
    });
    assert_eq!(observe(&mut registry, &environment), Ok(1));
    assert_eq!(state.borrow().delivered, [Ok(())]);
    assert_eq!(state.borrow().drops, 1);
}

#[test]
fn thread_admission_requires_exact_attachment_rights_and_native_sender_identity() {
    let (peer, environment) = setup_thread();
    let mut registry = Registry::new();
    for case in 0..12 {
        let mut header = header();
        let mut bytes = payload();
        let mut sender = Some(sender());
        let mut attachments = vec![AttachedObject {
            handle: 818,
            rights: mnu_abi::HANDLE_RIGHT_WAIT,
        }];
        let expected = match case {
            0 => {
                sender = None;
                protocol::STATUS_EPERM
            }
            1 => {
                sender.as_mut().unwrap().process_id = 1;
                protocol::STATUS_EPERM
            }
            2 => {
                sender.as_mut().unwrap().thread_id = 0;
                protocol::STATUS_EPERM
            }
            3 => {
                attachments[0].handle = 817;
                STATUS_EINVAL
            }
            4 => {
                attachments[0].handle = 899;
                protocol::STATUS_EPERM
            }
            5 => {
                attachments.clear();
                STATUS_EINVAL
            }
            6 => {
                attachments[0].rights |= mnu_abi::HANDLE_RIGHT_TRANSFER;
                STATUS_EINVAL
            }
            7 => {
                bytes[8] = 1;
                STATUS_EINVAL
            }
            8 => {
                header.flags = 1;
                STATUS_EINVAL
            }
            9 => {
                header.status = -5;
                STATUS_EINVAL
            }
            10 => {
                header.payload_len -= 1;
                STATUS_EINVAL
            }
            _ => {
                header.opcode = protocol::OP_PROCESS_CPU_SLEEP;
                protocol::STATUS_ENOSYS
            }
        };
        let (endpoint, state) = channel();
        let mut environment = environment.borrow_mut();
        let Environment { service, processes } = &mut *environment;
        let image = service.capture_request_image(peer).unwrap();
        assert_eq!(
            registry.begin_thread_request_with_reply(
                service,
                PeerIdentity {
                    effective_uid: 0,
                    ..peer
                },
                image,
                sender,
                header,
                &bytes,
                &attachments,
                endpoint,
                processes,
                |_| panic!("invalid thread request published")
            ),
            Err(expected),
            "case {case}"
        );
        assert!(registry.is_empty());
        assert_eq!(state.borrow().drops, 1);
    }
}

#[test]
fn failed_publication_and_native_sampling_do_not_publish_or_keep_waiters() {
    for mode in 0..3 {
        let (peer, environment) = setup_thread();
        let mut registry = Registry::new();
        let (endpoint, state) = channel();
        CLOCKS.with(|c| {
            let mut c = c.borrow_mut();
            c.fail = mode == 1;
            c.exec = mode == 2;
        });
        assert_eq!(
            start(&mut registry, &environment, peer, endpoint, |_| {
                assert_eq!(mode, 0);
                false
            }),
            match mode {
                0 => Ok(false),
                1 => Err(protocol::STATUS_EIO),
                _ => Err(protocol::STATUS_ESRCH),
            }
        );
        assert!(registry.is_empty());
        assert_eq!(state.borrow().drops, 1);
    }
}

#[test]
fn retired_native_thread_identity_never_retargets_a_reused_runtime_slot() {
    let (peer, environment) = setup_thread();
    let mut registry = Registry::new();
    let (endpoint, state) = channel();
    start(&mut registry, &environment, peer, endpoint, |_| true).unwrap();
    CLOCKS.with(|c| c.borrow_mut().thread_samples = vec![(2901, 19, 1_000_000)]);
    assert_eq!(observe(&mut registry, &environment), Ok(1));
    assert_eq!(state.borrow().delivered, [Err(protocol::STATUS_ESRCH)]);
    assert_eq!(state.borrow().drops, 1);
}
