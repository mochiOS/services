use std::cell::RefCell;
use std::rc::Rc;

use mochios_posix_client::{Client, ClientError, Transport};
use mochios_posix_protocol as protocol;
use posix_service::{AuthenticatedProcess, PeerIdentity, PosixService};

#[derive(Clone)]
struct LocalTransport {
    service: Rc<RefCell<PosixService>>,
    peer: PeerIdentity,
}

impl Transport for LocalTransport {
    type Error = ();

    fn call(&self, request: &[u8], response: &mut [u8]) -> Result<usize, Self::Error> {
        let (header, payload) = protocol::decode(request).map_err(|_| ())?;
        let reply = if matches!(
            header.opcode,
            protocol::OP_SIGNAL_THREAD_MASK
                | protocol::OP_SIGNAL_THREAD_DEQUEUE
                | protocol::OP_SIGNAL_THREAD_PENDING
                | protocol::OP_SIGNAL_IMAGE_STARTED
        ) {
            self.service.borrow_mut().handle_thread_signal_request(
                self.peer,
                mnu_abi::ExecutionIdentity {
                    process_id: self.peer.process_id,
                    thread_id: self.peer.process_id,
                },
                header,
                payload,
            )
        } else {
            self.service.borrow_mut().handle(self.peer, header, payload)
        };
        protocol::encode(reply.header, &reply.payload, response).map_err(|_| ())
    }
}

fn peer(process_id: u64, uid: u32) -> PeerIdentity {
    PeerIdentity {
        process_id,
        effective_uid: uid,
        effective_gid: uid,
    }
}

fn register(service: &mut PosixService, identity: PeerIdentity) {
    // Model the userspace boot authority explicitly; signal test actors are
    // initialized with independent credentials, not credentials from IPC peers.
    let bootstrap = peer(1, 0);
    if service.registered_peer(1).is_none() {
        service
            .initialize_bootstrap_process(
                AuthenticatedProcess {
                    handle: 1,
                    process_id: 1,
                },
                0,
                0,
                &[],
            )
            .unwrap();
    }
    service
        .initialize_process(
            bootstrap,
            AuthenticatedProcess {
                handle: identity.process_id as u32,
                process_id: identity.process_id,
            },
            identity.effective_uid,
            identity.effective_gid,
            &[],
        )
        .unwrap();
    let response = service.handle(
        identity,
        protocol::Header {
            opcode: protocol::OP_SESSION_REGISTER,
            request_id: identity.process_id,
            ..protocol::Header::default()
        },
        &[],
    );
    assert_eq!(response.header.status, protocol::STATUS_OK);
}

fn client(service: &Rc<RefCell<PosixService>>, identity: PeerIdentity) -> Client<LocalTransport> {
    Client::new(LocalTransport {
        service: Rc::clone(service),
        peer: identity,
    })
}

fn disposition(signal: u32, kind: u32) -> protocol::SignalDisposition {
    protocol::SignalDisposition {
        signal,
        kind,
        child_options: 0,
    }
}

// Mask changes are separate authenticated operations, not a dequeue payload.
trait TestSignalDelivery {
    fn dequeue_with_mask(&self, mask: u64) -> Result<u32, ClientError<()>>;
}

impl TestSignalDelivery for Client<LocalTransport> {
    fn dequeue_with_mask(&self, mask: u64) -> Result<u32, ClientError<()>> {
        self.thread_signal_mask(protocol::SIGNAL_MASK_SET, mask)?;
        let delivery = self.thread_dequeue_signal_delivery()?;
        if delivery.signal != 0 {
            self.complete_signal_delivery(delivery)?;
        }
        Ok(delivery.signal)
    }
}

#[test]
fn installed_image_preserves_ignore_and_pending_but_resets_caught_and_action_flags() {
    let identity = peer(101, 501);
    let service = Rc::new(RefCell::new(PosixService::new()));
    register(&mut service.borrow_mut(), identity);
    let caller = client(&service, identity);
    caller.set_signal_disposition(disposition(10, 1)).unwrap();
    caller.set_signal_disposition(disposition(12, 2)).unwrap();
    caller
        .set_signal_disposition(protocol::SignalDisposition {
            signal: protocol::SIGNAL_CHLD,
            kind: protocol::SIGNAL_DISPOSITION_IGNORE,
            child_options: protocol::SIGNAL_CHILD_OPTION_NOCLDSTOP,
        })
        .unwrap();
    caller.send_signal(101, 12).unwrap();
    let pending = caller.pending_signals().unwrap();
    assert_eq!(
        caller.signal_image_started().unwrap(),
        (1 << 9) | (1 << (protocol::SIGNAL_CHLD - 1))
    );
    assert_eq!(caller.signal_disposition(10).unwrap(), disposition(10, 1));
    assert_eq!(caller.signal_disposition(12).unwrap(), disposition(12, 0));
    assert_eq!(
        caller.signal_disposition(protocol::SIGNAL_CHLD).unwrap(),
        disposition(protocol::SIGNAL_CHLD, 1)
    );
    assert_eq!(caller.pending_signals().unwrap(), pending);
    assert_eq!(caller.dequeue_with_mask(0).unwrap(), 12);
}

#[test]
fn malformed_image_start_does_not_reset_caught_dispositions() {
    let identity = peer(101, 501);
    let service = Rc::new(RefCell::new(PosixService::new()));
    register(&mut service.borrow_mut(), identity);
    let caller = client(&service, identity);
    caller.set_signal_disposition(disposition(12, 2)).unwrap();
    for (flags, payload) in [(1, &[][..]), (0, &[1][..])] {
        let response = service.borrow_mut().handle(
            identity,
            protocol::Header {
                opcode: protocol::OP_SIGNAL_IMAGE_STARTED,
                flags,
                ..Default::default()
            },
            payload,
        );
        assert_eq!(response.header.status, -22);
        assert_eq!(caller.signal_disposition(12).unwrap(), disposition(12, 2));
    }
    assert_eq!(
        client(&service, peer(999, 0)).signal_image_started(),
        Err(ClientError::Remote(protocol::STATUS_ESRCH))
    );
}

#[test]
fn disposition_wire_is_pointer_free_and_rejects_malformed_metadata() {
    let action = disposition(10, protocol::SIGNAL_DISPOSITION_CAUGHT);
    let mut bytes = [0; protocol::SIGNAL_DISPOSITION_LEN];
    protocol::encode_signal_disposition(action, &mut bytes).unwrap();
    assert_eq!(bytes.len(), 16);
    assert_eq!(protocol::decode_signal_disposition(&bytes), Ok(action));
    for offset in [0, 4, 8, 12] {
        let mut invalid = bytes;
        invalid[offset..offset + 4].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(protocol::decode_signal_disposition(&invalid).is_err());
    }
    for length in 0..16 {
        assert!(protocol::decode_signal_disposition(&bytes[..length]).is_err());
    }
    assert!(protocol::decode_signal_disposition(&[0; 17]).is_err());
    assert!(protocol::encode_signal_disposition(action, &mut [0; 15]).is_err());
    assert!(protocol::encode_signal_disposition(disposition(0, 0), &mut bytes).is_err());
    assert!(protocol::encode_signal_disposition(disposition(65, 0), &mut bytes).is_err());
}

#[test]
fn ignore_discards_pending_and_future_signals_without_affecting_other_processes() {
    let first = peer(101, 501);
    let second = peer(102, 501);
    let service = Rc::new(RefCell::new(PosixService::new()));
    register(&mut service.borrow_mut(), first);
    register(&mut service.borrow_mut(), second);
    let sender = client(&service, first);
    let receiver = client(&service, second);
    sender.send_signal(102, 10).unwrap();
    assert_ne!(receiver.pending_signals().unwrap(), 0);
    assert_eq!(
        receiver.set_signal_disposition(disposition(10, 1)).unwrap(),
        disposition(10, 0)
    );
    assert_eq!(receiver.pending_signals().unwrap(), 0);
    assert!(
        !service
            .borrow()
            .signal_notification_processes()
            .any(|id| id == 102)
    );
    sender.send_signal(102, 10).unwrap();
    assert_eq!(receiver.pending_signals().unwrap(), 0);
    assert!(
        !service
            .borrow()
            .signal_notification_processes()
            .any(|id| id == 102)
    );
    assert_eq!(receiver.signal_disposition(10).unwrap(), disposition(10, 1));
    assert_eq!(sender.signal_disposition(10).unwrap(), disposition(10, 0));
    assert_eq!(
        receiver.set_signal_disposition(disposition(10, 2)).unwrap(),
        disposition(10, 1)
    );
    sender.send_signal(102, 10).unwrap();
    assert_eq!(receiver.dequeue_with_mask(0).unwrap(), 10);
}

#[test]
fn disposition_cannot_ignore_kill_or_stop_or_mutate_an_unregistered_peer() {
    let identity = peer(101, 501);
    let service = Rc::new(RefCell::new(PosixService::new()));
    register(&mut service.borrow_mut(), identity);
    let caller = client(&service, identity);
    for signal in [protocol::SIGNAL_KILL, protocol::SIGNAL_STOP] {
        for kind in [0, 1, 2] {
            assert_eq!(
                caller.set_signal_disposition(disposition(signal, kind)),
                Err(ClientError::Remote(-22))
            );
        }
        assert_eq!(
            caller.signal_disposition(signal).unwrap(),
            disposition(signal, 0)
        );
    }
    assert_eq!(
        client(&service, peer(999, 0)).set_signal_disposition(disposition(10, 1)),
        Err(ClientError::Remote(protocol::STATUS_ESRCH))
    );
}

#[test]
fn child_notification_options_and_disposition_update_atomically() {
    let identity = peer(101, 501);
    let service = Rc::new(RefCell::new(PosixService::new()));
    register(&mut service.borrow_mut(), identity);
    let caller = client(&service, identity);
    let action = protocol::SignalDisposition {
        signal: protocol::SIGNAL_CHLD,
        kind: protocol::SIGNAL_DISPOSITION_CAUGHT,
        child_options: protocol::SIGNAL_CHILD_OPTION_NOCLDSTOP,
    };
    assert_eq!(
        caller.set_signal_disposition(action).unwrap(),
        disposition(protocol::SIGNAL_CHLD, 0)
    );
    assert_eq!(
        caller.signal_disposition(protocol::SIGNAL_CHLD).unwrap(),
        action
    );
    let mut bytes = [0; protocol::SIGNAL_DISPOSITION_LEN];
    protocol::encode_signal_disposition(action, &mut bytes).unwrap();
    for (flags, payload) in [
        (2, bytes),
        (0, bytes),
        (1, {
            let mut invalid = bytes;
            invalid[12] = 1;
            invalid
        }),
    ] {
        let response = service.borrow_mut().handle(
            identity,
            protocol::Header {
                opcode: protocol::OP_SIGNAL_DISPOSITION,
                flags,
                ..Default::default()
            },
            &payload,
        );
        assert_eq!(response.header.status, -22);
        assert_eq!(
            caller.signal_disposition(protocol::SIGNAL_CHLD).unwrap(),
            action
        );
    }
}

#[test]
fn ignored_continue_still_requests_native_resume_and_cancels_pending_stop() {
    let identity = peer(101, 501);
    let service = Rc::new(RefCell::new(PosixService::new()));
    register(&mut service.borrow_mut(), identity);
    let caller = client(&service, identity);
    caller
        .set_signal_disposition(disposition(protocol::SIGNAL_CONT, 1))
        .unwrap();
    caller.send_signal(101, protocol::SIGNAL_STOP).unwrap();
    assert_ne!(caller.pending_signals().unwrap(), 0);
    caller.send_signal(101, protocol::SIGNAL_CONT).unwrap();
    assert_eq!(caller.pending_signals().unwrap(), 0);
    assert!(
        !service
            .borrow()
            .signal_notification_processes()
            .any(|id| id == 101)
    );
    assert!(
        service
            .borrow()
            .process_resume_notification_processes()
            .any(|id| id == 101)
    );
}

#[test]
fn signal_wire_format_rejects_invalid_numbers_and_reserved_bytes() {
    let mut bytes = [0u8; protocol::SIGNAL_SEND_REQUEST_LEN];
    protocol::encode_signal_send_request(
        protocol::SignalSendRequest {
            selector: -42,
            signal: 64,
        },
        &mut bytes,
    )
    .unwrap();
    assert_eq!(
        protocol::decode_signal_send_request(&bytes).unwrap(),
        protocol::SignalSendRequest {
            selector: -42,
            signal: 64,
        }
    );
    bytes[12] = 1;
    assert!(protocol::decode_signal_send_request(&bytes).is_err());
    assert!(
        protocol::encode_signal_send_request(
            protocol::SignalSendRequest {
                selector: 1,
                signal: 65,
            },
            &mut bytes,
        )
        .is_err()
    );

    let mut options = [0u8; protocol::SIGNAL_CHILD_OPTIONS_LEN];
    protocol::encode_signal_child_options(protocol::SIGNAL_CHILD_OPTION_NOCLDSTOP, &mut options)
        .unwrap();
    assert_eq!(
        protocol::decode_signal_child_options(&options),
        Ok(protocol::SIGNAL_CHILD_OPTION_NOCLDSTOP)
    );
    assert!(protocol::encode_signal_child_options(2, &mut options).is_err());
    assert!(protocol::decode_signal_child_options(&[0; 5]).is_err());
}

#[test]
fn job_control_signal_numbers_match_the_newlib_target_abi() {
    assert_eq!(protocol::SIGNAL_STOP, 17);
    assert_eq!(protocol::SIGNAL_TSTP, 18);
    assert_eq!(protocol::SIGNAL_CONT, 19);
    assert_eq!(protocol::SIGNAL_CHLD, 20);
    assert_eq!(protocol::SIGNAL_TTIN, 21);
    assert_eq!(protocol::SIGNAL_TTOU, 22);

    let newlib = include_str!("../../../libraries/newlib/newlib/libc/include/sys/signal.h");
    for definition in [
        "#define\tSIGSTOP\t17",
        "#define\tSIGTSTP\t18",
        "#define\tSIGCONT\t19",
        "#define\tSIGCHLD\t20",
        "#define\tSIGTTIN\t21",
        "#define\tSIGTTOU\t22",
    ] {
        assert!(newlib.contains(definition), "missing {definition}");
    }
}

#[test]
fn standard_signals_coalesce_and_respect_the_receiving_thread_mask() {
    let first = peer(101, 501);
    let second = peer(102, 501);
    let service = Rc::new(RefCell::new(PosixService::new()));
    register(&mut service.borrow_mut(), first);
    register(&mut service.borrow_mut(), second);
    let sender = client(&service, first);
    let receiver = client(&service, second);

    sender.send_signal(102, 10).unwrap();
    sender.send_signal(102, 10).unwrap();
    assert_eq!(
        service
            .borrow()
            .signal_notification_processes()
            .collect::<Vec<_>>(),
        vec![102]
    );
    service.borrow_mut().acknowledge_signal_notification(102);
    assert!(
        service
            .borrow()
            .signal_notification_processes()
            .next()
            .is_none()
    );
    assert_eq!(receiver.pending_signals().unwrap(), 1 << 9);
    assert_eq!(receiver.dequeue_with_mask(1 << 9).unwrap(), 0);
    assert_eq!(receiver.dequeue_with_mask(0).unwrap(), 10);
    assert_eq!(receiver.pending_signals().unwrap(), 0);

    sender.send_signal(102, protocol::SIGNAL_KILL).unwrap();
    assert_eq!(
        receiver
            .dequeue_with_mask(1 << (protocol::SIGNAL_KILL - 1))
            .unwrap(),
        protocol::SIGNAL_KILL
    );
}

#[test]
fn child_signal_options_round_trip_through_the_client() {
    let identity = peer(103, 501);
    let service = Rc::new(RefCell::new(PosixService::new()));
    register(&mut service.borrow_mut(), identity);
    let client = client(&service, identity);

    client
        .set_signal_child_options(protocol::SIGNAL_CHILD_OPTION_NOCLDSTOP)
        .unwrap();
    assert!(matches!(
        client.set_signal_child_options(2),
        Err(ClientError::Protocol(
            protocol::ProtocolError::InvalidLength
        ))
    ));
}

#[test]
fn sigcont_requests_native_resume_and_replaces_pending_stop_signals() {
    let sender_identity = peer(151, 501);
    let receiver_identity = peer(152, 501);
    let service = Rc::new(RefCell::new(PosixService::new()));
    register(&mut service.borrow_mut(), sender_identity);
    register(&mut service.borrow_mut(), receiver_identity);
    let sender = client(&service, sender_identity);
    let receiver = client(&service, receiver_identity);

    sender.send_signal(152, protocol::SIGNAL_TSTP).unwrap();
    sender.send_signal(152, protocol::SIGNAL_CONT).unwrap();
    assert_eq!(
        service
            .borrow()
            .process_resume_notification_processes()
            .collect::<Vec<_>>(),
        vec![152]
    );
    assert_eq!(
        receiver.pending_signals().unwrap(),
        1u64 << (protocol::SIGNAL_CONT - 1)
    );

    service
        .borrow_mut()
        .acknowledge_process_resume_notification(152);
    assert!(
        service
            .borrow()
            .process_resume_notification_processes()
            .next()
            .is_none()
    );

    sender.send_signal(152, protocol::SIGNAL_CONT).unwrap();
    sender.send_signal(152, protocol::SIGNAL_TTIN).unwrap();
    assert_eq!(
        receiver.pending_signals().unwrap(),
        1u64 << (protocol::SIGNAL_TTIN - 1)
    );

    service
        .borrow_mut()
        .acknowledge_process_resume_notification(152);
    sender.send_signal(152, protocol::SIGNAL_KILL).unwrap();
    assert_eq!(
        service
            .borrow()
            .process_resume_notification_processes()
            .collect::<Vec<_>>(),
        vec![152]
    );
    assert_eq!(
        receiver.pending_signals().unwrap(),
        (1u64 << (protocol::SIGNAL_KILL - 1)) | (1u64 << (protocol::SIGNAL_TTIN - 1))
    );
}

#[test]
fn signal_selection_uses_posix_credentials_without_granting_uid_zero_authority() {
    let sender_identity = peer(201, 501);
    let same_user = peer(202, 501);
    let other_user = peer(203, 502);
    let root_without_capability = peer(204, 0);
    let service = Rc::new(RefCell::new(PosixService::new()));
    for identity in [
        sender_identity,
        same_user,
        other_user,
        root_without_capability,
    ] {
        register(&mut service.borrow_mut(), identity);
    }
    let sender = client(&service, sender_identity);
    let same_user_client = client(&service, same_user);
    let other_user_client = client(&service, other_user);
    let root_client = client(&service, root_without_capability);

    sender.send_signal(202, 0).unwrap();
    assert!(
        service
            .borrow()
            .signal_notification_processes()
            .next()
            .is_none()
    );
    assert_eq!(same_user_client.pending_signals().unwrap(), 0);
    assert_eq!(
        sender.send_signal(999, 0).unwrap_err(),
        ClientError::Remote(protocol::STATUS_ESRCH)
    );
    assert_eq!(
        sender.send_signal(203, 10).unwrap_err(),
        ClientError::Remote(protocol::STATUS_EPERM)
    );
    assert_eq!(
        root_client.send_signal(203, 10).unwrap_err(),
        ClientError::Remote(protocol::STATUS_EPERM)
    );

    sender.send_signal(-1, 12).unwrap();
    assert_eq!(sender.dequeue_with_mask(0).unwrap(), 12);
    assert_eq!(same_user_client.dequeue_with_mask(0).unwrap(), 12);
    assert_eq!(other_user_client.pending_signals().unwrap(), 0);
}
