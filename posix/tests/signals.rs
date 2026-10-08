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
        let reply = self.service.borrow_mut().handle(self.peer, header, payload);
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
    assert_eq!(
        service.bind_process(
            identity,
            AuthenticatedProcess {
                handle: identity.process_id as u32,
                process_id: identity.process_id,
            },
        ),
        Ok(true)
    );
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
    assert_eq!(receiver.dequeue_signal(1 << 9).unwrap(), 0);
    assert_eq!(receiver.dequeue_signal(0).unwrap(), 10);
    assert_eq!(receiver.pending_signals().unwrap(), 0);

    sender.send_signal(102, protocol::SIGNAL_KILL).unwrap();
    assert_eq!(
        receiver
            .dequeue_signal(1 << (protocol::SIGNAL_KILL - 1))
            .unwrap(),
        protocol::SIGNAL_KILL
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
    assert_eq!(sender.dequeue_signal(0).unwrap(), 12);
    assert_eq!(same_user_client.dequeue_signal(0).unwrap(), 12);
    assert_eq!(other_user_client.pending_signals().unwrap(), 0);
}
