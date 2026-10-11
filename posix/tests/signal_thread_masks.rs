use std::cell::RefCell;
use std::rc::Rc;

use mnu_abi::ExecutionIdentity;
use mochios_posix_client::{Client, ClientError, Transport};
use mochios_posix_protocol as protocol;
use posix_service::{AuthenticatedProcess, PeerIdentity, PosixService};

#[derive(Clone)]
struct LocalTransport {
    service: Rc<RefCell<PosixService>>,
    peer: PeerIdentity,
    authenticated: ExecutionIdentity,
}

impl Transport for LocalTransport {
    type Error = ();

    fn call(&self, request: &[u8], response: &mut [u8]) -> Result<usize, Self::Error> {
        let (header, payload) = protocol::decode(request).map_err(|_| ())?;
        let reply = if header.opcode == protocol::OP_SIGNAL_THREAD_MASK {
            self.service.borrow_mut().handle_thread_signal_mask(
                self.peer,
                self.authenticated,
                header,
                payload,
            )
        } else {
            self.service.borrow_mut().handle(self.peer, header, payload)
        };
        protocol::encode(reply.header, &reply.payload, response).map_err(|_| ())
    }
}

fn peer(process_id: u64) -> PeerIdentity {
    PeerIdentity {
        process_id,
        effective_uid: 501,
        effective_gid: 501,
    }
}

fn service() -> Rc<RefCell<PosixService>> {
    let mut service = PosixService::new();
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
    for id in [101, 102] {
        service
            .initialize_process(
                peer(1),
                AuthenticatedProcess {
                    handle: id as u32,
                    process_id: id,
                },
                501,
                501,
                &[],
            )
            .unwrap();
    }
    Rc::new(RefCell::new(service))
}

fn client(
    service: &Rc<RefCell<PosixService>>,
    process_id: u64,
    thread_id: u64,
) -> Client<LocalTransport> {
    Client::new(LocalTransport {
        service: Rc::clone(service),
        peer: peer(process_id),
        authenticated: ExecutionIdentity {
            process_id,
            thread_id,
        },
    })
}

#[test]
fn thread_masks_are_independent_and_updates_return_the_previous_value() {
    let service = service();
    let first = client(&service, 101, 501);
    let second = client(&service, 101, 502);
    let other = client(&service, 102, 501);
    assert_eq!(
        first
            .thread_signal_mask(protocol::SIGNAL_MASK_QUERY, 0)
            .unwrap(),
        0
    );
    assert_eq!(
        first
            .thread_signal_mask(protocol::SIGNAL_MASK_SET, 1 << 29)
            .unwrap(),
        0
    );
    assert_eq!(
        first
            .thread_signal_mask(protocol::SIGNAL_MASK_BLOCK, 1 << 30)
            .unwrap(),
        1 << 29
    );
    assert_eq!(
        first
            .thread_signal_mask(protocol::SIGNAL_MASK_UNBLOCK, 1 << 29)
            .unwrap(),
        (1 << 29) | (1 << 30)
    );
    assert_eq!(
        first
            .thread_signal_mask(protocol::SIGNAL_MASK_QUERY, 0)
            .unwrap(),
        1 << 30
    );
    assert_eq!(
        second
            .thread_signal_mask(protocol::SIGNAL_MASK_QUERY, 0)
            .unwrap(),
        0
    );
    assert_eq!(
        other
            .thread_signal_mask(protocol::SIGNAL_MASK_QUERY, 0)
            .unwrap(),
        0
    );
}

#[test]
fn kill_and_stop_cannot_be_blocked_and_initialization_preserves_an_existing_mask() {
    let service = service();
    let caller = client(&service, 101, 501);
    let unblockable = (1 << (protocol::SIGNAL_KILL - 1)) | (1 << (protocol::SIGNAL_STOP - 1));
    assert_eq!(
        caller
            .thread_signal_mask(protocol::SIGNAL_MASK_INITIALIZE, u64::MAX)
            .unwrap(),
        !unblockable
    );
    assert_eq!(
        caller
            .thread_signal_mask(protocol::SIGNAL_MASK_INITIALIZE, 0)
            .unwrap(),
        !unblockable
    );
    assert_eq!(
        caller
            .thread_signal_mask(protocol::SIGNAL_MASK_SET, 1 << 29)
            .unwrap(),
        !unblockable
    );
    assert_eq!(
        caller
            .thread_signal_mask(protocol::SIGNAL_MASK_BLOCK, unblockable)
            .unwrap(),
        1 << 29
    );
    assert_eq!(
        caller
            .thread_signal_mask(protocol::SIGNAL_MASK_QUERY, 0)
            .unwrap(),
        1 << 29
    );
    // The new image resets dispositions, not the surviving native thread mask.
    caller.signal_image_started().unwrap();
    assert_eq!(
        caller
            .thread_signal_mask(protocol::SIGNAL_MASK_INITIALIZE, 0)
            .unwrap(),
        1 << 29
    );
}

#[test]
fn identities_from_request_bytes_cannot_select_a_thread_or_another_process() {
    let service = service();
    let owner = client(&service, 101, 501);
    owner
        .thread_signal_mask(protocol::SIGNAL_MASK_SET, 1 << 29)
        .unwrap();
    for authenticated in [
        ExecutionIdentity {
            process_id: 102,
            thread_id: 501,
        },
        ExecutionIdentity {
            process_id: 0,
            thread_id: 501,
        },
        ExecutionIdentity {
            process_id: 101,
            thread_id: 0,
        },
    ] {
        let attacker = Client::new(LocalTransport {
            service: Rc::clone(&service),
            peer: peer(101),
            authenticated,
        });
        assert_eq!(
            attacker.thread_signal_mask(protocol::SIGNAL_MASK_SET, 0),
            Err(ClientError::Remote(protocol::STATUS_EPERM))
        );
    }
    assert_eq!(
        client(&service, 999, 501).thread_signal_mask(protocol::SIGNAL_MASK_SET, 0),
        Err(ClientError::Remote(protocol::STATUS_ESRCH))
    );
    assert_eq!(
        owner
            .thread_signal_mask(protocol::SIGNAL_MASK_QUERY, 0)
            .unwrap(),
        1 << 29
    );
}

#[test]
fn malformed_mask_requests_are_rejected_without_mutating_state() {
    let service = service();
    let caller = client(&service, 101, 501);
    caller
        .thread_signal_mask(protocol::SIGNAL_MASK_SET, 1 << 29)
        .unwrap();
    let mut bytes = [0; protocol::SIGNAL_THREAD_MASK_LEN];
    protocol::encode_signal_mask_request(
        protocol::SignalMaskRequest {
            operation: protocol::SIGNAL_MASK_SET,
            mask: 0,
        },
        &mut bytes,
    )
    .unwrap();
    for offset in [0, 4] {
        let mut invalid = bytes;
        invalid[offset..offset + 4].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(protocol::decode_signal_mask_request(&invalid).is_err());
        let response = service.borrow_mut().handle_thread_signal_mask(
            peer(101),
            ExecutionIdentity {
                process_id: 101,
                thread_id: 501,
            },
            protocol::Header {
                opcode: protocol::OP_SIGNAL_THREAD_MASK,
                ..Default::default()
            },
            &invalid,
        );
        assert_eq!(response.header.status, -22);
        assert_eq!(
            caller
                .thread_signal_mask(protocol::SIGNAL_MASK_QUERY, 0)
                .unwrap(),
            1 << 29
        );
    }
    for length in 0..16 {
        assert!(protocol::decode_signal_mask_request(&bytes[..length]).is_err());
    }
    assert!(protocol::decode_signal_mask_request(&[0; 17]).is_err());
    assert!(
        caller
            .thread_signal_mask(protocol::SIGNAL_MASK_QUERY, 1)
            .is_err()
    );
    assert!(caller.thread_signal_mask(5, 0).is_err());
}

#[test]
fn unblocking_a_pending_signal_requests_delivery_again() {
    let service = service();
    let caller = client(&service, 101, 501);
    caller
        .thread_signal_mask(protocol::SIGNAL_MASK_SET, 1 << 29)
        .unwrap();
    caller.send_signal(101, 30).unwrap();
    service.borrow_mut().acknowledge_signal_notification(101);
    assert!(
        !service
            .borrow()
            .signal_notification_processes()
            .any(|id| id == 101)
    );
    caller
        .thread_signal_mask(protocol::SIGNAL_MASK_UNBLOCK, 1 << 30)
        .unwrap();
    assert!(
        !service
            .borrow()
            .signal_notification_processes()
            .any(|id| id == 101)
    );
    caller
        .thread_signal_mask(protocol::SIGNAL_MASK_UNBLOCK, 1 << 29)
        .unwrap();
    assert!(
        service
            .borrow()
            .signal_notification_processes()
            .any(|id| id == 101)
    );
}

#[test]
fn mask_updates_require_authenticated_dispatch_and_strict_header_flags() {
    let service = service();
    let caller = client(&service, 101, 501);
    caller
        .thread_signal_mask(protocol::SIGNAL_MASK_SET, 1 << 29)
        .unwrap();
    let mut bytes = [0; protocol::SIGNAL_THREAD_MASK_LEN];
    protocol::encode_signal_mask_request(
        protocol::SignalMaskRequest {
            operation: protocol::SIGNAL_MASK_SET,
            mask: 0,
        },
        &mut bytes,
    )
    .unwrap();
    let header = protocol::Header {
        opcode: protocol::OP_SIGNAL_THREAD_MASK,
        request_id: 97,
        ..Default::default()
    };
    assert_eq!(
        service
            .borrow_mut()
            .handle(peer(101), header, &bytes)
            .header
            .status,
        -22
    );
    for (opcode, flags, expected) in [
        (protocol::OP_SIGNAL_THREAD_MASK, 1, -22),
        (u16::MAX, 0, protocol::STATUS_ENOSYS),
    ] {
        let response = service.borrow_mut().handle_thread_signal_mask(
            peer(101),
            ExecutionIdentity {
                process_id: 101,
                thread_id: 501,
            },
            protocol::Header {
                opcode,
                flags,
                ..header
            },
            &bytes,
        );
        assert_eq!(response.header.status, expected);
        assert_eq!(response.header.request_id, 97);
        assert_eq!(
            caller
                .thread_signal_mask(protocol::SIGNAL_MASK_QUERY, 0)
                .unwrap(),
            1 << 29
        );
    }
}
