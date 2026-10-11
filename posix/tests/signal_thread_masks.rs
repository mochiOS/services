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
        let reply = if matches!(
            header.opcode,
            protocol::OP_SIGNAL_THREAD_MASK
                | protocol::OP_SIGNAL_THREAD_DEQUEUE
                | protocol::OP_SIGNAL_THREAD_PENDING
        ) {
            self.service.borrow_mut().handle_thread_signal_request(
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
        let response = service.borrow_mut().handle_thread_signal_request(
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
        let response = service.borrow_mut().handle_thread_signal_request(
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

#[test]
fn delivery_and_pending_use_the_authenticated_threads_mask() {
    let service = service();
    let blocked = client(&service, 101, 501);
    let open = client(&service, 101, 502);
    blocked
        .thread_signal_mask(protocol::SIGNAL_MASK_INITIALIZE, 1 << 29)
        .unwrap();
    open.thread_signal_mask(protocol::SIGNAL_MASK_INITIALIZE, 0)
        .unwrap();
    blocked.send_signal(101, 30).unwrap();
    assert_eq!(blocked.thread_pending_signals().unwrap(), 1 << 29);
    assert_eq!(open.thread_pending_signals().unwrap(), 0);
    assert_eq!(blocked.thread_dequeue_signal_delivery().unwrap().signal, 0);
    assert_eq!(blocked.pending_signals().unwrap(), 1 << 29);
    let delivery = open.thread_dequeue_signal_delivery().unwrap();
    assert_eq!(delivery.signal, 30);
    assert_ne!(delivery.token, 0);
    open.complete_signal_delivery(delivery).unwrap();
    assert_eq!(blocked.thread_pending_signals().unwrap(), 0);
    blocked.send_signal(101, 30).unwrap();
    blocked
        .thread_signal_mask(protocol::SIGNAL_MASK_UNBLOCK, 1 << 29)
        .unwrap();
    assert_eq!(blocked.thread_pending_signals().unwrap(), 0);
    let delivery = blocked.thread_dequeue_signal_delivery().unwrap();
    assert_eq!(delivery.signal, 30);
    blocked.complete_signal_delivery(delivery).unwrap();
}

#[test]
fn thread_delivery_rejects_uninitialized_threads_and_untrusted_requests_atomically() {
    let service = service();
    let caller = client(&service, 101, 501);
    caller.send_signal(101, 30).unwrap();
    assert!(matches!(
        caller.thread_pending_signals(),
        Err(ClientError::Remote(protocol::STATUS_ESRCH))
    ));
    assert!(matches!(
        caller.thread_dequeue_signal_delivery(),
        Err(ClientError::Remote(protocol::STATUS_ESRCH))
    ));
    caller
        .thread_signal_mask(protocol::SIGNAL_MASK_INITIALIZE, 0)
        .unwrap();
    for opcode in [
        protocol::OP_SIGNAL_THREAD_PENDING,
        protocol::OP_SIGNAL_THREAD_DEQUEUE,
    ] {
        let header = protocol::Header {
            opcode,
            request_id: 113,
            ..Default::default()
        };
        assert_eq!(
            service
                .borrow_mut()
                .handle(peer(101), header, &[])
                .header
                .status,
            -22
        );
        for (identity, flags, payload, status) in [
            (
                ExecutionIdentity {
                    process_id: 101,
                    thread_id: 501,
                },
                1,
                &[][..],
                -22,
            ),
            (
                ExecutionIdentity {
                    process_id: 101,
                    thread_id: 501,
                },
                0,
                &[0u8][..],
                -22,
            ),
            (
                ExecutionIdentity {
                    process_id: 102,
                    thread_id: 501,
                },
                0,
                &[][..],
                protocol::STATUS_EPERM,
            ),
            (
                ExecutionIdentity {
                    process_id: 101,
                    thread_id: 0,
                },
                0,
                &[][..],
                protocol::STATUS_EPERM,
            ),
        ] {
            let reply = service.borrow_mut().handle_thread_signal_request(
                peer(101),
                identity,
                protocol::Header { flags, ..header },
                payload,
            );
            assert_eq!(reply.header.status, status);
            assert_eq!(reply.header.request_id, 113);
            assert_eq!(caller.pending_signals().unwrap(), 1 << 29);
        }
    }
}

#[test]
fn retired_dequeue_opcode_is_unknown_and_cannot_override_a_thread_mask() {
    let service = service();
    let caller = client(&service, 101, 501);
    caller
        .thread_signal_mask(protocol::SIGNAL_MASK_INITIALIZE, 1 << 29)
        .unwrap();
    caller.send_signal(101, 30).unwrap();
    for payload in [&[][..], &[0u8; 8][..]] {
        let header = protocol::Header {
            opcode: 36,
            request_id: 114,
            ..Default::default()
        };
        let reply = service.borrow_mut().handle(peer(101), header, payload);
        assert_eq!(reply.header.status, protocol::STATUS_ENOSYS);
        assert_eq!(reply.header.request_id, 114);
    }
    assert_eq!(caller.thread_pending_signals().unwrap(), 1 << 29);
    assert_eq!(caller.thread_dequeue_signal_delivery().unwrap().signal, 0);
    assert_eq!(
        caller
            .thread_signal_mask(protocol::SIGNAL_MASK_QUERY, 0)
            .unwrap(),
        1 << 29
    );
}

#[test]
fn confirmed_thread_exit_reclaims_only_its_mask_and_preserves_process_signals() {
    for status in [
        Ok(mnu_abi::ThreadStatus {
            process_id: 101,
            thread_id: 501,
            state: mnu_abi::THREAD_STATE_TERMINATED,
            reserved: 0,
        }),
        Err(protocol::STATUS_ESRCH),
    ] {
        let service = service();
        let exited = client(&service, 101, 501);
        let live = client(&service, 101, 502);
        exited
            .thread_signal_mask(protocol::SIGNAL_MASK_INITIALIZE, 1 << 29)
            .unwrap();
        live.thread_signal_mask(protocol::SIGNAL_MASK_INITIALIZE, 1 << 30)
            .unwrap();
        exited.send_signal(101, 30).unwrap();
        service.borrow_mut().acknowledge_signal_notification(101);
        assert_eq!(
            service.borrow_mut().retire_signal_thread(
                ExecutionIdentity {
                    process_id: 101,
                    thread_id: 501
                },
                status
            ),
            Ok(true)
        );
        assert_eq!(
            exited.thread_pending_signals(),
            Err(ClientError::Remote(protocol::STATUS_ESRCH))
        );
        assert_eq!(
            live.thread_signal_mask(protocol::SIGNAL_MASK_QUERY, 0)
                .unwrap(),
            1 << 30
        );
        assert_eq!(live.pending_signals().unwrap(), 1 << 29);
        assert!(
            service
                .borrow()
                .signal_notification_processes()
                .any(|id| id == 101)
        );
        assert_eq!(
            service.borrow_mut().retire_signal_thread(
                ExecutionIdentity {
                    process_id: 101,
                    thread_id: 501
                },
                status
            ),
            Ok(true)
        );
    }
}

#[test]
fn live_threads_and_failed_or_mismatched_observations_are_not_reclaimed() {
    let service = service();
    let caller = client(&service, 101, 501);
    caller
        .thread_signal_mask(protocol::SIGNAL_MASK_INITIALIZE, 1 << 29)
        .unwrap();
    let identity = ExecutionIdentity {
        process_id: 101,
        thread_id: 501,
    };
    let native = mnu_abi::ThreadStatus {
        process_id: 101,
        thread_id: 501,
        state: mnu_abi::THREAD_STATE_TERMINATED,
        reserved: 0,
    };
    for state in mnu_abi::THREAD_STATE_READY..=mnu_abi::THREAD_STATE_SLEEPING {
        assert_eq!(
            service
                .borrow_mut()
                .retire_signal_thread(identity, Ok(mnu_abi::ThreadStatus { state, ..native })),
            Ok(false)
        );
    }
    for (status, expected) in [
        (Err(-5), -5),
        (Err(-11), -11),
        (Err(-9), -9),
        (
            Ok(mnu_abi::ThreadStatus {
                process_id: 102,
                ..native
            }),
            protocol::STATUS_EPERM,
        ),
        (
            Ok(mnu_abi::ThreadStatus {
                thread_id: 502,
                ..native
            }),
            protocol::STATUS_EPERM,
        ),
        (
            Ok(mnu_abi::ThreadStatus {
                reserved: 1,
                ..native
            }),
            -22,
        ),
        (Ok(mnu_abi::ThreadStatus { state: 0, ..native }), -22),
        (Ok(mnu_abi::ThreadStatus { state: 6, ..native }), -22),
    ] {
        assert_eq!(
            service.borrow_mut().retire_signal_thread(identity, status),
            Err(expected)
        );
        assert_eq!(
            caller
                .thread_signal_mask(protocol::SIGNAL_MASK_QUERY, 0)
                .unwrap(),
            1 << 29
        );
    }
    for invalid in [
        ExecutionIdentity {
            process_id: 0,
            ..identity
        },
        ExecutionIdentity {
            thread_id: 0,
            ..identity
        },
    ] {
        assert_eq!(
            service
                .borrow_mut()
                .retire_signal_thread(invalid, Err(protocol::STATUS_ESRCH)),
            Err(protocol::STATUS_EPERM)
        );
    }
}
