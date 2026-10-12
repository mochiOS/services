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
                | protocol::OP_SIGNAL_THREAD_RAISE
                | protocol::OP_SIGNAL_THREAD_EPOCH
                | protocol::OP_SIGNAL_IMAGE_STARTED
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
fn attached_thread_signal_is_private_to_the_native_target_not_the_sender() {
    let service = service();
    let first = client(&service, 101, 501);
    let second = client(&service, 101, 502);
    let bit = 1 << 9;
    first
        .thread_signal_mask(protocol::SIGNAL_MASK_SET, 0)
        .unwrap();
    second
        .thread_signal_mask(protocol::SIGNAL_MASK_SET, bit)
        .unwrap();
    let target = mnu_abi::ThreadStatus {
        process_id: 101,
        thread_id: 502,
        state: mnu_abi::THREAD_STATE_RUNNING,
        reserved: 0,
    };
    let rights = mnu_abi::HANDLE_RIGHT_WAIT | mnu_abi::HANDLE_RIGHT_SIGNAL;
    let mut payload = [0; protocol::SIGNAL_SEND_REQUEST_LEN];
    protocol::encode_signal_send_request(
        protocol::SignalSendRequest {
            selector: 0,
            signal: 10,
        },
        &mut payload,
    )
    .unwrap();
    service
        .borrow_mut()
        .send_thread_signal(
            peer(101),
            ExecutionIdentity {
                process_id: 101,
                thread_id: 501,
            },
            target,
            rights,
            &payload,
        )
        .unwrap();
    assert_eq!(first.thread_dequeue_signal_delivery().unwrap().signal, 0);
    assert_eq!(second.thread_pending_signals().unwrap(), bit);
    second
        .thread_signal_mask(protocol::SIGNAL_MASK_UNBLOCK, bit)
        .unwrap();
    assert_eq!(second.thread_dequeue_signal_delivery().unwrap().signal, 10);
}

#[test]
fn thread_signal_requires_signal_rights_same_process_and_a_live_native_thread() {
    let service = service();
    let first = client(&service, 101, 501);
    first
        .thread_signal_mask(protocol::SIGNAL_MASK_SET, 0)
        .unwrap();
    let sender = ExecutionIdentity {
        process_id: 101,
        thread_id: 501,
    };
    let target = mnu_abi::ThreadStatus {
        process_id: 101,
        thread_id: 501,
        state: mnu_abi::THREAD_STATE_RUNNING,
        reserved: 0,
    };
    let rights = mnu_abi::HANDLE_RIGHT_WAIT | mnu_abi::HANDLE_RIGHT_SIGNAL;
    let mut payload = [0; protocol::SIGNAL_SEND_REQUEST_LEN];
    protocol::encode_signal_send_request(
        protocol::SignalSendRequest {
            selector: 0,
            signal: 0,
        },
        &mut payload,
    )
    .unwrap();
    assert_eq!(
        service
            .borrow_mut()
            .send_thread_signal(peer(101), sender, target, rights, &payload),
        Ok(())
    );
    assert_eq!(first.thread_signal_epoch().unwrap(), 0);
    for reduced in [0, mnu_abi::HANDLE_RIGHT_WAIT, mnu_abi::HANDLE_RIGHT_SIGNAL] {
        assert_eq!(
            service
                .borrow_mut()
                .send_thread_signal(peer(101), sender, target, reduced, &payload),
            Err(protocol::STATUS_EPERM)
        );
    }
    assert_eq!(
        service.borrow_mut().send_thread_signal(
            peer(101),
            sender,
            mnu_abi::ThreadStatus {
                process_id: 102,
                ..target
            },
            rights,
            &payload
        ),
        Err(protocol::STATUS_EPERM)
    );
    assert_eq!(
        service.borrow_mut().send_thread_signal(
            peer(101),
            sender,
            mnu_abi::ThreadStatus {
                state: mnu_abi::THREAD_STATE_TERMINATED,
                ..target
            },
            rights,
            &payload
        ),
        Err(protocol::STATUS_ESRCH)
    );
    assert_eq!(first.thread_dequeue_signal_delivery().unwrap().signal, 0);
}

#[test]
fn wait_guard_detects_pending_delivery_and_the_post_delivery_entry_race() {
    let service = service();
    let first = client(&service, 101, 501);
    let second = client(&service, 101, 502);
    first
        .thread_signal_mask(protocol::SIGNAL_MASK_SET, 0)
        .unwrap();
    second
        .thread_signal_mask(protocol::SIGNAL_MASK_SET, 0)
        .unwrap();
    let identity = ExecutionIdentity {
        process_id: 101,
        thread_id: 501,
    };
    assert_eq!(first.thread_signal_epoch().unwrap(), 0);
    assert_eq!(
        service
            .borrow()
            .validate_wait_delivery_epoch(peer(101), identity, 0),
        Ok(())
    );
    first.send_signal(101, 10).unwrap();
    assert_eq!(
        service
            .borrow()
            .validate_wait_delivery_epoch(peer(101), identity, 0),
        Err(protocol::STATUS_EINTR)
    );
    let delivery = first.thread_dequeue_signal_delivery().unwrap();
    first.complete_signal_delivery(delivery).unwrap();
    assert_eq!(first.thread_signal_epoch().unwrap(), 1);
    assert_eq!(second.thread_signal_epoch().unwrap(), 0);
    assert_eq!(
        service
            .borrow()
            .validate_wait_delivery_epoch(peer(101), identity, 0),
        Err(protocol::STATUS_EINTR)
    );
    assert_eq!(
        service
            .borrow()
            .validate_wait_delivery_epoch(peer(101), identity, 1),
        Ok(())
    );
    first
        .thread_signal_mask(protocol::SIGNAL_MASK_INITIALIZE, 0)
        .unwrap();
    assert_eq!(first.thread_signal_epoch().unwrap(), 1);
}

#[test]
fn wait_guard_uses_the_authenticated_threads_mask_and_private_pending_queue() {
    let service = service();
    let first = client(&service, 101, 501);
    let second = client(&service, 101, 502);
    let pipe = 1 << (protocol::SIGNAL_PIPE - 1);
    first
        .thread_signal_mask(protocol::SIGNAL_MASK_SET, pipe)
        .unwrap();
    second
        .thread_signal_mask(protocol::SIGNAL_MASK_SET, 0)
        .unwrap();
    first.raise_signal(protocol::SIGNAL_PIPE).unwrap();
    let identity = ExecutionIdentity {
        process_id: 101,
        thread_id: 501,
    };
    assert_eq!(
        service
            .borrow()
            .validate_wait_delivery_epoch(peer(101), identity, 0),
        Ok(())
    );
    assert_eq!(
        service.borrow().validate_wait_delivery_epoch(
            peer(101),
            ExecutionIdentity {
                thread_id: 502,
                ..identity
            },
            0
        ),
        Ok(())
    );
    first
        .thread_signal_mask(protocol::SIGNAL_MASK_UNBLOCK, pipe)
        .unwrap();
    assert_eq!(
        service
            .borrow()
            .validate_wait_delivery_epoch(peer(101), identity, 0),
        Err(protocol::STATUS_EINTR)
    );
}

#[test]
fn wait_guard_rejects_untrusted_identity_and_reclaims_epochs_only_after_thread_exit() {
    let service = service();
    let first = client(&service, 101, 501);
    assert_eq!(
        first.thread_signal_epoch(),
        Err(ClientError::Remote(protocol::STATUS_ESRCH))
    );
    first
        .thread_signal_mask(protocol::SIGNAL_MASK_SET, 0)
        .unwrap();
    let identity = ExecutionIdentity {
        process_id: 101,
        thread_id: 501,
    };
    assert_eq!(
        service
            .borrow()
            .validate_wait_delivery_epoch(peer(102), identity, 0),
        Err(protocol::STATUS_EPERM)
    );
    assert_eq!(
        service.borrow().validate_wait_delivery_epoch(
            peer(101),
            ExecutionIdentity {
                thread_id: 0,
                ..identity
            },
            0
        ),
        Err(protocol::STATUS_EPERM)
    );
    service
        .borrow_mut()
        .retire_signal_thread(identity, Err(-5))
        .unwrap_err();
    assert_eq!(first.thread_signal_epoch().unwrap(), 0);
    service
        .borrow_mut()
        .retire_signal_thread(identity, Err(protocol::STATUS_ESRCH))
        .unwrap();
    assert_eq!(
        first.thread_signal_epoch(),
        Err(ClientError::Remote(protocol::STATUS_ESRCH))
    );
}

#[test]
fn generated_signal_is_pending_only_for_the_authenticated_calling_thread() {
    let service = service();
    let first = client(&service, 101, 501);
    let second = client(&service, 101, 502);
    let pipe = 1 << (protocol::SIGNAL_PIPE - 1);
    first
        .thread_signal_mask(protocol::SIGNAL_MASK_SET, pipe)
        .unwrap();
    second
        .thread_signal_mask(protocol::SIGNAL_MASK_SET, 0)
        .unwrap();
    first.raise_signal(protocol::SIGNAL_PIPE).unwrap();
    first.raise_signal(protocol::SIGNAL_PIPE).unwrap();
    assert_eq!(first.thread_pending_signals().unwrap(), pipe);
    assert_eq!(second.thread_pending_signals().unwrap(), 0);
    assert_eq!(second.thread_dequeue_signal_delivery().unwrap().signal, 0);
    assert_eq!(first.thread_dequeue_signal_delivery().unwrap().signal, 0);
    first
        .thread_signal_mask(protocol::SIGNAL_MASK_UNBLOCK, pipe)
        .unwrap();
    assert_eq!(
        service
            .borrow()
            .thread_signal_notification_threads()
            .collect::<Vec<_>>(),
        vec![(101, 501)]
    );
    let delivery = first.thread_dequeue_signal_delivery().unwrap();
    assert_eq!(delivery.signal, protocol::SIGNAL_PIPE);
    assert_ne!(delivery.token, 0);
    first.complete_signal_delivery(delivery).unwrap();
    assert_eq!(first.thread_dequeue_signal_delivery().unwrap().signal, 0);
}

#[test]
fn ignoring_a_signal_discards_all_thread_pending_instances() {
    let service = service();
    let pipe = 1 << (protocol::SIGNAL_PIPE - 1);
    let first = client(&service, 101, 501);
    let second = client(&service, 101, 502);
    for thread in [&first, &second] {
        thread
            .thread_signal_mask(protocol::SIGNAL_MASK_SET, pipe)
            .unwrap();
        thread.raise_signal(protocol::SIGNAL_PIPE).unwrap();
    }
    first
        .set_signal_disposition(protocol::SignalDisposition {
            signal: protocol::SIGNAL_PIPE,
            kind: protocol::SIGNAL_DISPOSITION_IGNORE,
            child_options: 0,
        })
        .unwrap();
    for thread in [&first, &second] {
        assert_eq!(thread.thread_pending_signals().unwrap(), 0);
        thread.raise_signal(protocol::SIGNAL_PIPE).unwrap();
        assert_eq!(thread.thread_pending_signals().unwrap(), 0);
    }
}

#[test]
fn generated_signal_rejects_forged_target_and_uninitialized_thread() {
    let service = service();
    let first = client(&service, 101, 501);
    assert_eq!(
        first.raise_signal(protocol::SIGNAL_PIPE),
        Err(ClientError::Remote(protocol::STATUS_ESRCH))
    );
    first
        .thread_signal_mask(protocol::SIGNAL_MASK_SET, 0)
        .unwrap();
    let mut payload = [0; protocol::SIGNAL_SEND_REQUEST_LEN];
    protocol::encode_signal_send_request(
        protocol::SignalSendRequest {
            selector: 102,
            signal: protocol::SIGNAL_PIPE,
        },
        &mut payload,
    )
    .unwrap();
    let response = service.borrow_mut().handle_thread_signal_request(
        peer(101),
        ExecutionIdentity {
            process_id: 101,
            thread_id: 501,
        },
        protocol::Header {
            opcode: protocol::OP_SIGNAL_THREAD_RAISE,
            ..Default::default()
        },
        &payload,
    );
    assert_eq!(response.header.status, -22);
    assert_eq!(first.thread_dequeue_signal_delivery().unwrap().signal, 0);
}

#[test]
fn thread_exit_discards_its_pending_signal_without_leaking_to_another_thread() {
    let service = service();
    let first = client(&service, 101, 501);
    first
        .thread_signal_mask(protocol::SIGNAL_MASK_SET, 1 << (protocol::SIGNAL_PIPE - 1))
        .unwrap();
    first.raise_signal(protocol::SIGNAL_PIPE).unwrap();
    service
        .borrow_mut()
        .retire_signal_thread(
            ExecutionIdentity {
                process_id: 101,
                thread_id: 501,
            },
            Err(protocol::STATUS_ESRCH),
        )
        .unwrap();
    first
        .thread_signal_mask(protocol::SIGNAL_MASK_SET, 0)
        .unwrap();
    assert_eq!(first.thread_dequeue_signal_delivery().unwrap().signal, 0);
    assert_eq!(
        service
            .borrow()
            .thread_signal_notification_threads()
            .count(),
        0
    );
}

#[test]
fn continue_and_stop_cancel_pending_signals_across_thread_and_process_queues() {
    let service = service();
    let first = client(&service, 101, 501);
    let bits = (1 << (protocol::SIGNAL_CONT - 1)) | (1 << (protocol::SIGNAL_TSTP - 1));
    first
        .thread_signal_mask(protocol::SIGNAL_MASK_SET, bits)
        .unwrap();
    first.raise_signal(protocol::SIGNAL_TSTP).unwrap();
    first.send_signal(101, protocol::SIGNAL_CONT).unwrap();
    assert_eq!(
        first.thread_pending_signals().unwrap(),
        1 << (protocol::SIGNAL_CONT - 1)
    );
    first.raise_signal(protocol::SIGNAL_TSTP).unwrap();
    assert_eq!(
        first.thread_pending_signals().unwrap(),
        1 << (protocol::SIGNAL_TSTP - 1)
    );
    first.send_signal(101, protocol::SIGNAL_TSTP).unwrap();
    first.raise_signal(protocol::SIGNAL_CONT).unwrap();
    assert_eq!(
        first.thread_pending_signals().unwrap(),
        1 << (protocol::SIGNAL_CONT - 1)
    );
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

#[test]
fn reclaiming_abandoned_deliveries_frees_capacity_without_touching_live_owners() {
    let service = service();
    let exited = client(&service, 101, 501);
    let live = client(&service, 101, 502);
    let other_process = client(&service, 102, 501);
    for caller in [&exited, &live, &other_process] {
        caller
            .thread_signal_mask(protocol::SIGNAL_MASK_INITIALIZE, 0)
            .unwrap();
    }
    let mut abandoned = Vec::new();
    let mut retained = Vec::new();
    for index in 0..protocol::SIGNAL_MAX {
        exited.send_signal(101, 30).unwrap();
        let caller = if index % 2 == 0 { &exited } else { &live };
        let delivery = caller.thread_dequeue_signal_delivery().unwrap();
        assert_eq!(delivery.signal, 30);
        if index % 2 == 0 {
            abandoned.push(delivery);
        } else {
            retained.push(delivery);
        }
    }
    other_process.send_signal(102, 30).unwrap();
    let other_delivery = other_process.thread_dequeue_signal_delivery().unwrap();
    live.send_signal(101, 31).unwrap();
    assert_eq!(
        live.thread_dequeue_signal_delivery(),
        Err(ClientError::Remote(protocol::STATUS_EAGAIN))
    );
    let identity = ExecutionIdentity {
        process_id: 101,
        thread_id: 501,
    };
    assert_eq!(
        service.borrow_mut().retire_signal_thread(identity, Err(-5)),
        Err(-5)
    );
    assert_eq!(
        live.thread_dequeue_signal_delivery(),
        Err(ClientError::Remote(protocol::STATUS_EAGAIN))
    );
    assert_eq!(
        service
            .borrow_mut()
            .retire_signal_thread(identity, Err(protocol::STATUS_ESRCH)),
        Ok(true)
    );
    for delivery in abandoned {
        assert_eq!(
            exited.complete_signal_delivery(delivery),
            Err(ClientError::Remote(protocol::STATUS_EAGAIN))
        );
    }
    let pending = live.thread_dequeue_signal_delivery().unwrap();
    assert_eq!(pending.signal, 31);
    live.complete_signal_delivery(pending).unwrap();
    for delivery in retained {
        live.complete_signal_delivery(delivery).unwrap();
    }
    other_process
        .complete_signal_delivery(other_delivery)
        .unwrap();
    assert_eq!(live.pending_signals().unwrap(), 0);
    assert_eq!(live.thread_dequeue_signal_delivery().unwrap().signal, 0);
}

#[test]
fn image_start_reclaims_only_callers_deliveries_and_preserves_mask_and_pending() {
    let service = service();
    let caller = client(&service, 101, 501);
    let sibling = client(&service, 101, 502);
    let other = client(&service, 102, 501);
    for thread in [&caller, &sibling, &other] {
        thread
            .thread_signal_mask(protocol::SIGNAL_MASK_INITIALIZE, 0)
            .unwrap();
    }
    let mut old = Vec::new();
    let mut live = Vec::new();
    for index in 0..protocol::SIGNAL_MAX {
        caller.send_signal(101, 30).unwrap();
        let delivery = if index % 2 == 0 {
            caller.thread_dequeue_signal_delivery().unwrap()
        } else {
            sibling.thread_dequeue_signal_delivery().unwrap()
        };
        if index % 2 == 0 {
            old.push(delivery);
        } else {
            live.push(delivery);
        }
    }
    other.send_signal(102, 30).unwrap();
    let foreign = other.thread_dequeue_signal_delivery().unwrap();
    caller
        .thread_signal_mask(protocol::SIGNAL_MASK_SET, 1 << 30)
        .unwrap();
    caller.send_signal(101, 31).unwrap();
    assert_eq!(
        sibling.thread_dequeue_signal_delivery(),
        Err(ClientError::Remote(protocol::STATUS_EAGAIN))
    );
    assert_eq!(caller.signal_image_started().unwrap(), 0);
    assert_eq!(
        caller
            .thread_signal_mask(protocol::SIGNAL_MASK_QUERY, 0)
            .unwrap(),
        1 << 30
    );
    assert_eq!(caller.thread_pending_signals().unwrap(), 1 << 30);
    for delivery in old {
        assert_eq!(
            caller.complete_signal_delivery(delivery),
            Err(ClientError::Remote(protocol::STATUS_EAGAIN))
        );
    }
    let pending = sibling.thread_dequeue_signal_delivery().unwrap();
    assert_eq!(pending.signal, 31);
    sibling.complete_signal_delivery(pending).unwrap();
    for delivery in live {
        sibling.complete_signal_delivery(delivery).unwrap();
    }
    other.complete_signal_delivery(foreign).unwrap();
    assert_eq!(caller.pending_signals().unwrap(), 0);
}

#[test]
fn image_start_requires_authenticated_identity_and_empty_payload_before_mutation() {
    let service = service();
    let caller = client(&service, 101, 501);
    caller
        .thread_signal_mask(protocol::SIGNAL_MASK_INITIALIZE, 0)
        .unwrap();
    caller
        .set_signal_disposition(protocol::SignalDisposition {
            signal: 30,
            kind: protocol::SIGNAL_DISPOSITION_CAUGHT,
            child_options: 0,
        })
        .unwrap();
    caller.send_signal(101, 30).unwrap();
    let delivery = caller.thread_dequeue_signal_delivery().unwrap();
    let header = protocol::Header {
        opcode: protocol::OP_SIGNAL_IMAGE_STARTED,
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
    for (identity, flags, payload, expected) in [
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
            &[1][..],
            -22,
        ),
    ] {
        let response = service.borrow_mut().handle_thread_signal_request(
            peer(101),
            identity,
            protocol::Header { flags, ..header },
            payload,
        );
        assert_eq!(response.header.status, expected);
        assert_eq!(
            caller.signal_disposition(30).unwrap().kind,
            protocol::SIGNAL_DISPOSITION_CAUGHT
        );
    }
    caller.complete_signal_delivery(delivery).unwrap();
}
