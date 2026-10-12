use super::*;

const USER_SIGNAL: u32 = 10;

fn set_action(service: &mut PosixService, peer: PeerIdentity, signal: u32, kind: u32) {
    let mut bytes = [0; protocol::SIGNAL_DISPOSITION_LEN];
    protocol::encode_signal_disposition(
        protocol::SignalDisposition {
            signal,
            kind,
            child_options: 0,
        },
        &mut bytes,
    )
    .unwrap();
    assert_eq!(
        service
            .handle(
                peer,
                protocol::Header {
                    opcode: protocol::OP_SIGNAL_DISPOSITION,
                    flags: protocol::SIGNAL_DISPOSITION_SET,
                    ..Default::default()
                },
                &bytes
            )
            .header
            .status,
        0
    );
}

fn pending(service: &mut PosixService, peer: PeerIdentity, thread: u64) -> u64 {
    let reply = service.handle_thread_signal_request(
        peer,
        mnu_abi::ExecutionIdentity {
            process_id: peer.process_id,
            thread_id: thread,
        },
        protocol::Header {
            opcode: protocol::OP_SIGNAL_THREAD_PENDING,
            ..Default::default()
        },
        &[],
    );
    assert_eq!(reply.header.status, 0);
    protocol::decode_signal_mask(&reply.payload).unwrap()
}

fn raise_for_thread(service: &mut PosixService, peer: PeerIdentity, thread: u64, signal: u32) {
    let mut bytes = [0; protocol::SIGNAL_SEND_REQUEST_LEN];
    protocol::encode_signal_send_request(
        protocol::SignalSendRequest {
            selector: 0,
            signal,
        },
        &mut bytes,
    )
    .unwrap();
    let reply = service.handle_thread_signal_request(
        peer,
        mnu_abi::ExecutionIdentity {
            process_id: peer.process_id,
            thread_id: thread,
        },
        protocol::Header {
            opcode: protocol::OP_SIGNAL_THREAD_RAISE,
            ..Default::default()
        },
        &bytes,
    );
    assert_eq!(reply.header.status, 0);
}

#[test]
fn default_ignore_discards_blocked_process_and_every_threads_pending_signal() {
    let peer = PeerIdentity {
        process_id: 811,
        effective_uid: 501,
        effective_gid: 20,
    };
    for signal in [
        protocol::SIGNAL_CHLD,
        protocol::SIGNAL_URG,
        protocol::SIGNAL_WINCH,
    ] {
        let mut service = service_for(peer);
        let bit = 1 << (signal - 1);
        let other = 1 << (USER_SIGNAL - 1);
        for thread in [811, 812] {
            terminal_mask(&mut service, peer, thread, bit | other);
        }
        set_action(
            &mut service,
            peer,
            signal,
            protocol::SIGNAL_DISPOSITION_CAUGHT,
        );
        send_signal(&mut service, peer, peer, signal);
        for thread in [811, 812] {
            raise_for_thread(&mut service, peer, thread, signal);
        }
        send_signal(&mut service, peer, peer, USER_SIGNAL);
        assert_eq!(pending(&mut service, peer, 811), bit | other);
        assert_eq!(pending(&mut service, peer, 812), bit | other);
        set_action(
            &mut service,
            peer,
            signal,
            protocol::SIGNAL_DISPOSITION_DEFAULT,
        );
        assert_eq!(
            service.signal_state(peer.process_id).unwrap().pending(),
            other
        );
        assert_eq!(pending(&mut service, peer, 811), other);
        assert_eq!(pending(&mut service, peer, 812), other);
        // Installing a later handler cannot resurrect a discarded occurrence.
        set_action(
            &mut service,
            peer,
            signal,
            protocol::SIGNAL_DISPOSITION_CAUGHT,
        );
        assert_eq!(pending(&mut service, peer, 811), other);
        raise_for_thread(&mut service, peer, 811, signal);
        assert_eq!(pending(&mut service, peer, 811), bit | other);
        assert_eq!(pending(&mut service, peer, 812), other);
    }
}

#[test]
fn default_terminate_or_continue_does_not_discard_a_blocked_occurrence() {
    let peer = PeerIdentity {
        process_id: 821,
        effective_uid: 501,
        effective_gid: 20,
    };
    for signal in [USER_SIGNAL, protocol::SIGNAL_CONT] {
        let mut service = service_for(peer);
        let bit = 1 << (signal - 1);
        terminal_mask(&mut service, peer, 821, bit);
        set_action(
            &mut service,
            peer,
            signal,
            protocol::SIGNAL_DISPOSITION_CAUGHT,
        );
        send_signal(&mut service, peer, peer, signal);
        raise_for_thread(&mut service, peer, 821, signal);
        set_action(
            &mut service,
            peer,
            signal,
            protocol::SIGNAL_DISPOSITION_DEFAULT,
        );
        assert_eq!(pending(&mut service, peer, 821), bit);
        assert_eq!(
            service.signal_state(peer.process_id).unwrap().pending(),
            bit
        );
    }
}

#[test]
fn resetting_sigchld_discards_notification_without_discarding_child_wait_status() {
    let (mut service, _, parent, child, mut filesystem, mut processes) = orphan_family();
    terminal_mask(
        &mut service,
        parent,
        parent.process_id,
        1 << (protocol::SIGNAL_CHLD - 1),
    );
    set_child_signal_disposition(&mut service, parent, protocol::SIGNAL_DISPOSITION_CAUGHT);
    processes
        .states
        .insert(142, ProcessLifecycle::Exited { exit_code: 47 });
    service
        .refresh_child_exit_notifications(&mut processes)
        .unwrap();
    assert_ne!(pending(&mut service, parent, parent.process_id), 0);
    set_child_signal_disposition(&mut service, parent, protocol::SIGNAL_DISPOSITION_DEFAULT);
    assert_eq!(pending(&mut service, parent, parent.process_id), 0);
    assert!(!service
        .signal_notification_processes()
        .any(|id| id == parent.process_id));
    let result = service
        .wait_child(
            parent,
            protocol::WaitRequest {
                selector: child.process_id as i64,
                options: 0,
            },
            &mut filesystem,
            &mut processes,
        )
        .unwrap();
    assert_eq!(result.process_id, child.process_id);
    assert_eq!(result.status, 47 << 8);
}
