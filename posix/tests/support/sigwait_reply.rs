use super::*;
use posix_service::SignalWaitCompletion;

const SIGNAL: u32 = 10;
const MASK: u64 = 1 << (SIGNAL - 1);

#[test]
fn failed_reply_preserves_thread_and_process_origins_and_accepts_each_only_once() {
    for deadline in [None, Some(0)] {
        let (mut service, _, parent, child, _, _) = orphan_family();
        let own = mnu_abi::ExecutionIdentity {
            process_id: parent.process_id,
            thread_id: 901,
        };
        let sibling = mnu_abi::ExecutionIdentity {
            thread_id: 902,
            ..own
        };
        for thread in [own, sibling] {
            terminal_mask(&mut service, parent, thread.thread_id, MASK);
        }
        send_signal(&mut service, child, parent, SIGNAL);
        let mut bytes = [0; protocol::SIGNAL_SEND_REQUEST_LEN];
        protocol::encode_signal_send_request(
            protocol::SignalSendRequest {
                selector: 0,
                signal: SIGNAL,
            },
            &mut bytes,
        )
        .unwrap();
        assert_eq!(
            service
                .handle_thread_signal_request(
                    parent,
                    own,
                    protocol::Header {
                        opcode: protocol::OP_SIGNAL_THREAD_RAISE,
                        ..Default::default()
                    },
                    &bytes
                )
                .header
                .status,
            0
        );
        for _ in 0..3 {
            assert_eq!(
                service.poll_wait_signal_info_with_reply(
                    parent,
                    own,
                    MASK,
                    0,
                    deadline,
                    100,
                    |accepted| {
                        assert_eq!(accepted.signal, SIGNAL);
                        assert_eq!(accepted.origin.process_id, parent.process_id);
                        assert_eq!(accepted.origin.real_uid, 505);
                        false
                    }
                ),
                Ok(SignalWaitCompletion::Undelivered)
            );
        }
        // While the first thread's signal remains pending, its sibling can
        // select only the separately queued process-wide occurrence.
        assert_eq!(
            service.poll_wait_signal_info_with_reply(
                parent,
                sibling,
                MASK,
                0,
                deadline,
                100,
                |accepted| {
                    assert_eq!(accepted.origin.process_id, child.process_id);
                    false
                },
            ),
            Ok(SignalWaitCompletion::Undelivered)
        );
        assert_eq!(
            service.poll_wait_signal_info_with_reply(
                parent,
                own,
                MASK,
                0,
                deadline,
                100,
                |accepted| {
                    assert_eq!(accepted.origin.process_id, parent.process_id);
                    true
                }
            ),
            Ok(SignalWaitCompletion::Replied)
        );
        assert_eq!(
            service.signal_state(parent.process_id).unwrap().pending(),
            MASK
        );
        // The original process signal still has the child's identity after
        // both kinds of reply have been rejected.
        for publish in [false, true] {
            assert_eq!(
                service.poll_wait_signal_info_with_reply(
                    parent,
                    sibling,
                    MASK,
                    0,
                    deadline,
                    100,
                    |accepted| {
                        assert_eq!(accepted.origin.process_id, child.process_id);
                        assert_eq!(accepted.origin.real_uid, 505);
                        publish
                    }
                ),
                Ok(if publish {
                    SignalWaitCompletion::Replied
                } else {
                    SignalWaitCompletion::Undelivered
                })
            );
        }
        assert_eq!(
            service.signal_state(parent.process_id).unwrap().pending(),
            0
        );
        assert_eq!(
            service.poll_wait_signal_info_with_reply(
                parent,
                own,
                MASK,
                0,
                Some(100),
                100,
                |_| panic!("no signal")
            ),
            Err(protocol::STATUS_EAGAIN)
        );
        assert_eq!(
            service.poll_wait_signal_info_with_reply(
                parent,
                own,
                MASK,
                0,
                Some(101),
                100,
                |_| panic!("still pending")
            ),
            Ok(SignalWaitCompletion::Pending)
        );
    }
}

#[test]
fn failed_validation_never_publishes_and_leaves_signal_available_to_the_valid_waiter() {
    let (mut service, init, parent, child, _, _) = orphan_family();
    let own = mnu_abi::ExecutionIdentity {
        process_id: parent.process_id,
        thread_id: 901,
    };
    terminal_mask(&mut service, parent, own.thread_id, MASK);
    send_signal(&mut service, child, parent, SIGNAL);
    for (sender, mask, epoch, error) in [
        (
            mnu_abi::ExecutionIdentity {
                process_id: init.process_id,
                ..own
            },
            MASK,
            0,
            protocol::STATUS_EPERM,
        ),
        (
            mnu_abi::ExecutionIdentity {
                thread_id: 902,
                ..own
            },
            MASK,
            0,
            protocol::STATUS_ESRCH,
        ),
        (own, MASK | (1 << 11), 0, STATUS_EINVAL),
        (own, MASK, 1, protocol::STATUS_EINTR),
    ] {
        assert_eq!(
            service.poll_wait_signal_info_with_reply(
                parent,
                sender,
                mask,
                epoch,
                None,
                0,
                |_| panic!("invalid wait published")
            ),
            Err(error)
        );
        assert_eq!(
            service.signal_state(parent.process_id).unwrap().pending(),
            MASK
        );
    }
    assert_eq!(
        service.poll_wait_signal_info_with_reply(parent, own, MASK, 0, None, 0, |accepted| {
            assert_eq!(accepted.origin.process_id, child.process_id);
            true
        }),
        Ok(SignalWaitCompletion::Replied)
    );
}
