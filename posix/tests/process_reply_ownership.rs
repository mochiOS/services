use mochios_posix_client::{
    Client, ClientError, ObjectHandleAttachment as Handle, ObjectHandles, ObjectTransport,
    Transport,
};
use mochios_posix_protocol as wire;
use std::cell::{Cell, RefCell};

struct Replies {
    opcode: u16,
    mode: u8,
    incoming: Vec<u32>,
    closed: RefCell<Vec<u32>>,
    calls: Cell<usize>,
}
impl Transport for &Replies {
    type Error = u8;
    fn call(&self, _: &[u8], _: &mut [u8]) -> Result<usize, u8> {
        panic!("explicit Handle transport required")
    }
}
impl ObjectTransport for &Replies {
    type Handle = u32;
    fn close_received_handle(&self, handle: u32) {
        self.closed.borrow_mut().push(handle);
    }
    fn call_with_handles(
        &self,
        input: &[u8],
        output: &mut [u8],
        handles: &mut ObjectHandles<u32>,
    ) -> Result<usize, u8> {
        let (header, payload) = wire::decode(input).unwrap();
        assert_eq!(header.opcode, self.opcode);
        assert_eq!(header.flags, 0);
        let expected = if self.opcode == wire::OP_PROCESS_LAUNCHED {
            vec![source(7), source(11)]
        } else {
            vec![source(7)]
        };
        assert_eq!(handles.iter().collect::<Vec<_>>(), expected);
        match self.opcode {
            wire::OP_PROCESS_INITIALIZE | wire::OP_PROCESS_SPAWNED => {
                let mut groups = [0; 2];
                assert_eq!(
                    wire::decode_spawn_credentials(payload, &mut groups),
                    Ok((501, 20, 2))
                );
                assert_eq!(groups, [20, 30]);
            }
            wire::OP_SIGNAL_THREAD_SEND => assert_eq!(
                wire::decode_signal_send_request(payload),
                Ok(wire::SignalSendRequest {
                    selector: 0,
                    signal: 10
                })
            ),
            _ => assert!(
                payload.is_empty(),
                "identity must come from attached objects"
            ),
        }
        self.calls.set(self.calls.get() + 1);
        handles.clear();
        for handle in &self.incoming {
            handles.push(source(*handle)).unwrap();
        }
        if self.mode == 1 {
            return Err(42);
        }
        if self.mode == 2 {
            return Ok(output.len() + 1);
        }
        if self.mode == 3 {
            output[0] = 0;
            return Ok(1);
        }
        let mut payload = if self.opcode == wire::OP_PROCESS_SESSION_INFO {
            let mut bytes = vec![0; wire::SESSION_INFO_LEN];
            wire::encode_session_info(
                wire::SessionInfo {
                    real_uid: 501,
                    effective_uid: 501,
                    real_gid: 20,
                    effective_gid: 20,
                    umask: 0o22,
                },
                &mut bytes,
            )
            .unwrap();
            bytes
        } else {
            vec![]
        };
        if self.mode == 7 {
            payload.push(1);
        }
        wire::encode(
            wire::Header {
                opcode: if self.mode == 6 {
                    wire::OP_PING
                } else {
                    wire::OP_STATUS
                },
                request_id: header.request_id + u64::from(self.mode == 4),
                status: if self.mode == 5 { -11 } else { 0 },
                payload_len: payload.len() as u32,
                ..Default::default()
            },
            &payload,
            output,
        )
        .map_err(|_| 99)
    }
}
fn source(handle: u32) -> Handle<u32> {
    Handle {
        handle,
        rights: mnu_abi::HANDLE_RIGHT_ALL,
    }
}

#[test]
fn invalid_credentials_or_signal_do_not_send_or_release_a_borrowed_object() {
    for opcode in [
        wire::OP_PROCESS_INITIALIZE,
        wire::OP_PROCESS_SPAWNED,
        wire::OP_SIGNAL_THREAD_SEND,
    ] {
        let replies = Replies {
            opcode,
            mode: 0,
            incoming: vec![8],
            closed: RefCell::new(vec![]),
            calls: Cell::new(0),
        };
        let client = Client::new(&replies);
        for (uid, gid) in [(u32::MAX, 20), (501, u32::MAX)] {
            let result = match opcode {
                wire::OP_PROCESS_INITIALIZE => client.initialize_process(source(7), uid, gid, &[]),
                wire::OP_PROCESS_SPAWNED => client.register_spawned_child(source(7), uid, gid, &[]),
                _ => client.send_thread_signal(wire::SIGNAL_MAX + 1, source(7)),
            };
            assert!(matches!(result, Err(ClientError::Protocol(_))));
            assert_eq!(replies.calls.get(), 0);
            assert!(replies.closed.borrow().is_empty());
        }
    }
}
fn invoke(client: &Client<&Replies>, opcode: u16) -> Result<(), ClientError<u8>> {
    let handle = source(7);
    match opcode {
        wire::OP_SIGNAL_THREAD_REGISTER => client.register_signal_thread(handle),
        wire::OP_SIGNAL_THREAD_SEND => client.send_thread_signal(10, handle),
        wire::OP_PROCESS_FORKED => client.register_child(handle),
        wire::OP_PROCESS_INITIALIZE => client.initialize_process(handle, 501, 20, &[20, 30]),
        wire::OP_PROCESS_SPAWNED => client.register_spawned_child(handle, 501, 20, &[20, 30]),
        wire::OP_PROCESS_LAUNCHED => client.register_launched_child(handle, source(11)),
        wire::OP_PROCESS_LAUNCH_ABORT => client.abort_launched_child(handle),
        wire::OP_PROCESS_TREE_TERMINATE => client.terminate_launched_tree(handle),
        wire::OP_PROCESS_TREE_RECLAIM => client.reclaim_launched_tree(handle),
        wire::OP_PROCESS_SESSION_INFO => client.process_session_info(handle).map(|info| {
            assert_eq!(info.effective_uid, 501);
            assert_eq!(info.effective_gid, 20);
        }),
        _ => unreachable!(),
    }
}

#[test]
fn process_and_thread_replies_preserve_borrowed_objects_and_original_errors_without_replay() {
    for opcode in [
        wire::OP_SIGNAL_THREAD_REGISTER,
        wire::OP_SIGNAL_THREAD_SEND,
        wire::OP_PROCESS_FORKED,
        wire::OP_PROCESS_INITIALIZE,
        wire::OP_PROCESS_SPAWNED,
        wire::OP_PROCESS_LAUNCHED,
        wire::OP_PROCESS_LAUNCH_ABORT,
        wire::OP_PROCESS_TREE_TERMINATE,
        wire::OP_PROCESS_TREE_RECLAIM,
        wire::OP_PROCESS_SESSION_INFO,
    ] {
        for mode in 0..8 {
            for incoming in [vec![], vec![8], vec![8, 8, 9, 0], vec![7, 11, 8, 0]] {
                let replies = Replies {
                    opcode,
                    mode,
                    incoming,
                    closed: RefCell::new(vec![]),
                    calls: Cell::new(0),
                };
                let result = invoke(&Client::new(&replies), opcode);
                match mode {
                    0 if replies.incoming.is_empty() => assert_eq!(result, Ok(())),
                    0 | 4 | 6 => assert_eq!(result, Err(ClientError::MismatchedResponse)),
                    1 => assert_eq!(result, Err(ClientError::Transport(42))),
                    2 | 7 => assert_eq!(result, Err(ClientError::ResponseTooLarge)),
                    3 => assert!(matches!(result, Err(ClientError::Protocol(_)))),
                    5 => assert_eq!(result, Err(ClientError::Remote(-11))),
                    _ => unreachable!(),
                }
                let mut expected = vec![];
                for handle in &replies.incoming {
                    if *handle != 0
                        && *handle != 7
                        && !(opcode == wire::OP_PROCESS_LAUNCHED && *handle == 11)
                        && !expected.contains(handle)
                    {
                        expected.push(*handle);
                    }
                }
                assert_eq!(
                    *replies.closed.borrow(),
                    expected,
                    "opcode={opcode} mode={mode}"
                );
                assert_eq!(replies.calls.get(), 1);
            }
        }
    }
}
