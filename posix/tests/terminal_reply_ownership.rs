use mochios_posix_client::{
    Client, ClientError, ObjectHandleAttachment as Handle, ObjectHandles, ObjectTransport,
    Transport,
};
use mochios_posix_protocol as wire;
use std::cell::{Cell, RefCell};

#[test]
fn invalid_foreground_group_does_not_send_or_release_the_terminal() {
    for group in [0, i64::MAX as u64 + 1, u64::MAX] {
        let replies = Replies {
            opcode: wire::OP_TERMINAL_SET_FOREGROUND,
            mode: 0,
            incoming: vec![8],
            closed: RefCell::new(vec![]),
            calls: Cell::new(0),
        };
        let terminal = Handle {
            handle: 7,
            rights: mnu_abi::HANDLE_RIGHT_TRANSFER,
        };
        assert_eq!(
            Client::new(&replies).set_terminal_foreground_process_group(terminal, group),
            Err(ClientError::RequestTooLarge)
        );
        assert_eq!(replies.calls.get(), 0);
        assert!(replies.closed.borrow().is_empty());
    }
}

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
        if self.opcode == wire::OP_PTY_OPEN {
            assert!(handles.is_empty());
        } else {
            assert_eq!(handles.len(), 1);
            assert_eq!(handles.get(0).unwrap().handle, 7);
        }
        if self.opcode == wire::OP_TERMINAL_SET_FOREGROUND {
            assert_eq!(wire::decode_process_id_request(payload), Ok(71));
        } else {
            assert!(payload.is_empty());
        }
        self.calls.set(self.calls.get() + 1);
        handles.clear();
        for handle in &self.incoming {
            handles
                .push(Handle {
                    handle: *handle,
                    rights: mnu_abi::HANDLE_RIGHT_ALL,
                })
                .unwrap();
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
        let mut payload = if self.opcode == wire::OP_TERMINAL_GET_FOREGROUND {
            let group: i64 = match self.mode {
                8 => 0,
                9 => -1,
                _ => 71,
            };
            group.to_le_bytes().to_vec()
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
                status: if self.mode == 5 { -13 } else { 0 },
                payload_len: payload.len() as u32,
                ..Default::default()
            },
            &payload,
            output,
        )
        .map_err(|_| 99)
    }
}

#[test]
fn pty_creation_transfers_a_distinct_pair_or_releases_every_received_reference_once() {
    for mode in 0..8 {
        for incoming in [
            vec![],
            vec![8],
            vec![8, 9],
            vec![0, 9],
            vec![8, 0],
            vec![8, 8],
            vec![8, 9, 10],
            vec![8, 9, 8, 0],
        ] {
            let replies = Replies {
                opcode: wire::OP_PTY_OPEN,
                mode,
                incoming,
                closed: RefCell::new(vec![]),
                calls: Cell::new(0),
            };
            let result = Client::new(&replies).open_pty();
            let accepted = mode == 0 && replies.incoming == [8, 9];
            match mode {
                0 if accepted => {
                    let pair = result.unwrap();
                    assert_eq!(pair.master.handle, 8);
                    assert_eq!(pair.slave.handle, 9);
                }
                0 | 4 | 6 => assert_eq!(result, Err(ClientError::MismatchedResponse)),
                1 => assert_eq!(result, Err(ClientError::Transport(42))),
                2 | 7 => assert_eq!(result, Err(ClientError::ResponseTooLarge)),
                3 => assert!(matches!(result, Err(ClientError::Protocol(_)))),
                5 => assert_eq!(result, Err(ClientError::Remote(-13))),
                _ => unreachable!(),
            }
            let mut expected = vec![];
            if !accepted {
                for handle in &replies.incoming {
                    if *handle != 0 && !expected.contains(handle) {
                        expected.push(*handle);
                    }
                }
            }
            assert_eq!(*replies.closed.borrow(), expected, "mode={mode}");
            assert_eq!(replies.calls.get(), 1);
        }
    }
}

#[test]
fn terminal_controls_never_close_the_borrowed_terminal_or_replay_a_mutation() {
    for opcode in [
        wire::OP_TERMINAL_ACQUIRE,
        wire::OP_TERMINAL_RELEASE,
        wire::OP_TERMINAL_GET_FOREGROUND,
        wire::OP_TERMINAL_SET_FOREGROUND,
    ] {
        for mode in 0..if opcode == wire::OP_TERMINAL_GET_FOREGROUND {
            10
        } else {
            8
        } {
            for incoming in [vec![], vec![8], vec![8, 8, 9, 0], vec![7, 8, 7, 0]] {
                let replies = Replies {
                    opcode,
                    mode,
                    incoming,
                    closed: RefCell::new(vec![]),
                    calls: Cell::new(0),
                };
                let client = Client::new(&replies);
                let terminal = Handle {
                    handle: 7,
                    rights: mnu_abi::HANDLE_RIGHT_TRANSFER,
                };
                let result = match opcode {
                    wire::OP_TERMINAL_ACQUIRE => client.acquire_controlling_terminal(terminal),
                    wire::OP_TERMINAL_RELEASE => client.release_controlling_terminal(terminal),
                    wire::OP_TERMINAL_SET_FOREGROUND => {
                        client.set_terminal_foreground_process_group(terminal, 71)
                    }
                    _ => client
                        .terminal_foreground_process_group(terminal)
                        .map(|group| assert_eq!(group, 71)),
                };
                match mode {
                    0 if replies.incoming.is_empty() => assert_eq!(result, Ok(())),
                    0 | 4 | 6 | 8 | 9 => assert_eq!(result, Err(ClientError::MismatchedResponse)),
                    1 => assert_eq!(result, Err(ClientError::Transport(42))),
                    2 | 7 => assert_eq!(result, Err(ClientError::ResponseTooLarge)),
                    3 => assert!(matches!(result, Err(ClientError::Protocol(_)))),
                    5 => assert_eq!(result, Err(ClientError::Remote(-13))),
                    _ => unreachable!(),
                }
                let mut expected = vec![];
                for handle in &replies.incoming {
                    if *handle != 0 && *handle != 7 && !expected.contains(handle) {
                        expected.push(*handle);
                    }
                }
                assert_eq!(*replies.closed.borrow(), expected);
                assert_eq!(replies.calls.get(), 1);
            }
        }
    }
}
