use mochios_posix_client::{
    Client, ClientError, ObjectHandleAttachment as Handle, ObjectHandles, ObjectTransport,
    OpenAtBase, Transport,
};
use mochios_posix_protocol as wire;
use std::cell::{Cell, RefCell};

struct Replies {
    mode: u8,
    incoming: Vec<u32>,
    borrowed: Option<u32>,
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
        assert_eq!(header.opcode, wire::OP_OPEN_AT);
        let open = wire::decode_open_at(payload).unwrap();
        assert_eq!(
            open.options,
            wire::OPEN_READ | wire::OPEN_WRITE | wire::OPEN_CREATE | wire::OPEN_EXCLUSIVE
        );
        assert_eq!(open.path, "new-file");
        assert_eq!(
            handles.iter().map(|entry| entry.handle).collect::<Vec<_>>(),
            self.borrowed.into_iter().collect::<Vec<_>>()
        );
        self.calls.set(self.calls.get() + 1);
        handles.clear();
        for handle in &self.incoming {
            handles
                .push(Handle {
                    handle: *handle,
                    rights: mnu_abi::HANDLE_RIGHT_READ | mnu_abi::HANDLE_RIGHT_WRITE,
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
        let payload = if self.mode == 7 { &[1u8][..] } else { &[] };
        wire::encode(
            wire::Header {
                opcode: if self.mode == 6 {
                    wire::OP_PING
                } else {
                    wire::OP_STATUS
                },
                request_id: header.request_id + u64::from(self.mode == 4),
                status: if self.mode == 5 { -17 } else { 0 },
                payload_len: payload.len() as u32,
                ..Default::default()
            },
            payload,
            output,
        )
        .map_err(|_| 99)
    }
}

#[test]
fn open_transfers_exactly_one_new_handle_or_drains_the_reply_without_replaying_creation() {
    for base in [
        OpenAtBase::ProcessRoot,
        OpenAtBase::ProcessCwd,
        OpenAtBase::Directory(Handle {
            handle: 7,
            rights: mnu_abi::HANDLE_RIGHT_READ | mnu_abi::HANDLE_RIGHT_TRANSFER,
        }),
    ] {
        let borrowed = match base {
            OpenAtBase::Directory(handle) => Some(handle.handle),
            _ => None,
        };
        for mode in 0..8 {
            for incoming in [
                vec![],
                vec![8],
                vec![0],
                vec![7],
                vec![8, 8],
                vec![8, 9, 0],
                vec![7, 8, 7, 0],
            ] {
                let replies = Replies {
                    mode,
                    incoming,
                    borrowed,
                    closed: RefCell::new(vec![]),
                    calls: Cell::new(0),
                };
                let result = Client::new(&replies).open_at(
                    base,
                    wire::OPEN_READ | wire::OPEN_WRITE | wire::OPEN_CREATE | wire::OPEN_EXCLUSIVE,
                    0o600,
                    "new-file",
                );
                let accepted = mode == 0
                    && replies.incoming.len() == 1
                    && replies.incoming[0] != 0
                    && Some(replies.incoming[0]) != borrowed;
                match mode {
                    0 if accepted => assert_eq!(
                        result,
                        Ok(Handle {
                            handle: replies.incoming[0],
                            rights: mnu_abi::HANDLE_RIGHT_READ | mnu_abi::HANDLE_RIGHT_WRITE
                        })
                    ),
                    0 | 4 | 6 => assert_eq!(result, Err(ClientError::MismatchedResponse)),
                    1 => assert_eq!(result, Err(ClientError::Transport(42))),
                    2 | 7 => assert_eq!(result, Err(ClientError::ResponseTooLarge)),
                    3 => assert!(matches!(result, Err(ClientError::Protocol(_)))),
                    5 => assert_eq!(result, Err(ClientError::Remote(-17))),
                    _ => unreachable!(),
                }
                let mut expected = vec![];
                if !accepted {
                    for handle in &replies.incoming {
                        if *handle != 0 && Some(*handle) != borrowed && !expected.contains(handle) {
                            expected.push(*handle);
                        }
                    }
                }
                assert_eq!(
                    *replies.closed.borrow(),
                    expected,
                    "mode={mode} borrowed={borrowed:?}"
                );
                assert_eq!(replies.calls.get(), 1);
            }
        }
    }
}

#[test]
fn invalid_open_path_does_not_send_or_close_the_directory() {
    let replies = Replies {
        mode: 0,
        incoming: vec![8],
        borrowed: Some(7),
        closed: RefCell::new(vec![]),
        calls: Cell::new(0),
    };
    let result = Client::new(&replies).open_at(
        OpenAtBase::Directory(Handle {
            handle: 7,
            rights: mnu_abi::HANDLE_RIGHT_READ | mnu_abi::HANDLE_RIGHT_TRANSFER,
        }),
        wire::OPEN_READ,
        0,
        &"x".repeat(wire::MAX_PATH_LEN + 1),
    );
    assert!(matches!(result, Err(ClientError::Protocol(_))));
    assert_eq!(replies.calls.get(), 0);
    assert!(replies.closed.borrow().is_empty());
}
