use mochios_posix_client::{
    Client, ClientError, ObjectHandleAttachment as Handle, ObjectHandles, ObjectTransport,
    Transport,
};
use mochios_posix_protocol as wire;
use std::cell::{Cell, RefCell};

struct Replies {
    mode: u8,
    incoming: Vec<u32>,
    closed: RefCell<Vec<u32>>,
    calls: Cell<usize>,
}
impl Transport for &Replies {
    type Error = u8;
    fn call(&self, _: &[u8], _: &mut [u8]) -> Result<usize, u8> {
        panic!("explicit Handle required")
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
        let (header, _) = wire::decode(input).unwrap();
        assert_eq!(handles.len(), 1);
        assert_eq!(handles.get(0).unwrap().handle, 7);
        self.calls.set(self.calls.get() + 1);
        handles.clear();
        for handle in &self.incoming {
            handles
                .push(Handle {
                    handle: *handle,
                    rights: 1,
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
        let payload = match header.opcode {
            wire::OP_FGETFL => vec![0; wire::FILE_FLAGS_PAYLOAD_LEN],
            wire::OP_FSTAT => vec![0; wire::FILE_STATUS_LEN],
            _ => vec![],
        };
        wire::encode(
            wire::Header {
                opcode: if self.mode == 6 {
                    wire::OP_PING
                } else {
                    wire::OP_STATUS
                },
                request_id: header.request_id + u64::from(self.mode == 4),
                payload_len: payload.len() as u32,
                status: if self.mode == 5 { -13 } else { 0 },
                ..Default::default()
            },
            &payload,
            output,
        )
        .map_err(|_| 99)
    }
}

fn invoke(client: &Client<&Replies>, opcode: u16) -> Result<(), ClientError<u8>> {
    let file = Handle {
        handle: 7,
        rights: mnu_abi::HANDLE_RIGHT_ALL,
    };
    match opcode {
        wire::OP_FTRUNCATE => client.ftruncate(file, 5),
        wire::OP_FSYNC => client.fsync(file),
        wire::OP_FCHMOD => client.fchmod(file, 0o600),
        wire::OP_FCHOWN => client.fchown(file, 1, 2),
        wire::OP_FSETFL => client.set_status_flags(file, wire::OPEN_NONBLOCK),
        wire::OP_FGETFL => client.get_status_flags(file).map(|_| ()),
        wire::OP_FSTAT => client.fstat(file).map(|_| ()),
        _ => unreachable!(),
    }
}

#[test]
fn every_file_reply_is_drained_once_without_closing_the_borrowed_source_or_replaying() {
    for opcode in [
        wire::OP_FTRUNCATE,
        wire::OP_FSYNC,
        wire::OP_FCHMOD,
        wire::OP_FCHOWN,
        wire::OP_FSETFL,
        wire::OP_FGETFL,
        wire::OP_FSTAT,
    ] {
        for mode in 0..7 {
            for incoming in [vec![], vec![8], vec![8, 8, 9, 0], vec![7, 8, 7, 0]] {
                let replies = Replies {
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
                    2 => assert_eq!(result, Err(ClientError::ResponseTooLarge)),
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
