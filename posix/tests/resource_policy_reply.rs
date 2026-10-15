use mochios_posix_client::{
    Client, ClientError, ObjectHandleAttachment as Handle, ObjectHandles, ObjectTransport,
    Transport,
};
use mochios_posix_protocol as wire;
use std::cell::RefCell;

struct Replies {
    mode: u8,
    incoming: Vec<Handle<u32>>,
    closed: RefCell<Vec<u32>>,
}
impl Transport for &Replies {
    type Error = i32;
    fn call(&self, _: &[u8], _: &mut [u8]) -> Result<usize, i32> {
        panic!("object IPC required")
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
    ) -> Result<usize, i32> {
        let (header, payload) = wire::decode(input).unwrap();
        assert_eq!(header.opcode, wire::OP_RESOURCE_POLICY);
        assert_eq!(header.flags, 0);
        assert!(payload.is_empty() && handles.is_empty());
        for handle in &self.incoming {
            handles.push(*handle).unwrap();
        }
        match self.mode {
            1 => return Err(42),
            2 => return Ok(output.len() + 1),
            3 => {
                output[0] = 0;
                return Ok(1);
            }
            _ => {}
        }
        let payload = if self.mode == 7 { &[1][..] } else { &[][..] };
        wire::encode(
            wire::Header {
                opcode: if self.mode == 6 {
                    wire::OP_PING
                } else {
                    wire::OP_STATUS
                },
                request_id: header.request_id + u64::from(self.mode == 4),
                status: if self.mode == 5 { -22 } else { 0 },
                payload_len: payload.len() as u32,
                ..Default::default()
            },
            payload,
            output,
        )
        .map_err(|_| -5)
    }
}
fn reader(handle: u32) -> Handle<u32> {
    Handle {
        handle,
        rights: wire::resource_policy::READER_RIGHTS,
    }
}

#[test]
fn reader_offers_require_one_exact_read_map_handle_and_drain_all_failures() {
    for mode in 0..8 {
        for incoming in [
            vec![],
            vec![reader(8)],
            vec![reader(0)],
            vec![reader(8), reader(8), reader(9), reader(0)],
            vec![Handle {
                handle: 8,
                rights: mnu_abi::HANDLE_RIGHT_ALL,
            }],
        ] {
            let valid = incoming == [reader(8)];
            let replies = Replies {
                mode,
                incoming,
                closed: RefCell::new(vec![]),
            };
            let result = Client::new(&replies).resource_policy_handle();
            match mode {
                0 if valid => assert_eq!(result, Ok(reader(8))),
                0 | 4 | 6 => assert_eq!(result, Err(ClientError::MismatchedResponse)),
                1 => assert_eq!(result, Err(ClientError::Transport(42))),
                2 | 7 => assert_eq!(result, Err(ClientError::ResponseTooLarge)),
                3 => assert!(matches!(result, Err(ClientError::Protocol(_)))),
                5 => assert_eq!(result, Err(ClientError::Remote(-22))),
                _ => unreachable!(),
            }
            let mut expected = Vec::new();
            if !(mode == 0 && valid) {
                for handle in &replies.incoming {
                    if handle.handle != 0 && !expected.contains(&handle.handle) {
                        expected.push(handle.handle);
                    }
                }
            }
            assert_eq!(*replies.closed.borrow(), expected);
        }
    }
}
