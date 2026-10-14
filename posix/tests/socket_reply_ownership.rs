use mochios_posix_client::{
    Client, ClientError, ObjectHandleAttachment as Handle, ObjectHandles, ObjectTransport,
    Transport,
};
use mochios_posix_protocol::{self as protocol, socket as wire};
use std::cell::Cell;

struct Replies {
    opcode: u16,
    mode: u8,
    incoming: Vec<u32>,
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
    fn close_received_handle(&self, _: u32) {
        panic!("explicit cleanup callback owns replies")
    }
    fn call_with_handles(
        &self,
        input: &[u8],
        output: &mut [u8],
        handles: &mut ObjectHandles<u32>,
    ) -> Result<usize, u8> {
        let (header, _) = protocol::decode(input).unwrap();
        assert_eq!(header.opcode, self.opcode);
        if has_borrow(self.opcode) {
            assert_eq!(handles.len(), 1);
            assert_eq!(handles.get(0).unwrap().handle, 7);
        } else {
            assert!(handles.is_empty());
        }
        self.calls.set(self.calls.get() + 1);
        handles.clear();
        let rights = reply_rights(self.opcode);
        for handle in &self.incoming {
            handles
                .push(Handle {
                    handle: *handle,
                    rights,
                })
                .unwrap();
        }
        if self.mode == 1 {
            return Err(42);
        }
        if self.mode == 4 {
            return Ok(output.len() + 1);
        }
        if self.mode == 5 {
            output[0] = 0;
            return Ok(1);
        }
        let mut payload = vec![0; wire::MAX_ADDRESS_LEN];
        let length = match self.opcode {
            protocol::OP_SOCKET_CONNECT => {
                wire::ConnectReply::Waiting.encode(&mut payload).unwrap()
            }
            protocol::OP_SOCKET_ACCEPT => wire::Address::UnixUnnamed.encode(&mut payload).unwrap(),
            _ => 0,
        };
        protocol::encode(
            protocol::Header {
                opcode: if self.mode == 6 {
                    protocol::OP_PING
                } else {
                    protocol::OP_STATUS
                },
                request_id: header.request_id + u64::from(self.mode == 3),
                status: if self.mode == 2 { -13 } else { 0 },
                payload_len: length as u32,
                ..Default::default()
            },
            &payload[..length],
            output,
        )
        .map_err(|_| 99)
    }
}
fn has_borrow(opcode: u16) -> bool {
    !matches!(
        opcode,
        protocol::OP_SOCKET_CREATE | protocol::OP_SOCKET_PAIR
    )
}
fn reply_rights(opcode: u16) -> u64 {
    match opcode {
        protocol::OP_SOCKET_CONNECT => wire::connect_job_rights(),
        protocol::OP_SOCKET_RECEIVE_WAIT => wire::receive_wait_job_rights(),
        _ => wire::descriptor_rights(),
    }
}

#[test]
fn socket_creation_and_jobs_preserve_borrows_and_release_owned_failed_replies_once() {
    for opcode in [
        protocol::OP_SOCKET_CREATE,
        protocol::OP_SOCKET_PAIR,
        protocol::OP_SOCKET_ACCEPT,
        protocol::OP_SOCKET_CONNECT,
        protocol::OP_SOCKET_RECEIVE_WAIT,
    ] {
        for mode in 0..7 {
            for incoming in [
                vec![],
                vec![0],
                vec![7],
                vec![8],
                vec![8, 8],
                vec![0, 8],
                vec![8, 9],
                vec![7, 8, 7, 0],
            ] {
                let replies = Replies {
                    opcode,
                    mode,
                    incoming,
                    calls: Cell::new(0),
                };
                let client = Client::new(&replies);
                let socket = Handle {
                    handle: 7,
                    rights: wire::descriptor_rights(),
                };
                let create = wire::Create {
                    domain: wire::Domain::Unix,
                    kind: wire::Kind::Stream,
                    protocol: 0,
                    options: 0,
                };
                let mut closed = vec![];
                let result = match opcode {
                    protocol::OP_SOCKET_CREATE => client
                        .open_socket(create, |handle| closed.push(handle))
                        .map(|handle| vec![handle]),
                    protocol::OP_SOCKET_PAIR => client
                        .socket_pair(create, |handle| closed.push(handle))
                        .map(|pair| pair.to_vec()),
                    protocol::OP_SOCKET_ACCEPT => client
                        .accept_socket(socket, wire::Accept { options: 0 }, |handle| {
                            closed.push(handle)
                        })
                        .map(|accepted| vec![accepted.socket]),
                    protocol::OP_SOCKET_CONNECT => client
                        .connect_socket(socket, wire::Address::UnixPath(b"/server"), |handle| {
                            closed.push(handle)
                        })
                        .map(|started| match started {
                            mochios_posix_client::socket::ConnectStarted::Pending(handle) => {
                                vec![handle]
                            }
                            _ => panic!("expected a pending job"),
                        }),
                    _ => client
                        .wait_socket_receive(socket, 3, |handle| closed.push(handle))
                        .map(|handle| vec![handle]),
                };
                let accepted = mode == 0
                    && if opcode == protocol::OP_SOCKET_PAIR {
                        replies.incoming == [8, 9]
                    } else {
                        replies.incoming.len() == 1
                            && replies.incoming[0] != 0
                            && (!has_borrow(opcode) || replies.incoming[0] != 7)
                    };
                match mode {
                    0 if accepted => assert_eq!(
                        result,
                        Ok(replies
                            .incoming
                            .iter()
                            .map(|handle| Handle {
                                handle: *handle,
                                rights: reply_rights(opcode)
                            })
                            .collect())
                    ),
                    0 | 3 | 6 => assert_eq!(result, Err(ClientError::MismatchedResponse)),
                    1 => assert_eq!(result, Err(ClientError::Transport(42))),
                    2 => assert_eq!(result, Err(ClientError::Remote(-13))),
                    4 => assert_eq!(result, Err(ClientError::ResponseTooLarge)),
                    5 => assert!(matches!(result, Err(ClientError::Protocol(_)))),
                    _ => unreachable!(),
                }
                let mut expected = vec![];
                if !accepted {
                    for handle in &replies.incoming {
                        if *handle != 0
                            && (!has_borrow(opcode) || *handle != 7)
                            && !expected.contains(handle)
                        {
                            expected.push(*handle);
                        }
                    }
                }
                assert_eq!(closed, expected, "opcode={opcode} mode={mode}");
                assert_eq!(replies.calls.get(), 1);
            }
        }
    }
}
