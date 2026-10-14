use mochios_posix_client::{
    Client, ClientError, ObjectHandleAttachment, ObjectHandles, ObjectTransport, Transport,
    socket::ConnectStarted,
};
use mochios_posix_protocol::{self as protocol, socket as wire};
use std::sync::{Arc, Mutex};

struct Reply {
    status: i32,
    mismatch: bool,
    failed_transport: bool,
    payload: Vec<u8>,
    handles: Vec<ObjectHandleAttachment<u32>>,
    calls: usize,
}

impl Default for Reply {
    fn default() -> Self {
        let mut payload = [0; wire::CONNECT_REPLY_LEN];
        wire::ConnectReply::Waiting.encode(&mut payload).unwrap();
        Self {
            status: 0,
            mismatch: false,
            failed_transport: false,
            payload: payload.to_vec(),
            handles: vec![ObjectHandleAttachment {
                handle: 42,
                rights: wire::connect_job_rights(),
            }],
            calls: 0,
        }
    }
}

#[derive(Clone)]
struct Mock(Arc<Mutex<Reply>>);
impl Transport for Mock {
    type Error = ();
    fn call(&self, _: &[u8], _: &mut [u8]) -> Result<usize, ()> {
        panic!("connect requires explicit socket authority");
    }
}
impl ObjectTransport for Mock {
    type Handle = u32;
    fn call_with_handles(
        &self,
        request: &[u8],
        response: &mut [u8],
        handles: &mut ObjectHandles<u32>,
    ) -> Result<usize, ()> {
        let (header, payload) = protocol::decode(request).unwrap();
        assert_eq!(header.opcode, protocol::OP_SOCKET_CONNECT);
        assert_eq!(header.flags, 0);
        assert_eq!(
            wire::Address::decode(payload),
            Ok(wire::Address::UnixPath(b"/server"))
        );
        assert_eq!(handles.len(), 1);
        assert_eq!(
            handles.get(0),
            Some(ObjectHandleAttachment {
                handle: 7,
                rights: wire::connect_socket_rights()
            })
        );
        handles.clear();
        let mut reply = self.0.lock().unwrap();
        reply.calls += 1;
        for handle in &reply.handles {
            handles.push(*handle).unwrap();
        }
        if reply.failed_transport {
            return Err(());
        }
        protocol::encode(
            protocol::Header {
                opcode: protocol::OP_STATUS,
                request_id: header.request_id + u64::from(reply.mismatch),
                status: reply.status,
                payload_len: reply.payload.len() as u32,
                ..Default::default()
            },
            &reply.payload,
            response,
        )
        .map_err(|_| ())
    }
}

fn source() -> ObjectHandleAttachment<u32> {
    ObjectHandleAttachment {
        handle: 7,
        rights: wire::descriptor_rights(),
    }
}

#[test]
fn connection_reply_rejects_truncation_unknown_phase_and_reserved_bytes() {
    for phase in [wire::ConnectReply::Connected, wire::ConnectReply::Waiting] {
        let mut bytes = [0xff; wire::CONNECT_REPLY_LEN];
        assert_eq!(phase.encode(&mut bytes), Ok(wire::CONNECT_REPLY_LEN));
        assert_eq!(wire::ConnectReply::decode(&bytes), Ok(phase));
        for length in 0..bytes.len() {
            assert!(wire::ConnectReply::decode(&bytes[..length]).is_err());
            assert!(phase.encode(&mut bytes[..length]).is_err());
        }
        bytes[4] = 1;
        assert!(wire::ConnectReply::decode(&bytes).is_err());
    }
    assert!(wire::ConnectReply::decode(&[2, 0, 0, 0, 0, 0, 0, 0]).is_err());
    assert!(wire::ConnectReply::decode(&[0; wire::CONNECT_REPLY_LEN + 1]).is_err());
}

#[test]
fn immediate_connection_and_owned_wait_job_have_distinct_reply_shapes() {
    for pending in [false, true] {
        let mut reply = Reply::default();
        if !pending {
            wire::ConnectReply::Connected
                .encode(&mut reply.payload)
                .unwrap();
            reply.handles.clear();
        }
        let client = Client::new(Mock(Arc::new(Mutex::new(reply))));
        let result = client.connect_socket(source(), wire::Address::UnixPath(b"/server"), |_| {
            panic!("valid resource closed")
        });
        assert_eq!(
            result,
            Ok(if pending {
                ConnectStarted::Pending(ObjectHandleAttachment {
                    handle: 42,
                    rights: wire::connect_job_rights(),
                })
            } else {
                ConnectStarted::Connected
            })
        );
    }
}

#[test]
fn malformed_or_failed_replies_close_received_jobs_once_without_borrowed_authority() {
    for case in 0..9 {
        let mut reply = Reply::default();
        let expected = match case {
            0 => {
                reply.status = -11;
                ClientError::Remote(-11)
            }
            1 => {
                reply.mismatch = true;
                ClientError::MismatchedResponse
            }
            2 => {
                reply.failed_transport = true;
                ClientError::Transport(())
            }
            3 => {
                reply.payload.clear();
                ClientError::MismatchedResponse
            }
            4 => {
                reply.handles[0].rights |= mnu_abi::HANDLE_RIGHT_READ;
                ClientError::MismatchedResponse
            }
            5 => {
                reply.handles[0].rights &= !mnu_abi::HANDLE_RIGHT_WAIT;
                ClientError::MismatchedResponse
            }
            6 => {
                reply.handles.push(reply.handles[0]);
                ClientError::MismatchedResponse
            }
            7 => {
                reply.handles.push(ObjectHandleAttachment {
                    handle: 43,
                    rights: wire::connect_job_rights(),
                });
                ClientError::MismatchedResponse
            }
            _ => {
                wire::ConnectReply::Connected
                    .encode(&mut reply.payload)
                    .unwrap();
                ClientError::MismatchedResponse
            }
        };
        let client = Client::new(Mock(Arc::new(Mutex::new(reply))));
        let mut closed = Vec::new();
        assert_eq!(
            client.connect_socket(source(), wire::Address::UnixPath(b"/server"), |handle| {
                closed.push(handle)
            }),
            Err(expected),
            "case={case}"
        );
        assert_eq!(closed, if case == 7 { vec![42, 43] } else { vec![42] });
        assert!(!closed.contains(&7));
    }
}

#[test]
fn absent_wait_job_and_transport_errors_do_not_close_the_source_socket() {
    for failed_transport in [false, true] {
        let reply = Reply {
            failed_transport,
            handles: Vec::new(),
            ..Default::default()
        };
        let client = Client::new(Mock(Arc::new(Mutex::new(reply))));
        assert_eq!(
            client.connect_socket(source(), wire::Address::UnixPath(b"/server"), |_| panic!(
                "no owned reference"
            )),
            Err(if failed_transport {
                ClientError::Transport(())
            } else {
                ClientError::MismatchedResponse
            })
        );
    }
}

#[test]
fn invalid_source_or_address_never_calls_transport() {
    let state = Arc::new(Mutex::new(Reply::default()));
    let client = Client::new(Mock(state.clone()));
    for handle in [
        ObjectHandleAttachment {
            handle: 0,
            rights: wire::descriptor_rights(),
        },
        ObjectHandleAttachment {
            handle: 7,
            rights: mnu_abi::HANDLE_RIGHT_TRANSFER,
        },
    ] {
        assert_eq!(
            client.connect_socket(handle, wire::Address::UnixPath(b"/server"), |_| panic!(
                "borrowed close"
            )),
            Err(ClientError::Remote(-13))
        );
    }
    assert!(
        client
            .connect_socket(source(), wire::Address::UnixPath(b""), |_| panic!(
                "borrowed close"
            ))
            .is_err()
    );
    assert_eq!(state.lock().unwrap().calls, 0);
}
