use mochios_posix_client::{
    Client, ClientError, ObjectHandleAttachment, ObjectHandles, ObjectTransport, Transport,
};
use mochios_posix_protocol::{
    self as protocol,
    socket::{self as wire, Accept, Address},
};
use std::sync::{Arc, Mutex};

struct Reply {
    status: i32,
    mismatch: bool,
    transport_error: bool,
    payload: Vec<u8>,
    handles: Vec<ObjectHandleAttachment<u32>>,
    calls: usize,
}
impl Default for Reply {
    fn default() -> Self {
        let mut address = [0; wire::MAX_ADDRESS_LEN];
        let count = Address::UnixPath(b"/peer").encode(&mut address).unwrap();
        Self {
            status: 0,
            mismatch: false,
            transport_error: false,
            payload: address[..count].to_vec(),
            handles: vec![ObjectHandleAttachment {
                handle: 42,
                rights: wire::descriptor_rights(),
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
        panic!("accept must attach a listener Handle");
    }
}
impl ObjectTransport for Mock {
    type Handle = u32;

    fn close_received_handle(&self, _: u32) {
        panic!("unexpected owned reply Handle in this fixture");
    }
    fn call_with_handles(
        &self,
        bytes: &[u8],
        response: &mut [u8],
        handles: &mut ObjectHandles<u32>,
    ) -> Result<usize, ()> {
        let (header, payload) = protocol::decode(bytes).unwrap();
        assert_eq!(header.opcode, protocol::OP_SOCKET_ACCEPT);
        assert_eq!(header.flags, 0);
        assert_eq!(
            Accept::decode(payload),
            Ok(Accept {
                options: wire::NONBLOCKING
            })
        );
        assert_eq!(handles.len(), 1);
        assert_eq!(
            handles.get(0),
            Some(ObjectHandleAttachment {
                handle: 7,
                rights: wire::accept_listener_rights()
            })
        );
        handles.clear(); // Incoming listener is borrowed, not a reply reference.
        let mut reply = self.0.lock().unwrap();
        reply.calls += 1;
        for handle in &reply.handles {
            handles.push(*handle).unwrap();
        }
        if reply.transport_error {
            return Err(());
        }
        Ok(protocol::encode(
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
        .unwrap())
    }
}
fn listener() -> ObjectHandleAttachment<u32> {
    ObjectHandleAttachment {
        handle: 7,
        rights: wire::descriptor_rights(),
    }
}

#[test]
fn accept_payload_contains_only_new_description_options_and_rejects_reserved_bytes() {
    for options in [0, wire::NONBLOCKING] {
        let request = Accept { options };
        let mut bytes = [0xff; wire::ACCEPT_LEN];
        assert_eq!(request.encode(&mut bytes), Ok(wire::ACCEPT_LEN));
        assert_eq!(Accept::decode(&bytes), Ok(request));
        assert_eq!(&bytes[4..], &[0; 4]);
        for length in 0..wire::ACCEPT_LEN {
            assert!(Accept::decode(&bytes[..length]).is_err());
        }
        bytes[4] = 1;
        assert!(Accept::decode(&bytes).is_err());
    }
    let mut bytes = [0xff; wire::ACCEPT_LEN];
    assert!(Accept { options: 2 }.encode(&mut bytes).is_err());
    assert_eq!(bytes, [0xff; wire::ACCEPT_LEN]);
}

#[test]
fn accept_returns_a_new_owned_socket_and_copies_peer_address_bytes() {
    let state = Arc::new(Mutex::new(Reply::default()));
    let client = Client::new(Mock(state.clone()));
    let mut closed = Vec::new();
    let accepted = client
        .accept_socket(
            listener(),
            Accept {
                options: wire::NONBLOCKING,
            },
            |handle| closed.push(handle),
        )
        .unwrap();
    assert_eq!(accepted.socket.handle, 42);
    assert_eq!(accepted.socket.rights, wire::descriptor_rights());
    assert_eq!(accepted.peer_address(), Ok(Address::UnixPath(b"/peer")));
    state.lock().unwrap().payload.fill(0);
    assert_eq!(accepted.peer_address(), Ok(Address::UnixPath(b"/peer")));
    assert!(closed.is_empty());
}

#[test]
fn malformed_and_failed_replies_reclaim_every_owned_reference_once() {
    for case in 0..7 {
        let mut reply = Reply::default();
        let expected_error = match case {
            0 => {
                reply.status = -11;
                Some(ClientError::Remote(-11))
            }
            1 => {
                reply.mismatch = true;
                Some(ClientError::MismatchedResponse)
            }
            2 => {
                reply.transport_error = true;
                Some(ClientError::Transport(()))
            }
            3 => {
                reply.payload.clear();
                Some(ClientError::MismatchedResponse)
            }
            4 => {
                reply.handles[0].rights |= mnu_abi::HANDLE_RIGHT_MAP;
                Some(ClientError::MismatchedResponse)
            }
            5 => {
                reply.handles.push(reply.handles[0]);
                Some(ClientError::MismatchedResponse)
            }
            _ => {
                reply.handles.push(ObjectHandleAttachment {
                    handle: 43,
                    rights: wire::descriptor_rights(),
                });
                Some(ClientError::MismatchedResponse)
            }
        };
        let client = Client::new(Mock(Arc::new(Mutex::new(reply))));
        let mut closed = Vec::new();
        let result = client.accept_socket(
            listener(),
            Accept {
                options: wire::NONBLOCKING,
            },
            |handle| closed.push(handle),
        );
        assert_eq!(result.err(), expected_error, "case={case}");
        assert_eq!(
            closed,
            if case == 6 { vec![42, 43] } else { vec![42] },
            "case={case}"
        );
        assert!(!closed.contains(&7));
    }
}

#[test]
fn empty_queue_and_transport_failures_never_close_the_borrowed_listener() {
    for failed_transport in [false, true] {
        let reply = Reply {
            status: -11,
            transport_error: failed_transport,
            handles: Vec::new(),
            payload: Vec::new(),
            ..Default::default()
        };
        let client = Client::new(Mock(Arc::new(Mutex::new(reply))));
        let mut closed = Vec::new();
        let result = client.accept_socket(
            listener(),
            Accept {
                options: wire::NONBLOCKING,
            },
            |handle| closed.push(handle),
        );
        assert_eq!(
            result.err(),
            Some(if failed_transport {
                ClientError::Transport(())
            } else {
                ClientError::Remote(-11)
            })
        );
        assert!(closed.is_empty());
    }
}

#[test]
fn invalid_authority_or_options_are_rejected_before_ipc() {
    let state = Arc::new(Mutex::new(Reply::default()));
    let client = Client::new(Mock(state.clone()));
    for source in [
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
            client
                .accept_socket(source, Accept { options: 0 }, |_| panic!(
                    "borrowed reference closed"
                ))
                .err(),
            Some(ClientError::Remote(-13))
        );
    }
    assert!(
        client
            .accept_socket(listener(), Accept { options: 2 }, |_| panic!(
                "borrowed reference closed"
            ))
            .is_err()
    );
    assert_eq!(state.lock().unwrap().calls, 0);
}
