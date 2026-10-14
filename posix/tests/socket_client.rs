use mochios_posix_client::{
    Client, ClientError, ObjectHandleAttachment, ObjectHandles, ObjectTransport, Transport,
};
use mochios_posix_protocol::{
    self as protocol,
    socket::{self as wire, Create, Domain, Kind},
};
use std::sync::{Arc, Mutex};

#[derive(Default)]
struct Reply {
    status: i32,
    mismatch: bool,
    transport_error: bool,
    payload: Vec<u8>,
    attachments: Vec<ObjectHandleAttachment<u32>>,
    calls: usize,
}
#[derive(Clone)]
struct Mock(Arc<Mutex<Reply>>);
impl Transport for Mock {
    type Error = ();
    fn call(&self, _: &[u8], _: &mut [u8]) -> Result<usize, ()> {
        panic!("socket creation requires Handle-aware IPC")
    }
}
impl ObjectTransport for Mock {
    type Handle = u32;
    fn call_with_handles(
        &self,
        request: &[u8],
        output: &mut [u8],
        handles: &mut ObjectHandles<u32>,
    ) -> Result<usize, ()> {
        let (header, payload) = protocol::decode(request).unwrap();
        assert_eq!(header.opcode, protocol::OP_SOCKET_PAIR);
        assert_eq!(header.flags, 0);
        assert_eq!(Create::decode(payload).unwrap(), request_create());
        assert!(handles.is_empty());
        let mut reply = self.0.lock().unwrap();
        reply.calls += 1;
        for attachment in &reply.attachments {
            handles.push(*attachment).unwrap();
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
            output,
        )
        .unwrap())
    }
}
fn request_create() -> Create {
    Create {
        domain: Domain::Unix,
        kind: Kind::Stream,
        protocol: 0,
        options: wire::NONBLOCKING,
    }
}
fn pair() -> [ObjectHandleAttachment<u32>; 2] {
    [
        ObjectHandleAttachment {
            handle: 7,
            rights: wire::descriptor_rights(),
        },
        ObjectHandleAttachment {
            handle: 8,
            rights: wire::descriptor_rights(),
        },
    ]
}

#[test]
fn successful_pair_transfers_both_handles_without_closing_them() {
    let state = Arc::new(Mutex::new(Reply {
        attachments: pair().to_vec(),
        ..Default::default()
    }));
    let client = Client::new(Mock(state.clone()));
    let mut closed = Vec::new();
    assert_eq!(
        client.socket_pair(request_create(), |handle| closed.push(handle)),
        Ok(pair())
    );
    assert!(closed.is_empty());
    assert_eq!(state.lock().unwrap().calls, 1);
}

#[test]
fn every_failed_or_malformed_reply_releases_all_owned_attachments() {
    let state = Arc::new(Mutex::new(Reply::default()));
    let client = Client::new(Mock(state.clone()));
    for case in 0..10 {
        let mut reply = Reply {
            attachments: pair().to_vec(),
            ..Default::default()
        };
        match case {
            0 => reply.status = -13,
            1 => reply.mismatch = true,
            2 => reply.transport_error = true,
            3 => reply.payload = vec![0],
            4 => reply.attachments.clear(),
            5 => {
                reply.attachments.pop();
            }
            6 => reply.attachments.push(ObjectHandleAttachment {
                handle: 9,
                rights: wire::descriptor_rights(),
            }),
            7 => reply.attachments[0].rights |= mnu_abi::HANDLE_RIGHT_MAP,
            8 => reply.attachments[1].rights &= !mnu_abi::HANDLE_RIGHT_WAIT,
            _ => reply.attachments[1].handle = reply.attachments[0].handle,
        }
        let mut expected: Vec<_> = reply
            .attachments
            .iter()
            .map(|attachment| attachment.handle)
            .collect();
        expected.dedup();
        *state.lock().unwrap() = reply;
        let mut closed = Vec::new();
        let result = client.socket_pair(request_create(), |handle| closed.push(handle));
        assert!(result.is_err(), "case={case}");
        assert_eq!(closed, expected, "case={case}");
        if case == 0 {
            assert_eq!(result, Err(ClientError::Remote(-13)));
        }
        if case == 2 {
            assert_eq!(result, Err(ClientError::Transport(())));
        }
    }
}

#[test]
fn invalid_request_options_are_rejected_before_allocating_remote_resources() {
    let state = Arc::new(Mutex::new(Reply::default()));
    let client = Client::new(Mock(state.clone()));
    let mut closed = Vec::new();
    assert!(
        client
            .socket_pair(
                Create {
                    options: 2,
                    ..request_create()
                },
                |handle| closed.push(handle)
            )
            .is_err()
    );
    assert_eq!(state.lock().unwrap().calls, 0);
    assert!(closed.is_empty());
}
