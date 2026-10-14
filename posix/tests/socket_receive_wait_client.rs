use mochios_posix_client::{
    Client, ClientError, ObjectHandleAttachment as Handle, ObjectHandles, ObjectTransport,
    Transport,
};
use mochios_posix_protocol::{self as protocol, socket as wire};
use std::sync::{Arc, Mutex};

#[derive(Default)]
struct Reply {
    status: i32,
    mismatch: bool,
    fail: bool,
    handles: Vec<Handle<u32>>,
    calls: usize,
}
#[derive(Clone)]
struct Mock(Arc<Mutex<Reply>>);
impl Transport for Mock {
    type Error = ();
    fn call(&self, _: &[u8], _: &mut [u8]) -> Result<usize, ()> {
        panic!("explicit attachment required");
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
        assert_eq!(header.opcode, protocol::OP_SOCKET_RECEIVE_WAIT);
        assert_eq!(header.flags, 0);
        assert_eq!(payload, &3u64.to_le_bytes());
        assert_eq!(handles.len(), 1);
        assert_eq!(
            handles.get(0),
            Some(Handle {
                handle: 7,
                rights: wire::receive_wait_socket_rights()
            })
        );
        handles.clear();
        let mut reply = self.0.lock().unwrap();
        reply.calls += 1;
        for handle in &reply.handles {
            handles.push(*handle).unwrap();
        }
        if reply.fail {
            return Err(());
        }
        protocol::encode(
            protocol::Header {
                opcode: protocol::OP_STATUS,
                request_id: header.request_id + u64::from(reply.mismatch),
                status: reply.status,
                ..Default::default()
            },
            &[],
            output,
        )
        .map_err(|_| ())
    }
}
fn source() -> Handle<u32> {
    Handle {
        handle: 7,
        rights: wire::descriptor_rights(),
    }
}
fn job() -> Handle<u32> {
    Handle {
        handle: 42,
        rights: wire::receive_wait_job_rights(),
    }
}

#[test]
fn explicit_read_authority_returns_only_a_waitable_owned_notification() {
    let reply = Arc::new(Mutex::new(Reply {
        handles: vec![job()],
        ..Default::default()
    }));
    let client = Client::new(Mock(reply.clone()));
    assert_eq!(
        client.wait_socket_receive(source(), 3, |_| panic!("valid Handle closed")),
        Ok(job())
    );
    assert_eq!(reply.lock().unwrap().calls, 1);
    assert_eq!(
        wire::receive_wait_job_rights()
            & (mnu_abi::HANDLE_RIGHT_READ
                | mnu_abi::HANDLE_RIGHT_WRITE
                | mnu_abi::HANDLE_RIGHT_CONTROL),
        0
    );
}

#[test]
fn missing_read_transfer_authority_zero_minimum_and_null_handle_never_send() {
    let reply = Arc::new(Mutex::new(Reply::default()));
    let client = Client::new(Mock(reply.clone()));
    for right in [mnu_abi::HANDLE_RIGHT_READ, mnu_abi::HANDLE_RIGHT_TRANSFER] {
        let mut socket = source();
        socket.rights &= !right;
        assert_eq!(
            client.wait_socket_receive(socket, 3, |_| panic!()),
            Err(ClientError::Remote(-13))
        );
    }
    assert_eq!(
        client.wait_socket_receive(
            Handle {
                handle: 0,
                ..source()
            },
            3,
            |_| panic!()
        ),
        Err(ClientError::Remote(-13))
    );
    assert_eq!(
        client.wait_socket_receive(source(), 0, |_| panic!()),
        Err(ClientError::Remote(-22))
    );
    assert_eq!(reply.lock().unwrap().calls, 0);
}

#[test]
fn malformed_remote_failed_and_transport_replies_release_received_resources_once() {
    for case in 0..7 {
        let mut reply = Reply {
            handles: vec![job()],
            ..Default::default()
        };
        match case {
            0 => reply.mismatch = true,
            1 => reply.fail = true,
            2 => reply.status = -23,
            3 => reply.handles.push(job()),
            4 => reply.handles[0].rights |= mnu_abi::HANDLE_RIGHT_CONTROL,
            5 => reply.handles.clear(),
            6 => reply.handles[0].handle = 0,
            _ => unreachable!(),
        }
        let client = Client::new(Mock(Arc::new(Mutex::new(reply))));
        let mut closed = Vec::new();
        assert!(
            client
                .wait_socket_receive(source(), 3, |h| closed.push(h))
                .is_err()
        );
        assert_eq!(closed, if case >= 5 { vec![] } else { vec![42] });
    }
}
