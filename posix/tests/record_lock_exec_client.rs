use mochios_posix_client::{
    Client, ClientError, ObjectHandleAttachment, ObjectHandles, ObjectTransport, Transport,
};
use mochios_posix_protocol::{self as protocol, record_lock_exec as wire};
use std::cell::{Cell, RefCell};

struct Backend {
    token: Cell<u64>,
    extra: Cell<bool>,
    calls: Cell<usize>,
    closed: RefCell<Vec<u32>>,
}
impl Transport for Backend {
    type Error = ();
    fn call(&self, _: &[u8], _: &mut [u8]) -> Result<usize, ()> {
        panic!("object IPC required")
    }
}
impl ObjectTransport for Backend {
    type Handle = u32;
    fn close_received_handle(&self, handle: u32) {
        self.closed.borrow_mut().push(handle);
    }
    fn call_with_handles(
        &self,
        bytes: &[u8],
        response: &mut [u8],
        objects: &mut ObjectHandles<u32>,
    ) -> Result<usize, ()> {
        let (header, bytes) = protocol::decode(bytes).unwrap();
        assert_eq!(header.opcode, protocol::OP_RECORD_LOCK_EXEC);
        match wire::decode(bytes).unwrap() {
            wire::Request::Prepare(_) => {
                assert!(objects.len() > 0);
                for index in 0..objects.len() {
                    assert_eq!(
                        objects.get(index).unwrap().rights,
                        mnu_abi::HANDLE_RIGHT_TRANSFER
                    );
                }
            }
            wire::Request::Cancel(_) => assert!(objects.is_empty()),
        }
        self.calls.set(self.calls.get() + 1);
        objects.clear();
        if self.extra.get() {
            objects
                .push(ObjectHandleAttachment {
                    handle: 99,
                    rights: mnu_abi::HANDLE_RIGHT_READ,
                })
                .unwrap();
        }
        let mut reply = [0; wire::LEN];
        wire::encode_reply(self.token.get(), &mut reply).unwrap();
        protocol::encode(
            protocol::Header {
                opcode: protocol::OP_STATUS,
                request_id: header.request_id,
                payload_len: reply.len() as u32,
                ..Default::default()
            },
            &reply,
            response,
        )
        .map_err(|_| ())
    }
}
fn client() -> Client<Backend> {
    Client::new(Backend {
        token: Cell::new(71),
        extra: Cell::new(false),
        calls: Cell::new(0),
        closed: RefCell::new(Vec::new()),
    })
}
fn file() -> ObjectHandleAttachment<u32> {
    ObjectHandleAttachment {
        handle: 81,
        rights: u64::MAX,
    }
}

#[test]
fn codec_checks_versions_lengths_operations_reserved_bytes_and_zero_cancellation() {
    for request in [
        wire::Request::Prepare(0),
        wire::Request::Prepare(u64::MAX),
        wire::Request::Cancel(1),
    ] {
        let mut bytes = [0xa5; wire::LEN + 1];
        wire::encode(request, &mut bytes).unwrap();
        assert_eq!(bytes[wire::LEN], 0xa5);
        assert_eq!(wire::decode(&bytes[..wire::LEN]), Ok(request));
        assert!(wire::decode(&bytes).is_err());
        for len in 0..wire::LEN {
            assert!(wire::decode(&bytes[..len]).is_err());
        }
        for index in 0..8 {
            let mut invalid = bytes;
            invalid[index] = 0xff;
            assert!(wire::decode(&invalid[..wire::LEN]).is_err());
        }
    }
    let mut bytes = [0xa5; wire::LEN];
    assert!(wire::encode(wire::Request::Cancel(0), &mut bytes).is_err());
    assert_eq!(bytes, [0xa5; wire::LEN]);
    for len in 0..wire::LEN {
        assert!(wire::encode(wire::Request::Prepare(1), &mut bytes[..len]).is_err());
        assert!(wire::encode_reply(1, &mut bytes[..len]).is_err());
        assert_eq!(bytes, [0xa5; wire::LEN]);
    }
    for token in [0, 1, u64::MAX] {
        wire::encode_reply(token, &mut bytes).unwrap();
        assert_eq!(wire::decode_reply(&bytes), Ok(token));
        for index in 0..8 {
            let mut invalid = bytes;
            invalid[index] = 0xff;
            assert!(wire::decode_reply(&invalid).is_err());
        }
    }
}

#[test]
fn batches_attenuate_files_and_require_matching_preparation_tokens() {
    let client = client();
    assert_eq!(
        client.prepare_record_lock_exec(&[file(); 4], None),
        Ok(Some(71))
    );
    assert_eq!(
        client.prepare_record_lock_exec(&[file()], Some(71)),
        Ok(Some(71))
    );
    client.transport().token.set(72);
    assert_eq!(
        client.prepare_record_lock_exec(&[file()], Some(71)),
        Err(ClientError::MismatchedResponse)
    );
    client.transport().token.set(0);
    assert_eq!(client.prepare_record_lock_exec(&[file()], None), Ok(None));
    assert_eq!(
        client.prepare_record_lock_exec(&[file()], Some(71)),
        Err(ClientError::MismatchedResponse)
    );
    client.cancel_record_lock_exec(71).unwrap();
    client.transport().token.set(71);
    assert_eq!(
        client.cancel_record_lock_exec(71),
        Err(ClientError::MismatchedResponse)
    );
}

#[test]
fn invalid_batches_and_missing_authority_do_not_issue_ipc_and_owned_reply_handles_are_closed() {
    let client = client();
    assert!(client.prepare_record_lock_exec(&[], None).is_err());
    assert!(client.prepare_record_lock_exec(&[file(); 5], None).is_err());
    assert!(client.prepare_record_lock_exec(&[file()], Some(0)).is_err());
    assert!(client.cancel_record_lock_exec(0).is_err());
    assert_eq!(
        client.prepare_record_lock_exec(
            &[ObjectHandleAttachment {
                handle: 81,
                rights: mnu_abi::HANDLE_RIGHT_READ
            }],
            None
        ),
        Err(ClientError::Remote(-13))
    );
    assert_eq!(client.transport().calls.get(), 0);
    client.transport().extra.set(true);
    assert_eq!(
        client.prepare_record_lock_exec(&[file()], None),
        Err(ClientError::MismatchedResponse)
    );
    assert_eq!(*client.transport().closed.borrow(), [99]);
}
