use mochios_posix_client::{
    Client, ClientError, ObjectHandleAttachment, ObjectHandles, ObjectTransport, Transport,
};
use mochios_posix_protocol::{
    self as protocol,
    record_lock::{self as wire, Kind, Operation, Origin, Reply, Request},
};
use std::cell::{Cell, RefCell};

struct Backend {
    reply: Cell<Reply>,
    unexpected: Cell<bool>,
    malformed: Cell<bool>,
    calls: RefCell<Vec<(Request, u64)>>,
    closed: RefCell<Vec<u32>>,
    epochs: RefCell<Vec<u64>>,
}
impl Transport for Backend {
    type Error = ();
    fn call(&self, _: &[u8], _: &mut [u8]) -> Result<usize, ()> {
        panic!("object transport required")
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
        handles: &mut ObjectHandles<u32>,
    ) -> Result<usize, ()> {
        let (header, payload) = protocol::decode(bytes).unwrap();
        let request = if header.opcode == protocol::OP_RECORD_LOCK_WAIT {
            let wait = protocol::record_lock_wait::decode(payload).unwrap();
            self.epochs.borrow_mut().push(wait.epoch);
            wait.lock
        } else {
            assert_eq!(header.opcode, protocol::OP_RECORD_LOCK);
            wire::decode_request(payload).unwrap()
        };
        assert_eq!(handles.len(), 1);
        let file = handles.get(0).unwrap();
        assert_eq!(file.handle, 71);
        self.calls.borrow_mut().push((request, file.rights));
        handles.clear();
        if self.unexpected.get() {
            handles
                .push(ObjectHandleAttachment {
                    handle: 99,
                    rights: mnu_abi::HANDLE_RIGHT_TRANSFER,
                })
                .unwrap();
        }
        let mut payload = [0; wire::REPLY_LEN];
        wire::encode_reply(self.reply.get(), &mut payload).unwrap();
        if self.malformed.get() {
            payload[7] = 1;
        }
        protocol::encode(
            protocol::Header {
                opcode: protocol::OP_STATUS,
                request_id: header.request_id,
                payload_len: payload.len() as u32,
                ..Default::default()
            },
            &payload,
            response,
        )
        .map_err(|_| ())
    }
}
fn client(reply: Reply) -> Client<Backend> {
    Client::new(Backend {
        reply: Cell::new(reply),
        unexpected: Cell::new(false),
        malformed: Cell::new(false),
        calls: RefCell::new(Vec::new()),
        closed: RefCell::new(Vec::new()),
        epochs: RefCell::new(Vec::new()),
    })
}
fn request(operation: Operation) -> Request {
    Request {
        operation,
        origin: Origin::Start,
        start: 0,
        length: 0,
    }
}
fn file(rights: u64) -> ObjectHandleAttachment<u32> {
    ObjectHandleAttachment { handle: 71, rights }
}

#[test]
fn attaches_only_the_authority_required_by_each_operation() {
    let client = client(Reply::Done);
    for operation in [
        Operation::Set(Kind::Read),
        Operation::Set(Kind::Write),
        Operation::Unlock,
        Operation::ReleaseFile,
        Operation::Query(Kind::Read),
    ] {
        let request = request(operation);
        client
            .transport()
            .reply
            .set(if matches!(operation, Operation::Query(_)) {
                Reply::Unlocked
            } else {
                Reply::Done
            });
        client.record_lock(file(u64::MAX), request).unwrap();
        assert_eq!(
            client.transport().calls.borrow().last(),
            Some(&(request, wire::required_rights(request)))
        );
    }
    let request = Request {
        origin: Origin::Current,
        ..request(Operation::Set(Kind::Read))
    };
    client.transport().reply.set(Reply::Done);
    client.record_lock(file(u64::MAX), request).unwrap();
    assert_eq!(
        client.transport().calls.borrow().last().unwrap().1,
        mnu_abi::HANDLE_RIGHT_READ | mnu_abi::HANDLE_RIGHT_SEEK | mnu_abi::HANDLE_RIGHT_TRANSFER
    );
}

#[test]
fn missing_data_transfer_or_seek_rights_never_issue_a_request() {
    let client = client(Reply::Done);
    let request = Request {
        origin: Origin::Current,
        ..request(Operation::Set(Kind::Write))
    };
    let required = wire::required_rights(request);
    for right in [
        mnu_abi::HANDLE_RIGHT_WRITE,
        mnu_abi::HANDLE_RIGHT_SEEK,
        mnu_abi::HANDLE_RIGHT_TRANSFER,
    ] {
        assert_eq!(
            client.record_lock(file(required & !right), request),
            Err(ClientError::Remote(-13))
        );
    }
    assert!(client.transport().calls.borrow().is_empty());
}

#[test]
fn query_results_and_mutation_results_are_not_interchangeable() {
    let client = client(Reply::Done);
    assert_eq!(
        client.record_lock(file(u64::MAX), request(Operation::Query(Kind::Read))),
        Err(ClientError::MismatchedResponse)
    );
    client.transport().reply.set(Reply::Unlocked);
    assert_eq!(
        client.record_lock(file(u64::MAX), request(Operation::Set(Kind::Read))),
        Err(ClientError::MismatchedResponse)
    );
    client.transport().reply.set(Reply::Conflict {
        owner: 70_000,
        kind: Kind::Write,
        start: 3,
        length: 0,
    });
    assert!(matches!(
        client.record_lock(file(u64::MAX), request(Operation::Query(Kind::Read))),
        Ok(Reply::Conflict { owner: 70_000, .. })
    ));
}

#[test]
fn malformed_scalar_replies_and_unexpected_owned_handles_are_rejected_and_closed() {
    let client = client(Reply::Done);
    client.transport().malformed.set(true);
    assert!(matches!(
        client.record_lock(file(u64::MAX), request(Operation::Unlock)),
        Err(ClientError::Protocol(_))
    ));
    client.transport().malformed.set(false);
    client.transport().unexpected.set(true);
    assert_eq!(
        client.record_lock(file(u64::MAX), request(Operation::Unlock)),
        Err(ClientError::MismatchedResponse)
    );
    assert_eq!(*client.transport().closed.borrow(), [99]);
}

#[test]
fn deferred_lock_preserves_epoch_and_attenuates_the_attached_file() {
    let client = client(Reply::Done);
    let request = Request {
        origin: Origin::Current,
        ..request(Operation::Set(Kind::Write))
    };
    client
        .wait_record_lock_since(file(u64::MAX), request, u64::MAX)
        .unwrap();
    assert_eq!(*client.transport().epochs.borrow(), [u64::MAX]);
    assert_eq!(
        *client.transport().calls.borrow(),
        [(request, wire::required_rights(request))]
    );
    assert_eq!(
        client.wait_record_lock_since(file(0), request, 0),
        Err(ClientError::Remote(-13))
    );
    assert_eq!(client.transport().calls.borrow().len(), 1);
    assert!(matches!(
        client.wait_record_lock_since(file(u64::MAX), self::request(Operation::Unlock), 0),
        Err(ClientError::Protocol(_))
    ));
}

#[test]
fn deferred_lock_rejects_noncompletion_replies_and_closes_unexpected_handles() {
    let client = client(Reply::Unlocked);
    let request = request(Operation::Set(Kind::Read));
    assert_eq!(
        client.wait_record_lock_since(file(u64::MAX), request, 0),
        Err(ClientError::MismatchedResponse)
    );
    client.transport().reply.set(Reply::Done);
    client.transport().unexpected.set(true);
    assert_eq!(
        client.wait_record_lock_since(file(u64::MAX), request, 0),
        Err(ClientError::MismatchedResponse)
    );
    assert_eq!(*client.transport().closed.borrow(), [99]);
}
