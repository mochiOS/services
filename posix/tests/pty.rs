use mnu_abi::provider;
use mochios_posix_client::{
    Client, ClientError, ObjectHandleAttachment, ObjectHandles, ObjectTransport, Transport,
};
use mochios_posix_protocol as protocol;
use posix_service::pty::{
    BUFFER_CAPACITY, EAGAIN, EBADF, EIO, ESPIPE, PtyManager, handle_provider_request,
};

#[test]
fn master_and_slave_exchange_bytes_in_opposite_directions() {
    let mut ptys = PtyManager::new();
    let pair = ptys.open().unwrap();

    assert_eq!(ptys.write(pair.master_object_id, b"input"), Ok(5));
    assert_eq!(ptys.read(pair.slave_object_id, 3), Ok(b"inp".to_vec()));
    assert_eq!(ptys.read(pair.slave_object_id, 8), Ok(b"ut".to_vec()));

    assert_eq!(ptys.write(pair.slave_object_id, b"output"), Ok(6));
    assert_eq!(ptys.read(pair.master_object_id, 8), Ok(b"output".to_vec()));
    assert_eq!(ptys.seek(pair.master_object_id), Err(ESPIPE));
}

#[test]
fn empty_reads_distinguish_would_block_from_peer_close() {
    let mut ptys = PtyManager::new();
    let pair = ptys.open().unwrap();

    assert_eq!(ptys.read(pair.master_object_id, 1), Err(EAGAIN));
    assert_eq!(ptys.read(pair.slave_object_id, 1), Err(EAGAIN));
    assert_eq!(ptys.read(pair.master_object_id, 0), Ok(Vec::new()));
    assert_eq!(ptys.release(pair.slave_object_id), Ok(()));
    assert_eq!(ptys.read(pair.master_object_id, 1), Ok(Vec::new()));
    assert_eq!(ptys.write(pair.master_object_id, b"x"), Err(EIO));
    assert_eq!(ptys.release(pair.master_object_id), Ok(()));
    assert_eq!(ptys.read(pair.master_object_id, 1), Err(EBADF));
}

#[test]
fn provider_wire_requests_drive_the_pty_without_posix_rpc() {
    let mut ptys = PtyManager::new();
    let pair = ptys.open().unwrap();
    let mut request = [0u8; provider::REQUEST_HEADER_LEN + 5];
    let mut response = [0u8; provider::RESPONSE_HEADER_LEN + provider::MAX_DATA_LEN];

    let request_len = provider::RequestHeader {
        opcode: provider::OP_WRITE,
        object_id: pair.master_object_id,
        argument: 0,
        basis: 0,
        length: 5,
        data_length: 5,
    }
    .encode(b"hello", &mut request)
    .unwrap();
    let response_len =
        handle_provider_request(&mut ptys, &request[..request_len], &mut response).unwrap();
    let (header, payload) = provider::ResponseHeader::decode(&response[..response_len]).unwrap();
    assert_eq!(header.status, 0);
    assert_eq!(header.value, 5);
    assert!(payload.is_empty());

    let request_len = provider::RequestHeader {
        opcode: provider::OP_READ,
        object_id: pair.slave_object_id,
        argument: 0,
        basis: 0,
        length: 16,
        data_length: 0,
    }
    .encode(&[], &mut request)
    .unwrap();
    let response_len =
        handle_provider_request(&mut ptys, &request[..request_len], &mut response).unwrap();
    let (header, payload) = provider::ResponseHeader::decode(&response[..response_len]).unwrap();
    assert_eq!(header.status, 0);
    assert_eq!(header.value, 5);
    assert_eq!(payload, b"hello");

    let request_len = provider::RequestHeader {
        opcode: provider::OP_RELEASE,
        object_id: pair.slave_object_id,
        argument: 0,
        basis: 0,
        length: 0,
        data_length: 0,
    }
    .encode(&[], &mut request)
    .unwrap();
    assert_eq!(
        handle_provider_request(&mut ptys, &request[..request_len], &mut response),
        None
    );
    assert_eq!(ptys.write(pair.master_object_id, b"x"), Err(EIO));
}

#[test]
fn pty_queues_are_bounded_and_support_partial_writes() {
    let mut ptys = PtyManager::new();
    let pair = ptys.open().unwrap();
    let bytes = vec![b'x'; BUFFER_CAPACITY + 7];

    assert_eq!(
        ptys.write(pair.master_object_id, &bytes),
        Ok(BUFFER_CAPACITY)
    );
    assert_eq!(ptys.write(pair.master_object_id, b"more"), Err(EAGAIN));
    assert_eq!(
        ptys.read(pair.slave_object_id, BUFFER_CAPACITY)
            .unwrap()
            .len(),
        BUFFER_CAPACITY
    );
}

#[test]
fn client_receives_only_the_two_provider_handles() {
    let client = Client::new(PtyTransport { handle_count: 2 });
    let pair = client.open_pty().unwrap();

    assert_eq!(pair.master.handle, 41);
    assert_eq!(pair.slave.handle, 42);
    assert_eq!(pair.master.rights, 0x31);
    assert_eq!(pair.slave.rights, 0x32);
}

#[test]
fn client_rejects_an_incomplete_pty_pair() {
    let client = Client::new(PtyTransport { handle_count: 1 });
    assert_eq!(client.open_pty(), Err(ClientError::MismatchedResponse));
}

struct PtyTransport {
    handle_count: usize,
}

impl Transport for PtyTransport {
    type Error = ();

    fn call(&self, _request: &[u8], _response: &mut [u8]) -> Result<usize, Self::Error> {
        Err(())
    }
}

impl ObjectTransport for PtyTransport {
    type Handle = u32;

    fn call_with_handles(
        &self,
        request: &[u8],
        response: &mut [u8],
        handles: &mut ObjectHandles<Self::Handle>,
    ) -> Result<usize, Self::Error> {
        let (header, payload) = protocol::decode(request).unwrap();
        assert_eq!(header.opcode, protocol::OP_PTY_OPEN);
        assert!(payload.is_empty());
        assert!(handles.is_empty());

        handles.clear();
        for index in 0..self.handle_count {
            handles
                .push(ObjectHandleAttachment {
                    handle: 41 + index as u32,
                    rights: 0x31 + index as u64,
                })
                .unwrap();
        }
        protocol::encode(
            protocol::Header {
                opcode: protocol::OP_STATUS,
                request_id: header.request_id,
                status: protocol::STATUS_OK,
                ..protocol::Header::default()
            },
            &[],
            response,
        )
        .map_err(|_| ())
    }
}
