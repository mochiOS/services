use mnu_abi::provider;
use mochios_posix_client::{
    Client, ClientError, ObjectHandleAttachment, ObjectHandles, ObjectTransport, Transport,
};
use mochios_posix_protocol as protocol;
use posix_service::pty::{
    BUFFER_CAPACITY, EAGAIN, EBADF, EINVAL, EIO, ENOTSUP, ESPIPE, PtyManager,
    handle_provider_request,
};

fn raw_attributes() -> protocol::TerminalAttributes {
    let mut attributes = protocol::TerminalAttributes::sane();
    attributes.input_flags = 0;
    attributes.output_flags = 0;
    attributes.local_flags = 0;
    attributes.control_characters[protocol::TERMINAL_CC_VMIN] = 1;
    attributes.control_characters[protocol::TERMINAL_CC_VTIME] = 0;
    attributes
}

fn make_raw(ptys: &mut PtyManager, object_id: u64) {
    ptys.set_attributes(object_id, raw_attributes()).unwrap();
}

#[test]
fn master_and_slave_exchange_bytes_in_opposite_directions() {
    let mut ptys = PtyManager::new();
    let pair = ptys.open().unwrap();
    make_raw(&mut ptys, pair.slave_object_id);

    assert_eq!(ptys.write(pair.master_object_id, b"input"), Ok(5));
    assert_eq!(ptys.read(pair.slave_object_id, 3), Ok(b"inp".to_vec()));
    assert_eq!(ptys.read(pair.slave_object_id, 8), Ok(b"ut".to_vec()));

    assert_eq!(ptys.write(pair.slave_object_id, b"output"), Ok(6));
    assert_eq!(ptys.read(pair.master_object_id, 8), Ok(b"output".to_vec()));
    assert_eq!(ptys.seek(pair.master_object_id), Err(ESPIPE));
}

#[test]
fn canonical_input_waits_for_a_record_and_preserves_line_boundaries() {
    let mut ptys = PtyManager::new();
    let pair = ptys.open().unwrap();

    assert_eq!(ptys.write(pair.master_object_id, b"first"), Ok(5));
    assert_eq!(ptys.read(pair.slave_object_id, 32), Err(EAGAIN));
    assert_eq!(ptys.write(pair.master_object_id, b"\rsecond\n"), Ok(8));
    assert_eq!(ptys.read(pair.slave_object_id, 32), Ok(b"first\n".to_vec()));
    assert_eq!(
        ptys.read(pair.slave_object_id, 32),
        Ok(b"second\n".to_vec())
    );
    assert_eq!(ptys.read(pair.slave_object_id, 32), Err(EAGAIN));
    assert_eq!(
        ptys.read(pair.master_object_id, 32),
        Ok(b"first\r\nsecond\r\n".to_vec())
    );
}

#[test]
fn canonical_erase_kill_and_eof_edit_the_pending_record() {
    let mut ptys = PtyManager::new();
    let pair = ptys.open().unwrap();

    assert_eq!(
        ptys.write(pair.master_object_id, b"ab\x7fc\nthrow-away\x15ok\x04"),
        Ok(19)
    );
    assert_eq!(ptys.read(pair.slave_object_id, 32), Ok(b"ac\n".to_vec()));
    assert_eq!(ptys.read(pair.slave_object_id, 32), Ok(b"ok".to_vec()));
    assert_eq!(ptys.write(pair.master_object_id, b"\x04"), Ok(1));
    assert_eq!(ptys.read(pair.slave_object_id, 32), Ok(Vec::new()));
}

#[test]
fn signal_characters_target_the_terminal_and_obey_noflsh() {
    let mut ptys = PtyManager::new();
    let pair = ptys.open().unwrap();

    assert_eq!(
        ptys.write(pair.master_object_id, b"discard\x03kept\n"),
        Ok(13)
    );
    assert_eq!(ptys.read(pair.slave_object_id, 32), Ok(b"kept\n".to_vec()));
    assert_eq!(
        ptys.read(pair.master_object_id, 32),
        Ok(b"kept\r\n".to_vec())
    );
    assert_eq!(
        ptys.take_terminal_signal(),
        Some(posix_service::pty::TerminalSignal {
            terminal_id: 1,
            signal: protocol::SIGNAL_INT,
        })
    );

    let mut attributes = protocol::TerminalAttributes::sane();
    attributes.local_flags |= protocol::TERMINAL_LFLAG_NOFLSH;
    ptys.set_attributes(pair.slave_object_id, attributes)
        .unwrap();
    assert_eq!(ptys.write(pair.master_object_id, b"keep\x1c\x1a\n"), Ok(7));
    assert_eq!(ptys.read(pair.slave_object_id, 32), Ok(b"keep\n".to_vec()));
    assert_eq!(
        ptys.take_terminal_signal().map(|event| event.signal),
        Some(protocol::SIGNAL_QUIT)
    );
    assert_eq!(
        ptys.take_terminal_signal().map(|event| event.signal),
        Some(protocol::SIGNAL_TSTP)
    );
    assert_eq!(ptys.take_terminal_signal(), None);
}

#[test]
fn raw_input_is_immediately_readable_and_output_postprocessing_is_configurable() {
    let mut ptys = PtyManager::new();
    let pair = ptys.open().unwrap();
    make_raw(&mut ptys, pair.slave_object_id);

    assert_eq!(ptys.write(pair.master_object_id, b"raw"), Ok(3));
    assert_eq!(ptys.read(pair.slave_object_id, 32), Ok(b"raw".to_vec()));
    assert_eq!(ptys.write(pair.slave_object_id, b"a\nb"), Ok(3));
    assert_eq!(ptys.read(pair.master_object_id, 32), Ok(b"a\nb".to_vec()));

    let mut cooked_output = raw_attributes();
    cooked_output.output_flags = protocol::TERMINAL_OFLAG_OPOST | protocol::TERMINAL_OFLAG_ONLCR;
    ptys.set_attributes(pair.slave_object_id, cooked_output)
        .unwrap();
    assert_eq!(ptys.write(pair.slave_object_id, b"c\nd"), Ok(3));
    assert_eq!(ptys.read(pair.master_object_id, 32), Ok(b"c\r\nd".to_vec()));
}

#[test]
fn empty_reads_distinguish_would_block_from_peer_close() {
    let mut ptys = PtyManager::new();
    let pair = ptys.open().unwrap();
    make_raw(&mut ptys, pair.slave_object_id);

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
fn last_master_release_generates_one_controller_hangup_and_preserves_eof() {
    let mut ptys = PtyManager::new();
    let pair = ptys.open().unwrap();
    let other = ptys.open().unwrap();
    let terminal_id = ptys.slave_terminal_id(pair.slave_object_id).unwrap();
    let mut request = [0; provider::REQUEST_HEADER_LEN];
    let length = provider::RequestHeader {
        opcode: provider::OP_RELEASE,
        object_id: pair.master_object_id,
        argument: 0,
        basis: 0,
        length: 0,
        data_length: 0,
    }
    .encode(&[], &mut request)
    .unwrap();
    let mut response = [0; provider::RESPONSE_HEADER_LEN];
    // Kernel RELEASE is a one-way notification, not a call awaiting a reply.
    assert_eq!(
        handle_provider_request(&mut ptys, &request[..length], &mut response),
        None
    );
    assert_eq!(
        ptys.take_terminal_signal(),
        Some(posix_service::pty::TerminalSignal {
            terminal_id,
            signal: protocol::SIGNAL_HUP,
        })
    );
    assert_eq!(ptys.release(pair.master_object_id), Err(EBADF));
    assert_eq!(ptys.take_terminal_signal(), None);
    assert_eq!(ptys.read(pair.slave_object_id, 1), Ok(Vec::new()));
    assert_eq!(ptys.write(pair.slave_object_id, b"x"), Err(EIO));
    assert_eq!(ptys.read(other.slave_object_id, 1), Err(EAGAIN));
    assert_eq!(ptys.release(pair.slave_object_id), Ok(()));
    assert_eq!(ptys.take_terminal_signal(), None);
}

#[test]
fn slave_close_and_failed_pair_discard_do_not_generate_controller_hangups() {
    let mut ptys = PtyManager::new();
    let pair = ptys.open().unwrap();
    let terminal_id = ptys.slave_terminal_id(pair.slave_object_id).unwrap();
    assert_eq!(ptys.release(pair.slave_object_id), Ok(()));
    assert_eq!(ptys.take_terminal_signal(), None);
    let unpublished = ptys.open().unwrap();
    ptys.discard(unpublished);
    assert_eq!(ptys.take_terminal_signal(), None);
    ptys.release(pair.master_object_id).unwrap();
    assert_eq!(
        ptys.take_terminal_signal(),
        Some(posix_service::pty::TerminalSignal {
            terminal_id,
            signal: protocol::SIGNAL_HUP,
        })
    );
    assert_eq!(ptys.take_terminal_signal(), None);
}

#[test]
fn runtime_routes_master_hangup_only_from_the_authenticated_provider() {
    let source = include_str!("../src/main.rs");
    assert!(source.contains("sender_process == Some(service_process_id)"));
    assert!(source.contains("&& attachments.is_empty()"));
    assert!(source.contains("if signal == protocol::SIGNAL_HUP"));
    assert!(source.contains("service.hangup_terminal(terminal_id)"));
    assert!(source.contains("signal_terminal_foreground_group(terminal_id, signal)"));
}

#[test]
fn provider_wire_requests_drive_the_pty_without_posix_rpc() {
    let mut ptys = PtyManager::new();
    let pair = ptys.open().unwrap();
    make_raw(&mut ptys, pair.slave_object_id);
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
fn unsupported_provider_control_returns_an_error_reply() {
    let mut ptys = PtyManager::new();
    let pair = ptys.open().unwrap();
    let mut request = [0u8; provider::REQUEST_HEADER_LEN];
    let mut response = [0u8; provider::RESPONSE_HEADER_LEN];
    let request_len = provider::RequestHeader {
        opcode: provider::OP_CONTROL,
        object_id: pair.master_object_id,
        argument: 0,
        basis: 17,
        length: 0,
        data_length: 0,
    }
    .encode(&[], &mut request)
    .unwrap();

    let response_len =
        handle_provider_request(&mut ptys, &request[..request_len], &mut response).unwrap();
    let (header, payload) = provider::ResponseHeader::decode(&response[..response_len]).unwrap();
    assert_eq!(header.status, -(i64::from(ENOTSUP)));
    assert_eq!(header.value, 0);
    assert!(payload.is_empty());
}

#[test]
fn terminal_attributes_are_shared_between_both_ends() {
    let mut ptys = PtyManager::new();
    let pair = ptys.open().unwrap();
    let defaults = protocol::TerminalAttributes::sane();
    assert_eq!(ptys.attributes(pair.master_object_id), Ok(defaults));
    assert_eq!(ptys.attributes(pair.slave_object_id), Ok(defaults));

    let mut raw = defaults;
    raw.input_flags = 0;
    raw.output_flags = 0;
    raw.local_flags = 0;
    raw.control_characters[protocol::TERMINAL_CC_VMIN] = 7;
    ptys.set_attributes(pair.slave_object_id, raw).unwrap();
    assert_eq!(ptys.attributes(pair.master_object_id), Ok(raw));

    let mut unsupported = raw;
    unsupported.input_flags = protocol::TERMINAL_IFLAG_IXOFF;
    assert_eq!(
        ptys.set_attributes(pair.master_object_id, unsupported),
        Err(ENOTSUP)
    );
    assert_eq!(ptys.attributes(pair.slave_object_id), Ok(raw));
}

#[test]
fn provider_control_round_trips_terminal_attributes() {
    let mut ptys = PtyManager::new();
    let pair = ptys.open().unwrap();
    let mut request = [0u8; provider::REQUEST_HEADER_LEN + protocol::TERMINAL_ATTRIBUTES_LEN];
    let mut response = [0u8; provider::RESPONSE_HEADER_LEN + protocol::TERMINAL_ATTRIBUTES_LEN];
    let mut attributes = protocol::TerminalAttributes::sane();
    attributes.local_flags &= !protocol::TERMINAL_LFLAG_ECHO;
    attributes.output_speed = 115_200;
    let mut encoded = [0; protocol::TERMINAL_ATTRIBUTES_LEN];
    protocol::encode_terminal_attributes(attributes, &mut encoded).unwrap();

    let request_len = provider::RequestHeader {
        opcode: provider::OP_CONTROL,
        object_id: pair.slave_object_id,
        argument: 0,
        basis: protocol::PTY_CONTROL_SET_ATTRIBUTES_NOW,
        length: 0,
        data_length: encoded.len() as u32,
    }
    .encode(&encoded, &mut request)
    .unwrap();
    let response_len =
        handle_provider_request(&mut ptys, &request[..request_len], &mut response).unwrap();
    let (header, payload) = provider::ResponseHeader::decode(&response[..response_len]).unwrap();
    assert_eq!(header.status, 0);
    assert!(payload.is_empty());

    let request_len = provider::RequestHeader {
        opcode: provider::OP_CONTROL,
        object_id: pair.master_object_id,
        argument: 0,
        basis: protocol::PTY_CONTROL_GET_ATTRIBUTES,
        length: protocol::TERMINAL_ATTRIBUTES_LEN as u32,
        data_length: 0,
    }
    .encode(&[], &mut request)
    .unwrap();
    let response_len =
        handle_provider_request(&mut ptys, &request[..request_len], &mut response).unwrap();
    let (header, payload) = provider::ResponseHeader::decode(&response[..response_len]).unwrap();
    assert_eq!(header.status, 0);
    assert_eq!(header.value, protocol::TERMINAL_ATTRIBUTES_LEN as u64);
    assert_eq!(
        protocol::decode_terminal_attributes(payload),
        Ok(attributes)
    );

    let request_len = provider::RequestHeader {
        opcode: provider::OP_CONTROL,
        object_id: pair.master_object_id,
        argument: 0,
        basis: protocol::PTY_CONTROL_SET_ATTRIBUTES_NOW,
        length: 0,
        data_length: 1,
    }
    .encode(&[0], &mut request)
    .unwrap();
    let response_len =
        handle_provider_request(&mut ptys, &request[..request_len], &mut response).unwrap();
    let (header, _) = provider::ResponseHeader::decode(&response[..response_len]).unwrap();
    assert_eq!(header.status, -(i64::from(EINVAL)));
}

#[test]
fn drained_attribute_changes_wait_and_flush_discards_unread_input() {
    let mut ptys = PtyManager::new();
    let pair = ptys.open().unwrap();
    let raw = raw_attributes();
    ptys.set_attributes(pair.slave_object_id, raw).unwrap();
    assert_eq!(ptys.write(pair.slave_object_id, b"pending"), Ok(7));

    let cooked = protocol::TerminalAttributes::sane();
    let mut encoded = [0; protocol::TERMINAL_ATTRIBUTES_LEN];
    protocol::encode_terminal_attributes(cooked, &mut encoded).unwrap();
    assert_eq!(
        ptys.control(
            pair.slave_object_id,
            protocol::PTY_CONTROL_SET_ATTRIBUTES_DRAIN,
            &encoded,
            0,
        ),
        Err(EAGAIN)
    );
    assert_eq!(ptys.attributes(pair.master_object_id), Ok(raw));
    assert_eq!(
        ptys.read(pair.master_object_id, 32),
        Ok(b"pending".to_vec())
    );
    assert_ne!(
        ptys.signals(pair.slave_object_id).unwrap() & mnu_abi::HANDLE_SIGNAL_IDLE,
        0
    );
    assert_eq!(
        ptys.control(
            pair.slave_object_id,
            protocol::PTY_CONTROL_SET_ATTRIBUTES_DRAIN,
            &encoded,
            0,
        ),
        Ok(Vec::new())
    );

    ptys.set_attributes(pair.slave_object_id, raw).unwrap();
    assert_eq!(ptys.write(pair.master_object_id, b"discard"), Ok(7));
    assert_eq!(
        ptys.control(
            pair.slave_object_id,
            protocol::PTY_CONTROL_SET_ATTRIBUTES_FLUSH,
            &encoded,
            0,
        ),
        Ok(Vec::new())
    );
    assert_eq!(ptys.read(pair.slave_object_id, 32), Err(EAGAIN));
    assert_eq!(ptys.attributes(pair.master_object_id), Ok(cooked));
}

#[test]
fn terminal_queue_controls_drain_and_discard_selected_directions() {
    let mut ptys = PtyManager::new();
    let pair = ptys.open().unwrap();
    make_raw(&mut ptys, pair.slave_object_id);
    assert_eq!(ptys.write(pair.master_object_id, b"input"), Ok(5));
    assert_eq!(ptys.write(pair.slave_object_id, b"output"), Ok(6));

    assert_eq!(
        ptys.control(pair.slave_object_id, protocol::PTY_CONTROL_DRAIN, &[], 0,),
        Err(EAGAIN)
    );

    let mut flush = [0; protocol::TERMINAL_FLUSH_LEN];
    protocol::encode_terminal_flush(protocol::TERMINAL_FLUSH_INPUT, &mut flush).unwrap();
    assert_eq!(
        ptys.control(pair.slave_object_id, protocol::PTY_CONTROL_FLUSH, &flush, 0,),
        Ok(Vec::new())
    );
    assert_eq!(ptys.read(pair.slave_object_id, 32), Err(EAGAIN));
    assert_eq!(ptys.read(pair.master_object_id, 32), Ok(b"output".to_vec()));

    assert_eq!(ptys.write(pair.slave_object_id, b"discard"), Ok(7));
    protocol::encode_terminal_flush(protocol::TERMINAL_FLUSH_OUTPUT, &mut flush).unwrap();
    assert_eq!(
        ptys.control(pair.slave_object_id, protocol::PTY_CONTROL_FLUSH, &flush, 0,),
        Ok(Vec::new())
    );
    assert_ne!(
        ptys.signals(pair.slave_object_id).unwrap() & mnu_abi::HANDLE_SIGNAL_IDLE,
        0
    );
    assert_eq!(
        ptys.control(pair.slave_object_id, protocol::PTY_CONTROL_DRAIN, &[], 0,),
        Ok(Vec::new())
    );
    assert_eq!(ptys.read(pair.master_object_id, 32), Err(EAGAIN));

    assert_eq!(
        ptys.control(
            pair.slave_object_id,
            protocol::PTY_CONTROL_FLUSH,
            &[0; protocol::TERMINAL_FLUSH_LEN],
            0,
        ),
        Err(EINVAL)
    );
}

#[test]
fn pty_queues_are_bounded_and_support_partial_writes() {
    let mut ptys = PtyManager::new();
    let pair = ptys.open().unwrap();
    make_raw(&mut ptys, pair.slave_object_id);
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
fn readiness_signals_follow_queue_capacity_and_peer_lifetime() {
    let mut ptys = PtyManager::new();
    let pair = ptys.open().unwrap();
    make_raw(&mut ptys, pair.slave_object_id);

    assert_eq!(
        ptys.signals(pair.master_object_id),
        Ok(mnu_abi::HANDLE_SIGNAL_WRITABLE | mnu_abi::HANDLE_SIGNAL_IDLE)
    );
    assert_eq!(
        ptys.signals(pair.slave_object_id),
        Ok(mnu_abi::HANDLE_SIGNAL_WRITABLE | mnu_abi::HANDLE_SIGNAL_IDLE)
    );

    assert_eq!(ptys.write(pair.master_object_id, b"input"), Ok(5));
    assert_eq!(
        ptys.signals(pair.slave_object_id),
        Ok(mnu_abi::HANDLE_SIGNAL_READABLE
            | mnu_abi::HANDLE_SIGNAL_WRITABLE
            | mnu_abi::HANDLE_SIGNAL_IDLE)
    );
    let remaining = vec![b'x'; BUFFER_CAPACITY - 5];
    assert_eq!(
        ptys.write(pair.master_object_id, &remaining),
        Ok(remaining.len())
    );
    assert_eq!(
        ptys.signals(pair.master_object_id),
        Ok(mnu_abi::HANDLE_SIGNAL_IDLE)
    );

    assert_eq!(ptys.release(pair.slave_object_id), Ok(()));
    assert_eq!(
        ptys.signals(pair.master_object_id),
        Ok(mnu_abi::HANDLE_SIGNAL_PEER_CLOSED | mnu_abi::HANDLE_SIGNAL_IDLE)
    );
}

#[test]
fn only_a_live_slave_object_identifies_a_controlling_terminal() {
    let mut ptys = PtyManager::new();
    let pair = ptys.open().unwrap();
    assert_eq!(ptys.slave_terminal_id(pair.slave_object_id), Ok(1));
    assert_eq!(ptys.slave_terminal_id(pair.master_object_id), Err(EBADF));
    ptys.discard(pair);
    assert_eq!(ptys.slave_terminal_id(pair.slave_object_id), Err(EBADF));
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

#[test]
fn client_attaches_only_the_terminal_handle_for_job_control() {
    let terminal = ObjectHandleAttachment {
        handle: 55,
        rights: 0x40,
    };
    Client::new(TerminalTransport {
        opcode: protocol::OP_TERMINAL_ACQUIRE,
        process_group: None,
    })
    .acquire_controlling_terminal(terminal)
    .unwrap();
    assert_eq!(
        Client::new(TerminalTransport {
            opcode: protocol::OP_TERMINAL_GET_FOREGROUND,
            process_group: Some(81),
        })
        .terminal_foreground_process_group(terminal),
        Ok(81)
    );
    Client::new(TerminalTransport {
        opcode: protocol::OP_TERMINAL_SET_FOREGROUND,
        process_group: Some(82),
    })
    .set_terminal_foreground_process_group(terminal, 82)
    .unwrap();
    Client::new(TerminalTransport {
        opcode: protocol::OP_TERMINAL_RELEASE,
        process_group: None,
    })
    .release_controlling_terminal(terminal)
    .unwrap();
}

struct TerminalTransport {
    opcode: u16,
    process_group: Option<i64>,
}

impl Transport for TerminalTransport {
    type Error = ();

    fn call(&self, _request: &[u8], _response: &mut [u8]) -> Result<usize, Self::Error> {
        Err(())
    }
}

impl ObjectTransport for TerminalTransport {
    type Handle = u32;

    fn call_with_handles(
        &self,
        request: &[u8],
        response: &mut [u8],
        handles: &mut ObjectHandles<Self::Handle>,
    ) -> Result<usize, Self::Error> {
        let (header, payload) = protocol::decode(request).unwrap();
        assert_eq!(header.opcode, self.opcode);
        assert_eq!(handles.len(), 1);
        assert_eq!(
            handles.get(0),
            Some(ObjectHandleAttachment {
                handle: 55,
                rights: 0x40,
            })
        );
        if self.opcode == protocol::OP_TERMINAL_SET_FOREGROUND {
            assert_eq!(
                protocol::decode_process_id_request(payload),
                Ok(self.process_group.unwrap())
            );
        } else {
            assert!(payload.is_empty());
        }
        handles.clear();
        let mut payload = [0u8; protocol::PROCESS_ID_REQUEST_LEN];
        let response_payload = if self.opcode == protocol::OP_TERMINAL_GET_FOREGROUND {
            protocol::encode_process_id_request(self.process_group.unwrap(), &mut payload).unwrap();
            payload.as_slice()
        } else {
            &[]
        };
        protocol::encode(
            protocol::Header {
                opcode: protocol::OP_STATUS,
                request_id: header.request_id,
                status: protocol::STATUS_OK,
                payload_len: response_payload.len() as u32,
                ..protocol::Header::default()
            },
            response_payload,
            response,
        )
        .map_err(|_| ())
    }
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
