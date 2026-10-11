use mnu_abi::HANDLE_SIGNAL_READABLE;
use mochios_posix_protocol as protocol;
use posix_service::pty::{PtyManager, PtyPair, BUFFER_CAPACITY, EAGAIN};

fn setup(canonical: bool) -> (PtyManager, PtyPair) {
    let mut manager = PtyManager::new();
    let pair = manager.open().unwrap();
    let mut attributes = protocol::TerminalAttributes::sane();
    attributes.input_flags = protocol::TERMINAL_IFLAG_IXON;
    attributes.output_flags = 0;
    attributes.local_flags = if canonical {
        protocol::TERMINAL_LFLAG_ICANON
    } else {
        0
    };
    manager
        .set_attributes(pair.slave_object_id, attributes)
        .unwrap();
    (manager, pair)
}

#[test]
fn stop_withholds_queued_output_and_readiness_without_losing_bytes() {
    for canonical in [false, true] {
        let (mut manager, pair) = setup(canonical);
        manager.write(pair.slave_object_id, b"before").unwrap();
        assert_ne!(
            manager.signals(pair.master_object_id).unwrap() & HANDLE_SIGNAL_READABLE,
            0
        );
        assert_eq!(manager.write(pair.master_object_id, b"\x13"), Ok(1));
        assert_eq!(manager.read(pair.master_object_id, 32), Err(EAGAIN));
        assert_eq!(
            manager.signals(pair.master_object_id).unwrap() & HANDLE_SIGNAL_READABLE,
            0
        );
        assert_eq!(manager.write(pair.slave_object_id, b"after"), Ok(5));
        assert_eq!(manager.write(pair.master_object_id, b"\x11"), Ok(1));
        assert_ne!(
            manager.signals(pair.master_object_id).unwrap() & HANDLE_SIGNAL_READABLE,
            0
        );
        assert_eq!(
            manager.read(pair.master_object_id, 32),
            Ok(b"beforeafter".to_vec())
        );
        // Control characters are neither input nor canonical line contents.
        assert_eq!(manager.read(pair.slave_object_id, 32), Err(EAGAIN));
        assert_eq!(manager.write(pair.master_object_id, b"line\n"), Ok(5));
        assert_eq!(
            manager.read(pair.slave_object_id, 32),
            Ok(b"line\n".to_vec())
        );
    }
}

#[test]
fn restart_is_consumed_even_when_both_queues_are_full() {
    let (mut manager, pair) = setup(false);
    let bytes = vec![b'x'; BUFFER_CAPACITY];
    manager.write(pair.master_object_id, b"\x13").unwrap();
    assert_eq!(
        manager.write(pair.slave_object_id, &bytes),
        Ok(BUFFER_CAPACITY)
    );
    assert_eq!(
        manager.write(pair.master_object_id, &bytes),
        Ok(BUFFER_CAPACITY)
    );
    assert_eq!(manager.write(pair.slave_object_id, b"y"), Err(EAGAIN));
    assert_eq!(manager.write(pair.master_object_id, b"\x11"), Ok(1));
    assert_eq!(
        manager.read(pair.master_object_id, BUFFER_CAPACITY),
        Ok(bytes.clone())
    );
    assert_eq!(
        manager.read(pair.slave_object_id, BUFFER_CAPACITY),
        Ok(bytes)
    );
}

#[test]
fn disabled_or_custom_control_characters_are_respected() {
    let (mut manager, pair) = setup(false);
    let mut attributes = manager.attributes(pair.slave_object_id).unwrap();
    attributes.control_characters[protocol::TERMINAL_CC_VSTOP] = b's';
    attributes.control_characters[protocol::TERMINAL_CC_VSTART] = b'q';
    manager
        .set_attributes(pair.slave_object_id, attributes)
        .unwrap();
    manager.write(pair.master_object_id, b"\x13s\x11").unwrap();
    manager.write(pair.slave_object_id, b"output").unwrap();
    assert_eq!(manager.read(pair.master_object_id, 32), Err(EAGAIN));
    assert_eq!(
        manager.read(pair.slave_object_id, 32),
        Ok(b"\x13\x11".to_vec())
    );
    manager.write(pair.master_object_id, b"q").unwrap();
    assert_eq!(
        manager.read(pair.master_object_id, 32),
        Ok(b"output".to_vec())
    );
    attributes.control_characters[protocol::TERMINAL_CC_VSTART] = 0;
    attributes.control_characters[protocol::TERMINAL_CC_VSTOP] = 0;
    manager
        .set_attributes(pair.slave_object_id, attributes)
        .unwrap();
    manager.write(pair.master_object_id, b"\0\x13\x11").unwrap();
    assert_eq!(
        manager.read(pair.slave_object_id, 32),
        Ok(b"\0\x13\x11".to_vec())
    );
}

#[test]
fn disabling_ixon_restarts_output_and_passes_control_bytes_as_data() {
    let (mut manager, pair) = setup(false);
    manager.write(pair.master_object_id, b"\x13").unwrap();
    manager.write(pair.slave_object_id, b"pending").unwrap();
    let mut attributes = manager.attributes(pair.slave_object_id).unwrap();
    attributes.input_flags = 0;
    manager
        .set_attributes(pair.slave_object_id, attributes)
        .unwrap();
    assert_eq!(
        manager.read(pair.master_object_id, 32),
        Ok(b"pending".to_vec())
    );
    manager.write(pair.master_object_id, b"\x13\x11").unwrap();
    assert_eq!(
        manager.read(pair.slave_object_id, 32),
        Ok(b"\x13\x11".to_vec())
    );
}

#[test]
fn closing_the_slave_does_not_leave_stopped_output_or_eof_unreachable() {
    let (mut manager, pair) = setup(false);
    manager.write(pair.master_object_id, b"\x13").unwrap();
    manager.write(pair.slave_object_id, b"pending").unwrap();
    manager.release(pair.slave_object_id).unwrap();
    assert_ne!(
        manager.signals(pair.master_object_id).unwrap() & HANDLE_SIGNAL_READABLE,
        0
    );
    assert_eq!(
        manager.read(pair.master_object_id, 32),
        Ok(b"pending".to_vec())
    );
    assert_eq!(manager.read(pair.master_object_id, 32), Ok(vec![]));
}

#[test]
fn flow_characters_are_not_echoed_and_other_terminals_remain_unaffected() {
    let (mut manager, pair) = setup(false);
    let other = manager.open().unwrap();
    let mut attributes = manager.attributes(pair.slave_object_id).unwrap();
    attributes.local_flags = protocol::TERMINAL_LFLAG_ECHO;
    manager
        .set_attributes(pair.slave_object_id, attributes)
        .unwrap();
    manager.write(pair.master_object_id, b"\x13input").unwrap();
    manager.write(other.slave_object_id, b"other").unwrap();
    assert_eq!(manager.read(pair.master_object_id, 32), Err(EAGAIN));
    assert_eq!(
        manager.read(other.master_object_id, 32),
        Ok(b"other".to_vec())
    );
    manager.write(pair.master_object_id, b"\x11").unwrap();
    assert_eq!(
        manager.read(pair.master_object_id, 32),
        Ok(b"input".to_vec())
    );
    assert_eq!(
        manager.read(pair.slave_object_id, 32),
        Ok(b"input".to_vec())
    );
}

#[test]
fn provider_wire_stop_and_start_preserve_error_and_byte_count_contracts() {
    use mnu_abi::provider;
    fn request(
        manager: &mut PtyManager,
        opcode: u16,
        object: u64,
        basis: u64,
        input: &[u8],
        length: u32,
    ) -> (i64, u64, Vec<u8>) {
        let mut request = vec![0; provider::REQUEST_HEADER_LEN + input.len()];
        let count = provider::RequestHeader {
            opcode,
            object_id: object,
            argument: 0,
            basis,
            length,
            data_length: input.len() as u32,
        }
        .encode(input, &mut request)
        .unwrap();
        let mut response = vec![0; provider::RESPONSE_HEADER_LEN + 128];
        let count =
            posix_service::pty::handle_provider_request(manager, &request[..count], &mut response)
                .unwrap();
        let (header, payload) = provider::ResponseHeader::decode(&response[..count]).unwrap();
        (header.status, header.value, payload.to_vec())
    }
    let mut manager = PtyManager::new();
    let pair = manager.open().unwrap();
    let mut attributes = protocol::TerminalAttributes::sane();
    attributes.input_flags = protocol::TERMINAL_IFLAG_IXON;
    attributes.local_flags = 0;
    attributes.output_flags = 0;
    let mut encoded = vec![0; protocol::TERMINAL_ATTRIBUTES_LEN];
    protocol::encode_terminal_attributes(attributes, &mut encoded).unwrap();
    assert_eq!(
        request(
            &mut manager,
            provider::OP_CONTROL,
            pair.slave_object_id,
            protocol::PTY_CONTROL_SET_ATTRIBUTES_NOW,
            &encoded,
            0
        ),
        (0, 0, vec![])
    );
    assert_eq!(
        request(
            &mut manager,
            provider::OP_WRITE,
            pair.master_object_id,
            0,
            b"\x13",
            1
        ),
        (0, 1, vec![])
    );
    assert_eq!(
        request(
            &mut manager,
            provider::OP_WRITE,
            pair.slave_object_id,
            0,
            b"queued",
            6
        ),
        (0, 6, vec![])
    );
    assert_eq!(
        request(
            &mut manager,
            provider::OP_READ,
            pair.master_object_id,
            0,
            &[],
            32
        ),
        (-(i64::from(EAGAIN)), 0, vec![])
    );
    assert_eq!(
        request(
            &mut manager,
            provider::OP_WRITE,
            pair.master_object_id,
            0,
            b"\x11",
            1
        ),
        (0, 1, vec![])
    );
    assert_eq!(
        request(
            &mut manager,
            provider::OP_READ,
            pair.master_object_id,
            0,
            &[],
            32
        ),
        (0, 6, b"queued".to_vec())
    );
}
