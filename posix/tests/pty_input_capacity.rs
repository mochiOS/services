//! Empty canonical records consume metadata even though they contain no bytes.
use mochios_posix_protocol as wire;
use posix_service::pty::{BUFFER_CAPACITY, EAGAIN, PtyManager, PtyPair};

fn terminal() -> (PtyManager, PtyPair) {
    let mut manager = PtyManager::new();
    let pair = manager.open().unwrap();
    let mut attributes = manager.attributes(pair.slave_object_id).unwrap();
    attributes.local_flags &= !wire::TERMINAL_LFLAG_ECHO;
    attributes.input_flags |= wire::TERMINAL_IFLAG_IXON;
    manager
        .set_attributes(pair.slave_object_id, attributes)
        .unwrap();
    (manager, pair)
}

fn writable(manager: &PtyManager, pair: PtyPair) -> bool {
    manager.signals(pair.master_object_id).unwrap() & mnu_abi::HANDLE_SIGNAL_WRITABLE != 0
}

fn drain_eof(manager: &mut PtyManager, pair: PtyPair, count: usize) {
    for _ in 0..count {
        assert_eq!(manager.read(pair.slave_object_id, 1), Ok(vec![]));
    }
    assert_eq!(manager.read(pair.slave_object_id, 1), Err(EAGAIN));
}

#[test]
fn repeated_empty_eof_is_bounded_and_retry_publishes_exactly_one_record() {
    let (mut manager, pair) = terminal();
    let flood = vec![4; BUFFER_CAPACITY + 17];
    assert_eq!(
        manager.write(pair.master_object_id, &flood),
        Ok(BUFFER_CAPACITY)
    );
    assert!(!writable(&manager, pair));
    assert_eq!(manager.write(pair.master_object_id, &[4]), Err(EAGAIN));
    assert_eq!(manager.read(pair.slave_object_id, 0), Ok(vec![]));
    assert!(
        !writable(&manager, pair),
        "zero-length reads must not consume EOF"
    );
    assert_eq!(manager.read(pair.slave_object_id, 1), Ok(vec![]));
    assert!(writable(&manager, pair));
    assert_eq!(manager.write(pair.master_object_id, &[4, 4]), Ok(1));
    assert!(!writable(&manager, pair));
    drain_eof(&mut manager, pair, BUFFER_CAPACITY);
    assert!(writable(&manager, pair));
}

#[test]
fn full_record_queue_does_not_accept_or_echo_later_data() {
    let (mut manager, pair) = terminal();
    manager
        .write(pair.master_object_id, &vec![4; BUFFER_CAPACITY])
        .unwrap();
    let mut attributes = manager.attributes(pair.slave_object_id).unwrap();
    attributes.local_flags |= wire::TERMINAL_LFLAG_ECHO;
    manager
        .set_attributes(pair.slave_object_id, attributes)
        .unwrap();
    assert_eq!(manager.write(pair.master_object_id, b"lost\n"), Err(EAGAIN));
    assert_eq!(manager.read(pair.master_object_id, 100), Err(EAGAIN));
    drain_eof(&mut manager, pair, BUFFER_CAPACITY);
    assert_eq!(manager.write(pair.master_object_id, b"kept\n"), Ok(5));
    assert_eq!(
        manager.read(pair.slave_object_id, 100),
        Ok(b"kept\n".to_vec())
    );
    assert_eq!(
        manager.read(pair.master_object_id, 100),
        Ok(b"kept\r\n".to_vec())
    );
}

#[test]
fn pending_canonical_input_can_commit_the_last_record_slot() {
    let (mut manager, pair) = terminal();
    manager
        .write(pair.master_object_id, &vec![4; BUFFER_CAPACITY - 1])
        .unwrap();
    assert_eq!(
        manager.write(pair.master_object_id, b"pending\x04\x04"),
        Ok(8)
    );
    assert!(!writable(&manager, pair));
    for _ in 0..BUFFER_CAPACITY - 1 {
        assert_eq!(manager.read(pair.slave_object_id, 1), Ok(vec![]));
    }
    assert_eq!(
        manager.read(pair.slave_object_id, 100),
        Ok(b"pending".to_vec())
    );
    assert_eq!(manager.read(pair.slave_object_id, 1), Err(EAGAIN));
    assert!(writable(&manager, pair));
}

#[test]
fn switching_to_raw_mode_preserves_pending_bytes_at_the_record_limit() {
    let (mut manager, pair) = terminal();
    manager
        .write(pair.master_object_id, &vec![4; BUFFER_CAPACITY - 1])
        .unwrap();
    manager.write(pair.master_object_id, b"pending").unwrap();
    let mut attributes = manager.attributes(pair.slave_object_id).unwrap();
    attributes.local_flags &= !wire::TERMINAL_LFLAG_ICANON;
    manager
        .set_attributes(pair.slave_object_id, attributes)
        .unwrap();
    assert!(!writable(&manager, pair));
    assert_eq!(manager.write(pair.master_object_id, b"later"), Err(EAGAIN));
    for _ in 0..BUFFER_CAPACITY - 1 {
        assert_eq!(manager.read(pair.slave_object_id, 1), Ok(vec![]));
    }
    assert_eq!(
        manager.read(pair.slave_object_id, 100),
        Ok(b"pending".to_vec())
    );
    assert_eq!(manager.read(pair.slave_object_id, 1), Err(EAGAIN));
    assert!(writable(&manager, pair));
}

#[test]
fn flow_control_and_signal_flush_still_work_with_a_full_record_queue() {
    let (mut manager, pair) = terminal();
    manager
        .write(pair.master_object_id, &vec![4; BUFFER_CAPACITY])
        .unwrap();
    manager.write(pair.slave_object_id, b"output").unwrap();
    assert_eq!(manager.write(pair.master_object_id, b"\x13"), Ok(1));
    assert_eq!(manager.read(pair.master_object_id, 100), Err(EAGAIN));
    assert_eq!(manager.write(pair.master_object_id, b"\x11"), Ok(1));
    assert_eq!(
        manager.read(pair.master_object_id, 100),
        Ok(b"output".to_vec())
    );
    assert!(!writable(&manager, pair));
    assert_eq!(manager.write(pair.master_object_id, b"\x03"), Ok(1));
    assert_eq!(
        manager.take_terminal_signal().unwrap().signal,
        wire::SIGNAL_INT
    );
    assert!(writable(&manager, pair));
    assert_eq!(manager.read(pair.slave_object_id, 1), Err(EAGAIN));
    assert_eq!(manager.write(pair.master_object_id, b"fresh\n"), Ok(6));
    assert_eq!(
        manager.read(pair.slave_object_id, 100),
        Ok(b"fresh\n".to_vec())
    );
}

#[test]
fn noflsh_retains_full_records_until_an_explicit_input_flush() {
    for flush_attributes in [false, true] {
        let (mut manager, pair) = terminal();
        let mut attributes = manager.attributes(pair.slave_object_id).unwrap();
        attributes.local_flags |= wire::TERMINAL_LFLAG_NOFLSH;
        manager
            .set_attributes(pair.slave_object_id, attributes)
            .unwrap();
        manager
            .write(pair.master_object_id, &vec![4; BUFFER_CAPACITY])
            .unwrap();
        assert_eq!(manager.write(pair.master_object_id, b"\x03"), Ok(1));
        assert_eq!(
            manager.take_terminal_signal().unwrap().signal,
            wire::SIGNAL_INT
        );
        assert!(!writable(&manager, pair));
        assert_eq!(
            manager.write(pair.master_object_id, b"blocked"),
            Err(EAGAIN)
        );
        if flush_attributes {
            let mut encoded = [0; wire::TERMINAL_ATTRIBUTES_LEN];
            wire::encode_terminal_attributes(attributes, &mut encoded).unwrap();
            manager
                .control(
                    pair.slave_object_id,
                    wire::PTY_CONTROL_SET_ATTRIBUTES_FLUSH,
                    &encoded,
                    0,
                )
                .unwrap();
        } else {
            let mut encoded = [0; 4];
            wire::encode_terminal_flush(wire::TERMINAL_FLUSH_INPUT, &mut encoded).unwrap();
            manager
                .control(pair.slave_object_id, wire::PTY_CONTROL_FLUSH, &encoded, 0)
                .unwrap();
        }
        assert!(writable(&manager, pair));
        assert_eq!(manager.read(pair.slave_object_id, 1), Err(EAGAIN));
        assert_eq!(manager.write(pair.master_object_id, b"fresh\n"), Ok(6));
        assert_eq!(
            manager.read(pair.slave_object_id, 100),
            Ok(b"fresh\n".to_vec())
        );
    }
}

#[test]
fn eof_can_publish_a_line_when_the_byte_queue_is_full() {
    let (mut manager, pair) = terminal();
    let bytes = vec![b'x'; BUFFER_CAPACITY];
    assert_eq!(
        manager.write(pair.master_object_id, &bytes),
        Ok(BUFFER_CAPACITY)
    );
    assert!(!writable(&manager, pair));
    assert_eq!(manager.write(pair.master_object_id, b"extra"), Err(EAGAIN));
    assert_eq!(manager.write(pair.master_object_id, &[4]), Ok(1));
    assert_eq!(
        manager.read(pair.slave_object_id, BUFFER_CAPACITY),
        Ok(bytes)
    );
    assert_eq!(manager.read(pair.slave_object_id, 1), Err(EAGAIN));
    assert!(writable(&manager, pair));
}
