//! Literal-next belongs to the userspace line discipline, not the kernel.
use mochios_posix_protocol as wire;
use posix_service::pty::{BUFFER_CAPACITY, EAGAIN, PtyManager, PtyPair};

fn terminal(echo: bool) -> (PtyManager, PtyPair) {
    let mut manager = PtyManager::new();
    let pair = manager.open().unwrap();
    let mut attributes = manager.attributes(pair.slave_object_id).unwrap();
    attributes.local_flags |= wire::TERMINAL_LFLAG_IEXTEN;
    attributes.input_flags |= wire::TERMINAL_IFLAG_IXON;
    if !echo {
        attributes.local_flags &= !wire::TERMINAL_LFLAG_ECHO;
    }
    manager
        .set_attributes(pair.slave_object_id, attributes)
        .unwrap();
    (manager, pair)
}

#[test]
fn quoting_bypasses_signals_editing_eof_flow_and_line_delimiters() {
    for byte in [3, 28, 26, 127, 21, 4, 17, 19, 22, b'\n', b'\r', 0] {
        let (mut manager, pair) = terminal(false);
        assert_eq!(manager.write(pair.master_object_id, &[22]), Ok(1));
        assert_eq!(manager.write(pair.master_object_id, &[byte]), Ok(1));
        assert_eq!(manager.read(pair.slave_object_id, 100), Err(EAGAIN));
        assert_eq!(manager.take_terminal_signal(), None);
        manager.write(pair.master_object_id, b"\n").unwrap();
        assert_eq!(
            manager.read(pair.slave_object_id, 100),
            Ok(vec![byte, b'\n'])
        );
        manager.write(pair.slave_object_id, b"output").unwrap();
        assert_eq!(
            manager.read(pair.master_object_id, 100),
            Ok(b"output".to_vec())
        );
    }
}

#[test]
fn inline_and_split_input_have_identical_results_and_quote_only_one_byte() {
    let bytes = b"ab\x16\x03cd\x16\n\n";
    for split in 0..=bytes.len() {
        let (mut manager, pair) = terminal(false);
        assert_eq!(
            manager.write(pair.master_object_id, &bytes[..split]),
            Ok(split)
        );
        assert_eq!(
            manager.write(pair.master_object_id, &bytes[split..]),
            Ok(bytes.len() - split)
        );
        assert_eq!(
            manager.read(pair.slave_object_id, 100),
            Ok(b"ab\x03cd\n\n".to_vec())
        );
        assert_eq!(manager.take_terminal_signal(), None);
        assert_eq!(manager.write(pair.master_object_id, &[3]), Ok(1));
        assert_eq!(
            manager.take_terminal_signal().unwrap().signal,
            wire::SIGNAL_INT
        );
    }
}

#[test]
fn quoted_bytes_keep_istrip_but_bypass_cr_translation() {
    let (mut manager, pair) = terminal(false);
    let mut attributes = manager.attributes(pair.slave_object_id).unwrap();
    attributes.input_flags |= wire::TERMINAL_IFLAG_ISTRIP | wire::TERMINAL_IFLAG_IGNCR;
    manager
        .set_attributes(pair.slave_object_id, attributes)
        .unwrap();
    manager
        .write(pair.master_object_id, b"\x16\x83\x16\r\n")
        .unwrap();
    assert_eq!(manager.take_terminal_signal(), None);
    assert_eq!(
        manager.read(pair.slave_object_id, 100),
        Ok(b"\x03\r\n".to_vec())
    );
}

#[test]
fn disabling_extending_processing_or_its_character_preserves_ordinary_input() {
    for mode in 0..3 {
        let (mut manager, pair) = terminal(false);
        let mut attributes = manager.attributes(pair.slave_object_id).unwrap();
        match mode {
            0 => attributes.local_flags &= !wire::TERMINAL_LFLAG_IEXTEN,
            1 => attributes.local_flags &= !wire::TERMINAL_LFLAG_ICANON,
            _ => attributes.control_characters[wire::TERMINAL_CC_VLNEXT] = 0,
        }
        manager
            .set_attributes(pair.slave_object_id, attributes)
            .unwrap();
        manager.write(pair.master_object_id, b"\x16x\n").unwrap();
        assert_eq!(
            manager.read(pair.slave_object_id, 100),
            Ok(b"\x16x\n".to_vec())
        );
    }
}

#[test]
fn quoted_byte_is_not_consumed_when_echo_is_full_and_can_be_retried() {
    let (mut manager, pair) = terminal(true);
    manager.write(pair.master_object_id, &[22]).unwrap();
    assert_eq!(
        manager.read(pair.master_object_id, 100),
        Ok(b"^\x08".to_vec())
    );
    manager
        .write(pair.slave_object_id, &vec![b'x'; BUFFER_CAPACITY])
        .unwrap();
    assert_eq!(manager.write(pair.master_object_id, &[3]), Err(EAGAIN));
    assert_eq!(manager.take_terminal_signal(), None);
    manager
        .read(pair.master_object_id, BUFFER_CAPACITY)
        .unwrap();
    assert_eq!(manager.write(pair.master_object_id, &[3]), Ok(1));
    manager.write(pair.master_object_id, b"\n").unwrap();
    assert_eq!(
        manager.read(pair.slave_object_id, 100),
        Ok(b"\x03\n".to_vec())
    );
    assert_eq!(manager.take_terminal_signal(), None);
}

#[test]
fn literal_prefix_echo_is_atomic_when_only_one_output_byte_remains() {
    let (mut manager, pair) = terminal(true);
    manager
        .write(pair.slave_object_id, &vec![b'x'; BUFFER_CAPACITY - 1])
        .unwrap();
    assert_eq!(manager.write(pair.master_object_id, &[22]), Err(EAGAIN));
    assert_eq!(
        manager.read(pair.master_object_id, BUFFER_CAPACITY),
        Ok(vec![b'x'; BUFFER_CAPACITY - 1])
    );
    assert_eq!(manager.write(pair.master_object_id, &[22, 3]), Ok(2));
    assert_eq!(
        manager.read(pair.master_object_id, 100),
        Ok(b"^\x08\x03".to_vec())
    );
    assert_eq!(manager.take_terminal_signal(), None);
    manager.write(pair.master_object_id, b"\n").unwrap();
    assert_eq!(
        manager.read(pair.slave_object_id, 100),
        Ok(b"\x03\n".to_vec())
    );
}

#[test]
fn remapped_literal_character_and_output_only_flush_keep_pending_input_state() {
    let (mut manager, pair) = terminal(false);
    let mut attributes = manager.attributes(pair.slave_object_id).unwrap();
    attributes.control_characters[wire::TERMINAL_CC_VLNEXT] = b'!';
    manager
        .set_attributes(pair.slave_object_id, attributes)
        .unwrap();
    manager.write(pair.master_object_id, b"\x16!").unwrap();
    let mut encoded = [0; 4];
    wire::encode_terminal_flush(wire::TERMINAL_FLUSH_OUTPUT, &mut encoded).unwrap();
    manager
        .control(pair.slave_object_id, wire::PTY_CONTROL_FLUSH, &encoded, 0)
        .unwrap();
    // An unrelated termios update must not consume the next input byte either.
    attributes.input_flags |= wire::TERMINAL_IFLAG_IUTF8;
    manager
        .set_attributes(pair.slave_object_id, attributes)
        .unwrap();
    manager.write(pair.master_object_id, b"\x03\n").unwrap();
    assert_eq!(manager.take_terminal_signal(), None);
    assert_eq!(
        manager.read(pair.slave_object_id, 100),
        Ok(b"\x16\x03\n".to_vec())
    );
}

#[test]
fn full_input_never_swallows_a_literal_prefix() {
    let (mut manager, pair) = terminal(false);
    // Keep the queue truly full while the pending line remains below its
    // own limit: committed input is readable and must not be discarded.
    manager.write(pair.master_object_id, b"a\n").unwrap();
    manager
        .write(pair.master_object_id, &vec![b'x'; BUFFER_CAPACITY - 2])
        .unwrap();
    assert_eq!(manager.write(pair.master_object_id, &[22]), Err(EAGAIN));
    assert_eq!(manager.write(pair.master_object_id, &[127]), Ok(1));
    assert_eq!(manager.write(pair.master_object_id, &[22, 3]), Ok(2));
    assert_eq!(manager.take_terminal_signal(), None);
    assert_eq!(manager.read(pair.slave_object_id, 2), Ok(b"a\n".to_vec()));
    manager.write(pair.master_object_id, &[4]).unwrap();
    let mut expected = vec![b'x'; BUFFER_CAPACITY - 3];
    expected.push(3);
    assert_eq!(
        manager.read(pair.slave_object_id, BUFFER_CAPACITY),
        Ok(expected)
    );
}

#[test]
fn input_flush_and_mode_changes_retire_pending_quote_but_other_terminals_do_not() {
    for mode in 0..4 {
        let (mut manager, pair) = terminal(false);
        manager.write(pair.master_object_id, &[22]).unwrap();
        if mode == 0 {
            let mut encoded = [0; 4];
            wire::encode_terminal_flush(wire::TERMINAL_FLUSH_INPUT, &mut encoded).unwrap();
            manager
                .control(pair.slave_object_id, wire::PTY_CONTROL_FLUSH, &encoded, 0)
                .unwrap();
        } else {
            let mut attributes = manager.attributes(pair.slave_object_id).unwrap();
            if mode == 1 {
                attributes.local_flags &= !wire::TERMINAL_LFLAG_IEXTEN;
            }
            if mode == 2 {
                attributes.local_flags &= !wire::TERMINAL_LFLAG_ICANON;
            }
            if mode == 3 {
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
                manager
                    .set_attributes(pair.slave_object_id, attributes)
                    .unwrap();
            }
        }
        manager.write(pair.master_object_id, &[3]).unwrap();
        assert_eq!(
            manager.take_terminal_signal().unwrap().signal,
            wire::SIGNAL_INT
        );
    }
    let (mut manager, first) = terminal(false);
    let second = manager.open().unwrap();
    manager.write(first.master_object_id, &[22]).unwrap();
    manager.write(second.master_object_id, &[3]).unwrap();
    manager.take_terminal_signal().unwrap();
    manager.write(first.master_object_id, b"\x03\n").unwrap();
    assert_eq!(manager.take_terminal_signal(), None);
    assert_eq!(
        manager.read(first.slave_object_id, 100),
        Ok(b"\x03\n".to_vec())
    );
}
