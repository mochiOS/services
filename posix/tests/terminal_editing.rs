use mochios_posix_protocol as wire;
use posix_service::pty::{BUFFER_CAPACITY, EAGAIN, PtyManager, PtyPair};

fn terminal(echo: bool) -> (PtyManager, PtyPair) {
    let mut manager = PtyManager::new();
    let pair = manager.open().unwrap();
    let mut attributes = manager.attributes(pair.slave_object_id).unwrap();
    attributes.local_flags |= wire::TERMINAL_LFLAG_IEXTEN;
    attributes.input_flags |= wire::TERMINAL_IFLAG_IUTF8;
    if !echo {
        attributes.local_flags &= !wire::TERMINAL_LFLAG_ECHO;
    }
    manager
        .set_attributes(pair.slave_object_id, attributes)
        .unwrap();
    (manager, pair)
}

fn output(manager: &mut PtyManager, pair: PtyPair) -> Vec<u8> {
    let mut result = vec![];
    loop {
        match manager.read(pair.master_object_id, 997) {
            Ok(bytes) if !bytes.is_empty() => result.extend(bytes),
            Err(EAGAIN) => return result,
            other => panic!("unexpected output: {other:?}"),
        }
    }
}

#[test]
fn word_erase_removes_trailing_ascii_whitespace_then_the_last_word() {
    for (input, expected) in [
        ("one two  \t", "one "),
        ("one 日本語", "one "),
        ("one !!!", "one "),
        ("   ", ""),
        ("", ""),
    ] {
        let (mut manager, pair) = terminal(false);
        manager
            .write(pair.master_object_id, input.as_bytes())
            .unwrap();
        manager.write(pair.master_object_id, b"\x17\n").unwrap();
        assert_eq!(
            manager.read(pair.slave_object_id, 100),
            Ok(format!("{expected}\n").into_bytes())
        );
    }
}

#[test]
fn edits_do_not_cross_records_and_reprint_never_becomes_input() {
    let (mut manager, pair) = terminal(true);
    manager
        .write(pair.master_object_id, b"committed\ncurrent word")
        .unwrap();
    output(&mut manager, pair);
    manager.write(pair.master_object_id, b"\x17\x12").unwrap();
    assert_eq!(
        output(&mut manager, pair),
        b"\x08 \x08"
            .repeat(4)
            .into_iter()
            .chain(b"\x12\r\ncurrent ".iter().copied())
            .collect::<Vec<_>>()
    );
    assert_eq!(
        manager.read(pair.slave_object_id, 100),
        Ok(b"committed\n".to_vec())
    );
    assert_eq!(manager.read(pair.slave_object_id, 100), Err(EAGAIN));
    manager.write(pair.master_object_id, b"\n").unwrap();
    assert_eq!(
        manager.read(pair.slave_object_id, 100),
        Ok(b"current \n".to_vec())
    );
}

#[test]
fn utf8_word_erase_echoes_once_per_scalar_and_invalid_bytes_are_preserved_safely() {
    let (mut manager, pair) = terminal(true);
    manager
        .write(pair.master_object_id, "prefix あ😀".as_bytes())
        .unwrap();
    output(&mut manager, pair);
    manager.write(pair.master_object_id, &[23]).unwrap();
    assert_eq!(output(&mut manager, pair), b"\x08 \x08".repeat(2));
    manager
        .write(pair.master_object_id, b"\xff\x80\x17\n")
        .unwrap();
    assert_eq!(
        manager.read(pair.slave_object_id, 100),
        Ok(b"prefix \n".to_vec())
    );
}

#[test]
fn controls_are_ordinary_when_disabled_or_raw_and_literal_next_quotes_them() {
    for mode in 0..3 {
        let (mut manager, pair) = terminal(false);
        let mut attributes = manager.attributes(pair.slave_object_id).unwrap();
        match mode {
            0 => attributes.local_flags &= !wire::TERMINAL_LFLAG_IEXTEN,
            1 => attributes.local_flags &= !wire::TERMINAL_LFLAG_ICANON,
            _ => {
                attributes.control_characters[wire::TERMINAL_CC_VWERASE] = 0;
                attributes.control_characters[wire::TERMINAL_CC_VREPRINT] = 0;
            }
        }
        manager
            .set_attributes(pair.slave_object_id, attributes)
            .unwrap();
        manager
            .write(pair.master_object_id, b"a\x17\x12\n")
            .unwrap();
        assert_eq!(
            manager.read(pair.slave_object_id, 100),
            Ok(b"a\x17\x12\n".to_vec())
        );
    }
    let (mut manager, pair) = terminal(false);
    manager
        .write(pair.master_object_id, b"a\x16\x17\x16\x12\n")
        .unwrap();
    assert_eq!(
        manager.read(pair.slave_object_id, 100),
        Ok(b"a\x17\x12\n".to_vec())
    );
}

#[test]
fn long_word_echo_is_bounded_ordered_and_drains_in_multiple_reads() {
    let (mut manager, pair) = terminal(false);
    manager
        .write(pair.master_object_id, &vec![b'x'; BUFFER_CAPACITY])
        .unwrap();
    let mut attributes = manager.attributes(pair.slave_object_id).unwrap();
    attributes.local_flags |= wire::TERMINAL_LFLAG_ECHO;
    manager
        .set_attributes(pair.slave_object_id, attributes)
        .unwrap();
    manager.write(pair.slave_object_id, b"before").unwrap();
    assert_eq!(manager.write(pair.master_object_id, &[23]), Ok(1));
    assert_eq!(manager.write(pair.slave_object_id, b"after"), Err(EAGAIN));
    assert_eq!(manager.write(pair.master_object_id, b"later"), Err(EAGAIN));
    let mut expected = b"before".to_vec();
    expected.extend(b"\x08 \x08".repeat(BUFFER_CAPACITY));
    assert_eq!(output(&mut manager, pair), expected);
    manager.write(pair.slave_object_id, b"after").unwrap();
    assert_eq!(output(&mut manager, pair), b"after");
    manager.write(pair.master_object_id, b"\n").unwrap();
    assert_eq!(manager.read(pair.slave_object_id, 100), Ok(b"\n".to_vec()));
}

#[test]
fn reprint_larger_than_the_output_queue_preserves_every_byte_and_original_input() {
    let (mut manager, pair) = terminal(false);
    let line = vec![b'x'; BUFFER_CAPACITY];
    manager.write(pair.master_object_id, &line).unwrap();
    let mut attributes = manager.attributes(pair.slave_object_id).unwrap();
    attributes.local_flags |= wire::TERMINAL_LFLAG_ECHO;
    manager
        .set_attributes(pair.slave_object_id, attributes)
        .unwrap();
    assert_eq!(manager.write(pair.master_object_id, &[18, 18]), Ok(1));
    let mut expected = b"\x12\r\n".to_vec();
    expected.extend_from_slice(&line);
    assert_eq!(output(&mut manager, pair), expected);
    assert_eq!(manager.write(pair.master_object_id, &[18]), Ok(1));
    assert_eq!(output(&mut manager, pair), expected);
    manager.write(pair.master_object_id, &[4]).unwrap();
    assert_eq!(
        manager.read(pair.slave_object_id, BUFFER_CAPACITY),
        Ok(line)
    );
}

#[test]
fn output_flush_retires_deferred_echo_and_releases_backpressure() {
    let (mut manager, pair) = terminal(false);
    manager
        .write(pair.master_object_id, &vec![b'x'; BUFFER_CAPACITY])
        .unwrap();
    let mut attributes = manager.attributes(pair.slave_object_id).unwrap();
    attributes.local_flags |= wire::TERMINAL_LFLAG_ECHO;
    manager
        .set_attributes(pair.slave_object_id, attributes)
        .unwrap();
    manager.write(pair.master_object_id, &[23]).unwrap();
    let mut encoded = [0; 4];
    wire::encode_terminal_flush(wire::TERMINAL_FLUSH_OUTPUT, &mut encoded).unwrap();
    manager
        .control(pair.slave_object_id, wire::PTY_CONTROL_FLUSH, &encoded, 0)
        .unwrap();
    assert_eq!(output(&mut manager, pair), b"");
    assert_ne!(
        manager.signals(pair.master_object_id).unwrap() & mnu_abi::HANDLE_SIGNAL_WRITABLE,
        0
    );
    manager.write(pair.master_object_id, b"fresh\n").unwrap();
    assert_eq!(
        manager.read(pair.slave_object_id, 100),
        Ok(b"fresh\n".to_vec())
    );
}

#[test]
fn deferred_reprint_keeps_original_output_encoding_across_termios_changes() {
    let (mut manager, pair) = terminal(false);
    // Quoted newlines are input data and expand to CR/NL in the reprint.
    let mut line = vec![b'x'; BUFFER_CAPACITY - 2];
    line.extend_from_slice(b"\x16\n");
    manager.write(pair.master_object_id, &line).unwrap();
    let mut attributes = manager.attributes(pair.slave_object_id).unwrap();
    attributes.local_flags |= wire::TERMINAL_LFLAG_ECHO;
    manager
        .set_attributes(pair.slave_object_id, attributes)
        .unwrap();
    manager.write(pair.master_object_id, &[18]).unwrap();
    attributes.output_flags = 0;
    manager
        .set_attributes(pair.slave_object_id, attributes)
        .unwrap();
    let mut expected = b"\x12\r\n".to_vec();
    expected.extend(vec![b'x'; BUFFER_CAPACITY - 2]);
    expected.extend_from_slice(b"\r\n");
    assert_eq!(output(&mut manager, pair), expected);
}

#[test]
fn deferred_echo_obeys_flow_control_and_signal_flush_policy() {
    for no_flush in [false, true] {
        let (mut manager, pair) = terminal(false);
        manager
            .write(pair.master_object_id, &vec![b'x'; BUFFER_CAPACITY])
            .unwrap();
        let mut attributes = manager.attributes(pair.slave_object_id).unwrap();
        attributes.local_flags |= wire::TERMINAL_LFLAG_ECHO;
        attributes.input_flags |= wire::TERMINAL_IFLAG_IXON;
        if no_flush {
            attributes.local_flags |= wire::TERMINAL_LFLAG_NOFLSH;
        }
        manager
            .set_attributes(pair.slave_object_id, attributes)
            .unwrap();
        manager.write(pair.master_object_id, &[23]).unwrap();
        manager.write(pair.master_object_id, &[19]).unwrap();
        assert_eq!(manager.read(pair.master_object_id, 100), Err(EAGAIN));
        assert_eq!(
            manager.signals(pair.master_object_id).unwrap() & mnu_abi::HANDLE_SIGNAL_READABLE,
            0
        );
        manager.write(pair.master_object_id, &[17, 3]).unwrap();
        assert_eq!(
            manager.take_terminal_signal().unwrap().signal,
            wire::SIGNAL_INT
        );
        let expected = if no_flush {
            b"\x08 \x08".repeat(BUFFER_CAPACITY)
        } else {
            vec![]
        };
        assert_eq!(output(&mut manager, pair), expected);
    }
}

#[test]
fn deferred_echo_survives_slave_close_and_dead_master_drain_discards_it() {
    for close_master in [false, true] {
        let (mut manager, pair) = terminal(false);
        manager
            .write(pair.master_object_id, &vec![b'x'; BUFFER_CAPACITY])
            .unwrap();
        let mut attributes = manager.attributes(pair.slave_object_id).unwrap();
        attributes.local_flags |= wire::TERMINAL_LFLAG_ECHO;
        manager
            .set_attributes(pair.slave_object_id, attributes)
            .unwrap();
        manager.write(pair.master_object_id, &[23]).unwrap();
        if close_master {
            manager.release(pair.master_object_id).unwrap();
            assert_eq!(
                manager.control(pair.slave_object_id, wire::PTY_CONTROL_DRAIN, &[], 0),
                Ok(vec![])
            );
            assert_eq!(
                manager.control(
                    pair.slave_object_id,
                    wire::PTY_CONTROL_SET_ATTRIBUTES_DRAIN,
                    &{
                        let mut bytes = [0; wire::TERMINAL_ATTRIBUTES_LEN];
                        wire::encode_terminal_attributes(attributes, &mut bytes).unwrap();
                        bytes
                    },
                    0
                ),
                Ok(vec![])
            );
        } else {
            manager.release(pair.slave_object_id).unwrap();
            let mut bytes = vec![];
            loop {
                let part = manager.read(pair.master_object_id, 997).unwrap();
                if part.is_empty() {
                    break;
                }
                bytes.extend(part);
            }
            assert_eq!(bytes, b"\x08 \x08".repeat(BUFFER_CAPACITY));
        }
    }
}
