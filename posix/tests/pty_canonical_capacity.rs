use mochios_posix_protocol as wire;
use posix_service::pty::{BUFFER_CAPACITY, EAGAIN, PtyManager, PtyPair};

fn terminal() -> (PtyManager, PtyPair) {
    let mut manager = PtyManager::new();
    let pair = manager.open().unwrap();
    let mut attributes = manager.attributes(pair.slave_object_id).unwrap();
    attributes.local_flags &= !wire::TERMINAL_LFLAG_ECHO;
    attributes.local_flags |= wire::TERMINAL_LFLAG_IEXTEN;
    manager
        .set_attributes(pair.slave_object_id, attributes)
        .unwrap();
    (manager, pair)
}

fn fill(manager: &mut PtyManager, pair: PtyPair) {
    assert_eq!(
        manager.write(pair.master_object_id, &vec![b'x'; BUFFER_CAPACITY - 1]),
        Ok(BUFFER_CAPACITY - 1)
    );
    assert_eq!(manager.read(pair.slave_object_id, 1), Err(EAGAIN));
}

#[test]
fn overlong_canonical_input_keeps_a_terminator_slot_and_never_traps_the_reader() {
    let (mut manager, pair) = terminal();
    assert_eq!(
        manager.write(pair.master_object_id, &vec![b'x'; BUFFER_CAPACITY + 17]),
        Ok(BUFFER_CAPACITY + 17)
    );
    assert_eq!(manager.read(pair.slave_object_id, 1), Err(EAGAIN));
    assert_eq!(manager.write(pair.master_object_id, b"\n"), Ok(1));
    let mut expected = vec![b'x'; BUFFER_CAPACITY - 1];
    expected.push(b'\n');
    assert_eq!(
        manager.read(pair.slave_object_id, BUFFER_CAPACITY),
        Ok(expected)
    );
    assert_eq!(manager.read(pair.slave_object_id, 1), Err(EAGAIN));
}

#[test]
fn configured_and_transformed_line_delimiters_use_the_reserved_slot() {
    for (source, delimiter) in [(b'|', b'|'), (b';', b';'), (b'\r', b'\n')] {
        let (mut manager, pair) = terminal();
        let mut attributes = manager.attributes(pair.slave_object_id).unwrap();
        attributes.control_characters[wire::TERMINAL_CC_VEOL] = b'|';
        attributes.control_characters[wire::TERMINAL_CC_VEOL2] = b';';
        manager
            .set_attributes(pair.slave_object_id, attributes)
            .unwrap();
        fill(&mut manager, pair);
        assert_eq!(manager.write(pair.master_object_id, b"discard"), Ok(7));
        assert_eq!(manager.write(pair.master_object_id, &[source]), Ok(1));
        let mut expected = vec![b'x'; BUFFER_CAPACITY - 1];
        expected.push(delimiter);
        assert_eq!(
            manager.read(pair.slave_object_id, BUFFER_CAPACITY),
            Ok(expected)
        );
    }
}

#[test]
fn literal_next_cannot_consume_the_reserved_line_terminator() {
    let (mut manager, pair) = terminal();
    fill(&mut manager, pair);
    let literal = manager
        .attributes(pair.slave_object_id)
        .unwrap()
        .control_characters[wire::TERMINAL_CC_VLNEXT];
    assert_ne!(literal, 0);
    assert_eq!(manager.write(pair.master_object_id, &[literal]), Ok(1));
    assert_eq!(manager.write(pair.master_object_id, b"\n"), Ok(1));
    assert_eq!(manager.read(pair.slave_object_id, 1), Err(EAGAIN));
    assert_eq!(manager.write(pair.master_object_id, b"\n"), Ok(1));
    let line = manager.read(pair.slave_object_id, BUFFER_CAPACITY).unwrap();
    assert_eq!(line.len(), BUFFER_CAPACITY);
    assert!(line[..line.len() - 1].iter().all(|&b| b == b'x'));
    assert_eq!(line.last(), Some(&b'\n'));
}

#[test]
fn editing_and_signals_still_work_after_a_line_reaches_its_limit() {
    let (mut manager, pair) = terminal();
    fill(&mut manager, pair);
    let attributes = manager.attributes(pair.slave_object_id).unwrap();
    let erase = attributes.control_characters[wire::TERMINAL_CC_VERASE];
    assert_eq!(
        manager.write(pair.master_object_id, &[erase, b'z', b'q', b'\n']),
        Ok(4)
    );
    let line = manager.read(pair.slave_object_id, BUFFER_CAPACITY).unwrap();
    assert_eq!(line.len(), BUFFER_CAPACITY);
    assert_eq!(&line[line.len() - 2..], b"z\n");
    fill(&mut manager, pair);
    let interrupt = attributes.control_characters[wire::TERMINAL_CC_VINTR];
    assert_eq!(manager.write(pair.master_object_id, &[interrupt]), Ok(1));
    assert_eq!(
        manager.take_terminal_signal().unwrap().signal,
        wire::SIGNAL_INT
    );
    assert_eq!(manager.write(pair.master_object_id, b"fresh\n"), Ok(6));
    assert_eq!(
        manager.read(pair.slave_object_id, 100),
        Ok(b"fresh\n".to_vec())
    );
}

#[test]
fn committed_unread_data_keeps_backpressure_instead_of_discarding_a_short_line() {
    let (mut manager, pair) = terminal();
    assert_eq!(manager.write(pair.master_object_id, b"old\n"), Ok(4));
    let input = vec![b'x'; BUFFER_CAPACITY - 4];
    assert_eq!(
        manager.write(pair.master_object_id, &input),
        Ok(input.len())
    );
    assert_eq!(manager.write(pair.master_object_id, b"z\n"), Err(EAGAIN));
    assert_eq!(manager.read(pair.slave_object_id, 4), Ok(b"old\n".to_vec()));
    assert_eq!(manager.write(pair.master_object_id, b"z\n"), Ok(2));
    let mut expected = input;
    expected.extend_from_slice(b"z\n");
    assert_eq!(
        manager.read(pair.slave_object_id, BUFFER_CAPACITY),
        Ok(expected)
    );
}

#[test]
fn raw_input_retains_all_bytes_and_the_existing_backpressure_limit() {
    let (mut manager, pair) = terminal();
    let mut attributes = manager.attributes(pair.slave_object_id).unwrap();
    attributes.local_flags &= !wire::TERMINAL_LFLAG_ICANON;
    manager
        .set_attributes(pair.slave_object_id, attributes)
        .unwrap();
    assert_eq!(
        manager.write(pair.master_object_id, &vec![b'x'; BUFFER_CAPACITY + 17]),
        Ok(BUFFER_CAPACITY)
    );
    assert_eq!(manager.write(pair.master_object_id, b"\n"), Err(EAGAIN));
    assert_eq!(
        manager.read(pair.slave_object_id, BUFFER_CAPACITY).unwrap(),
        vec![b'x'; BUFFER_CAPACITY]
    );
}
