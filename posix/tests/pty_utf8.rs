//! Canonical editing is byte preserving except for explicitly enabled IUTF8.
use mochios_posix_protocol as wire;
use posix_service::pty::{BUFFER_CAPACITY, EAGAIN, PtyManager, PtyPair};

fn terminal(utf8: bool, echo: bool) -> (PtyManager, PtyPair) {
    let mut manager = PtyManager::new();
    let pair = manager.open().unwrap();
    let mut attributes = manager.attributes(pair.slave_object_id).unwrap();
    if utf8 {
        attributes.input_flags |= wire::TERMINAL_IFLAG_IUTF8;
    }
    if !echo {
        attributes.local_flags &= !wire::TERMINAL_LFLAG_ECHO;
    }
    manager
        .set_attributes(pair.slave_object_id, attributes)
        .unwrap();
    (manager, pair)
}

#[test]
fn erase_removes_one_complete_scalar_across_individual_writes() {
    for text in ["x", "é", "あ", "😀", "e\u{301}"] {
        let (mut manager, pair) = terminal(true, false);
        for byte in format!("prefix{text}").bytes() {
            assert_eq!(manager.write(pair.master_object_id, &[byte]), Ok(1));
        }
        assert_eq!(manager.write(pair.master_object_id, b"\x7f\n"), Ok(2));
        let last = text.char_indices().last().unwrap().0;
        let expected = format!("prefix{}\n", &text[..last]);
        assert_eq!(
            manager.read(pair.slave_object_id, 100),
            Ok(expected.into_bytes())
        );
        assert_eq!(manager.read(pair.slave_object_id, 100), Err(EAGAIN));
    }
}

#[test]
fn disabling_utf8_preserves_bytewise_erasure_and_raw_mode_preserves_erase() {
    let (mut manager, pair) = terminal(false, false);
    assert_eq!(manager.write(pair.master_object_id, "あ".as_bytes()), Ok(3));
    manager.write(pair.master_object_id, b"\x7f\n").unwrap();
    assert_eq!(
        manager.read(pair.slave_object_id, 100),
        Ok(vec![0xe3, 0x81, b'\n'])
    );

    let (mut manager, pair) = terminal(true, false);
    let mut attributes = manager.attributes(pair.slave_object_id).unwrap();
    attributes.local_flags &= !wire::TERMINAL_LFLAG_ICANON;
    manager
        .set_attributes(pair.slave_object_id, attributes)
        .unwrap();
    let bytes = "あ\u{7f}".as_bytes();
    assert_eq!(manager.write(pair.master_object_id, bytes), Ok(bytes.len()));
    assert_eq!(manager.read(pair.slave_object_id, 100), Ok(bytes.to_vec()));
}

#[test]
fn invalid_utf8_erases_only_one_byte_without_eating_a_valid_prefix() {
    for suffix in [
        &[0x80][..],
        &[0xe3, 0x81],
        &[0xc0, 0xaf],
        &[0xed, 0xa0, 0x80],
        &[0xf4, 0x90, 0x80, 0x80],
        &[0xff],
        &[0x80, 0x80, 0x80, 0x80, 0x80],
    ] {
        let (mut manager, pair) = terminal(true, false);
        manager.write(pair.master_object_id, b"prefix").unwrap();
        manager.write(pair.master_object_id, suffix).unwrap();
        manager.write(pair.master_object_id, b"\x7f\n").unwrap();
        let mut expected = b"prefix".to_vec();
        expected.extend_from_slice(&suffix[..suffix.len() - 1]);
        expected.push(b'\n');
        assert_eq!(manager.read(pair.slave_object_id, 100), Ok(expected));
    }
}

#[test]
fn erasure_cannot_cross_committed_record_boundaries() {
    let (mut manager, pair) = terminal(true, false);
    let first = "firstあ\n".as_bytes();
    manager.write(pair.master_object_id, first).unwrap();
    manager.write(pair.master_object_id, b"\x7f\n").unwrap();
    assert_eq!(manager.read(pair.slave_object_id, 100), Ok(first.to_vec()));
    assert_eq!(manager.read(pair.slave_object_id, 100), Ok(b"\n".to_vec()));
}

#[test]
fn a_multibyte_character_emits_one_erase_and_backpressure_never_edits_early() {
    let (mut manager, pair) = terminal(true, true);
    manager
        .write(pair.master_object_id, "あ".as_bytes())
        .unwrap();
    assert_eq!(
        manager.read(pair.master_object_id, 100),
        Ok("あ".as_bytes().to_vec())
    );
    assert_eq!(
        manager.write(pair.slave_object_id, &vec![b'x'; BUFFER_CAPACITY]),
        Ok(BUFFER_CAPACITY)
    );
    assert_eq!(manager.write(pair.master_object_id, b"\x7f"), Err(EAGAIN));
    assert_eq!(
        manager.read(pair.master_object_id, BUFFER_CAPACITY),
        Ok(vec![b'x'; BUFFER_CAPACITY])
    );
    assert_eq!(manager.write(pair.master_object_id, b"\x7f"), Ok(1));
    assert_eq!(
        manager.read(pair.master_object_id, 100),
        Ok(b"\x08 \x08".to_vec())
    );
    manager.write(pair.master_object_id, b"\n").unwrap();
    assert_eq!(manager.read(pair.slave_object_id, 100), Ok(b"\n".to_vec()));
}

#[test]
fn complete_utf8_suffix_can_be_erased_after_invalid_bytes_and_queue_reuse() {
    let (mut manager, pair) = terminal(true, false);
    // Reuse the input queues without assuming anything about their storage.
    for _ in 0..100 {
        manager
            .write(pair.master_object_id, "あ\n".as_bytes())
            .unwrap();
        manager.read(pair.slave_object_id, 100).unwrap();
    }
    manager.write(pair.master_object_id, b"\xff").unwrap();
    manager
        .write(pair.master_object_id, "😀".as_bytes())
        .unwrap();
    manager.write(pair.master_object_id, b"\x7f\n").unwrap();
    assert_eq!(
        manager.read(pair.slave_object_id, 100),
        Ok(vec![0xff, b'\n'])
    );
}
