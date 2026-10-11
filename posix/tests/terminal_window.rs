use mochios_posix_protocol as protocol;
use posix_service::pty::{PtyManager, EBADF, EINVAL};

fn get(manager: &mut PtyManager, object: u64) -> protocol::TerminalWindowSize {
    let bytes = manager
        .control(object, protocol::PTY_CONTROL_GET_WINDOW_SIZE, &[], 8)
        .unwrap();
    protocol::decode_terminal_window_size(&bytes).unwrap()
}

#[test]
fn window_codec_is_exact_little_endian_and_preserves_all_fields() {
    let size = protocol::TerminalWindowSize {
        rows: 0x1234,
        columns: 0x5678,
        pixel_width: 0x9abc,
        pixel_height: 0xdef0,
    };
    let mut bytes = [0; 8];
    protocol::encode_terminal_window_size(size, &mut bytes).unwrap();
    assert_eq!(bytes, [0x34, 0x12, 0x78, 0x56, 0xbc, 0x9a, 0xf0, 0xde]);
    assert_eq!(protocol::decode_terminal_window_size(&bytes), Ok(size));
    assert!(protocol::encode_terminal_window_size(size, &mut [0; 7]).is_err());
    assert!(protocol::decode_terminal_window_size(&bytes[..7]).is_err());
    assert!(protocol::decode_terminal_window_size(&[0; 9]).is_err());
}

#[test]
fn both_pty_sides_share_size_and_only_changes_generate_winch() {
    let mut manager = PtyManager::new();
    let pair = manager.open().unwrap();
    let other = manager.open().unwrap();
    assert_eq!(get(&mut manager, pair.master_object_id), Default::default());
    let size = protocol::TerminalWindowSize {
        rows: 42,
        columns: 132,
        pixel_width: 1920,
        pixel_height: 1080,
    };
    let mut bytes = [0; 8];
    protocol::encode_terminal_window_size(size, &mut bytes).unwrap();
    manager
        .control(
            pair.master_object_id,
            protocol::PTY_CONTROL_SET_WINDOW_SIZE,
            &bytes,
            0,
        )
        .unwrap();
    assert_eq!(get(&mut manager, pair.slave_object_id), size);
    assert_eq!(
        get(&mut manager, other.master_object_id),
        Default::default()
    );
    let signal = manager.take_terminal_signal().unwrap();
    assert_eq!(signal.signal, protocol::SIGNAL_WINCH);
    assert_eq!(
        signal.terminal_id,
        manager.slave_terminal_id(pair.slave_object_id).unwrap()
    );
    assert!(manager.take_terminal_signal().is_none());
    manager
        .control(
            pair.slave_object_id,
            protocol::PTY_CONTROL_SET_WINDOW_SIZE,
            &bytes,
            0,
        )
        .unwrap();
    assert!(manager.take_terminal_signal().is_none());
    bytes[4] += 1;
    manager
        .control(
            pair.slave_object_id,
            protocol::PTY_CONTROL_SET_WINDOW_SIZE,
            &bytes,
            0,
        )
        .unwrap();
    assert_eq!(
        manager.take_terminal_signal().unwrap().signal,
        protocol::SIGNAL_WINCH
    );
}

#[test]
fn malformed_requests_do_not_change_size_or_enqueue_signals() {
    let mut manager = PtyManager::new();
    let pair = manager.open().unwrap();
    for (code, input, capacity) in [
        (protocol::PTY_CONTROL_SET_WINDOW_SIZE, &[1; 7][..], 0),
        (protocol::PTY_CONTROL_SET_WINDOW_SIZE, &[1; 9][..], 0),
        (protocol::PTY_CONTROL_SET_WINDOW_SIZE, &[1; 8][..], 1),
        (protocol::PTY_CONTROL_GET_WINDOW_SIZE, &[1][..], 8),
        (protocol::PTY_CONTROL_GET_WINDOW_SIZE, &[][..], 7),
    ] {
        assert_eq!(
            manager.control(pair.slave_object_id, code, input, capacity),
            Err(EINVAL)
        );
        assert_eq!(get(&mut manager, pair.slave_object_id), Default::default());
        assert!(manager.take_terminal_signal().is_none());
    }
    assert_eq!(
        manager.control(0, protocol::PTY_CONTROL_SET_WINDOW_SIZE, &[0; 8], 0),
        Err(EBADF)
    );
    manager.discard(pair);
    assert_eq!(
        manager.control(
            pair.slave_object_id,
            protocol::PTY_CONTROL_GET_WINDOW_SIZE,
            &[],
            8
        ),
        Err(EBADF)
    );
}
