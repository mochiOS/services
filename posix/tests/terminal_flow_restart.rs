//! Software restart policy lives in the provider's terminal state, not mnu.
use mnu_abi::HANDLE_SIGNAL_READABLE;
use mochios_posix_protocol as wire;
use posix_service::pty::{BUFFER_CAPACITY, EAGAIN, PtyManager, PtyPair};

fn setup(canonical: bool) -> (PtyManager, PtyPair) {
    let mut manager = PtyManager::new();
    let pair = manager.open().unwrap();
    let mut attributes = wire::TerminalAttributes::sane();
    attributes.input_flags = wire::TERMINAL_IFLAG_IXON | wire::TERMINAL_IFLAG_IXANY;
    attributes.output_flags = 0;
    attributes.local_flags = if canonical {
        wire::TERMINAL_LFLAG_ICANON
    } else {
        0
    };
    manager
        .set_attributes(pair.slave_object_id, attributes)
        .unwrap();
    (manager, pair)
}

#[test]
fn ordinary_input_restarts_output_without_consuming_the_restart_character() {
    for canonical in [false, true] {
        let (mut manager, pair) = setup(canonical);
        manager.write(pair.slave_object_id, b"queued").unwrap();
        manager.write(pair.master_object_id, b"\x13\x13").unwrap();
        assert_eq!(manager.read(pair.master_object_id, 100), Err(EAGAIN));
        manager.write(pair.master_object_id, b"x").unwrap();
        assert_ne!(
            manager.signals(pair.master_object_id).unwrap() & HANDLE_SIGNAL_READABLE,
            0
        );
        assert_eq!(
            manager.read(pair.master_object_id, 100),
            Ok(b"queued".to_vec())
        );
        if canonical {
            assert_eq!(manager.read(pair.slave_object_id, 100), Err(EAGAIN));
            manager.write(pair.master_object_id, b"\n").unwrap();
        }
        assert_eq!(
            manager.read(pair.slave_object_id, 100),
            Ok(if canonical {
                b"x\n".to_vec()
            } else {
                b"x".to_vec()
            })
        );
    }
}

#[test]
fn a_full_input_queue_cannot_trap_stopped_output_or_lose_the_retry_byte() {
    let (mut manager, pair) = setup(false);
    manager
        .write(pair.master_object_id, &vec![b'a'; BUFFER_CAPACITY])
        .unwrap();
    manager.write(pair.master_object_id, b"\x13").unwrap();
    manager
        .write(pair.slave_object_id, &vec![b'b'; BUFFER_CAPACITY])
        .unwrap();
    assert_eq!(manager.read(pair.master_object_id, 1), Err(EAGAIN));
    assert_eq!(manager.write(pair.master_object_id, b"x"), Err(EAGAIN));
    assert_eq!(
        manager.read(pair.master_object_id, BUFFER_CAPACITY),
        Ok(vec![b'b'; BUFFER_CAPACITY])
    );
    assert_eq!(
        manager.read(pair.slave_object_id, BUFFER_CAPACITY),
        Ok(vec![b'a'; BUFFER_CAPACITY])
    );
    assert_eq!(manager.write(pair.master_object_id, b"x"), Ok(1));
    assert_eq!(manager.read(pair.slave_object_id, 1), Ok(b"x".to_vec()));
}

#[test]
fn full_echo_output_can_drain_before_the_restart_input_is_retried() {
    let (mut manager, pair) = setup(true);
    let mut attributes = manager.attributes(pair.slave_object_id).unwrap();
    attributes.local_flags |= wire::TERMINAL_LFLAG_ECHO;
    manager
        .set_attributes(pair.slave_object_id, attributes)
        .unwrap();
    manager.write(pair.master_object_id, b"\x13").unwrap();
    manager
        .write(pair.slave_object_id, &vec![b'a'; BUFFER_CAPACITY])
        .unwrap();
    assert_eq!(manager.write(pair.master_object_id, b"x"), Err(EAGAIN));
    assert_eq!(
        manager.read(pair.master_object_id, BUFFER_CAPACITY),
        Ok(vec![b'a'; BUFFER_CAPACITY])
    );
    assert_eq!(manager.write(pair.master_object_id, b"x\n"), Ok(2));
    assert_eq!(
        manager.read(pair.master_object_id, 100),
        Ok(b"x\n".to_vec())
    );
    assert_eq!(manager.read(pair.slave_object_id, 100), Ok(b"x\n".to_vec()));
}

#[test]
fn terminal_control_roundtrips_ixany_without_changing_other_terminals() {
    let (mut manager, pair) = setup(false);
    let other = manager.open().unwrap();
    let mut attributes = manager.attributes(pair.slave_object_id).unwrap();
    attributes.input_flags |= wire::TERMINAL_IFLAG_ISTRIP;
    attributes.control_characters[wire::TERMINAL_CC_VSTOP] = b's';
    let mut bytes = [0; wire::TERMINAL_ATTRIBUTES_LEN];
    wire::encode_terminal_attributes(attributes, &mut bytes).unwrap();
    manager
        .control(
            pair.slave_object_id,
            wire::PTY_CONTROL_SET_ATTRIBUTES_NOW,
            &bytes,
            0,
        )
        .unwrap();
    let encoded = manager
        .control(
            pair.master_object_id,
            wire::PTY_CONTROL_GET_ATTRIBUTES,
            &[],
            bytes.len(),
        )
        .unwrap();
    assert_eq!(
        wire::decode_terminal_attributes(&encoded).unwrap(),
        attributes
    );
    manager.write(pair.slave_object_id, b"queued").unwrap();
    // The mapped STOP remains control input, not an IXANY restart.
    manager
        .write(pair.master_object_id, &[b's' | 0x80])
        .unwrap();
    assert_eq!(manager.read(pair.master_object_id, 100), Err(EAGAIN));
    manager
        .write(pair.master_object_id, &[b'x' | 0x80])
        .unwrap();
    assert_eq!(
        manager.read(pair.master_object_id, 100),
        Ok(b"queued".to_vec())
    );
    assert_eq!(manager.read(pair.slave_object_id, 100), Ok(b"x".to_vec()));
    assert_eq!(
        manager.attributes(other.slave_object_id).unwrap(),
        wire::TerminalAttributes::sane()
    );
}

#[test]
fn quoted_bytes_do_not_restart_but_unquoted_signal_characters_do() {
    let (mut manager, pair) = setup(true);
    let mut attributes = manager.attributes(pair.slave_object_id).unwrap();
    attributes.local_flags |=
        wire::TERMINAL_LFLAG_IEXTEN | wire::TERMINAL_LFLAG_ISIG | wire::TERMINAL_LFLAG_NOFLSH;
    // Literal-next itself is IXANY input. Disable IXANY while stopping and
    // quoting, then restore it to exercise the separately delivered quote.
    attributes.input_flags &= !wire::TERMINAL_IFLAG_IXANY;
    manager
        .set_attributes(pair.slave_object_id, attributes)
        .unwrap();
    manager.write(pair.master_object_id, b"\x13\x16").unwrap();
    attributes.input_flags |= wire::TERMINAL_IFLAG_IXANY;
    manager
        .set_attributes(pair.slave_object_id, attributes)
        .unwrap();
    manager.write(pair.slave_object_id, b"queued").unwrap();
    manager.write(pair.master_object_id, b"x").unwrap();
    assert_eq!(manager.read(pair.master_object_id, 100), Err(EAGAIN));
    manager.write(pair.master_object_id, b"\x03").unwrap();
    assert_eq!(
        manager.take_terminal_signal().unwrap().signal,
        wire::SIGNAL_INT
    );
    assert_eq!(
        manager.read(pair.master_object_id, 100),
        Ok(b"queued".to_vec())
    );
    manager.write(pair.master_object_id, b"\n").unwrap();
    assert_eq!(manager.read(pair.slave_object_id, 100), Ok(b"x\n".to_vec()));
}

#[test]
fn manual_output_stop_is_not_cleared_by_software_restart() {
    let (mut manager, pair) = setup(false);
    manager
        .control(
            pair.slave_object_id,
            wire::PTY_CONTROL_FLOW,
            &wire::TERMINAL_FLOW_OUTPUT_STOP.to_le_bytes(),
            0,
        )
        .unwrap();
    manager.write(pair.slave_object_id, b"queued").unwrap();
    manager.write(pair.master_object_id, b"x\x11").unwrap();
    assert_eq!(manager.read(pair.master_object_id, 100), Err(EAGAIN));
    assert_eq!(manager.read(pair.slave_object_id, 100), Ok(b"x".to_vec()));
    manager
        .control(
            pair.slave_object_id,
            wire::PTY_CONTROL_FLOW,
            &wire::TERMINAL_FLOW_OUTPUT_START.to_le_bytes(),
            0,
        )
        .unwrap();
    assert_eq!(
        manager.read(pair.master_object_id, 100),
        Ok(b"queued".to_vec())
    );
}

#[test]
fn identical_start_stop_characters_toggle_software_stop_with_or_without_ixany() {
    for ixany in [false, true] {
        let (mut manager, pair) = setup(false);
        let mut attributes = manager.attributes(pair.slave_object_id).unwrap();
        attributes.control_characters[wire::TERMINAL_CC_VSTART] = b'!';
        attributes.control_characters[wire::TERMINAL_CC_VSTOP] = b'!';
        if !ixany {
            attributes.input_flags &= !wire::TERMINAL_IFLAG_IXANY;
        }
        manager
            .set_attributes(pair.slave_object_id, attributes)
            .unwrap();
        for _ in 0..3 {
            manager.write(pair.slave_object_id, b"queued").unwrap();
            manager.write(pair.master_object_id, b"!").unwrap();
            assert_eq!(manager.read(pair.master_object_id, 100), Err(EAGAIN));
            manager.write(pair.master_object_id, b"!").unwrap();
            assert_eq!(
                manager.read(pair.master_object_id, 100),
                Ok(b"queued".to_vec())
            );
        }
        assert_eq!(manager.read(pair.slave_object_id, 100), Err(EAGAIN));
    }
}

#[test]
fn ixany_alone_does_not_enable_flow_control_and_disabled_stop_is_data() {
    let (mut manager, pair) = setup(false);
    let mut attributes = manager.attributes(pair.slave_object_id).unwrap();
    attributes.input_flags = wire::TERMINAL_IFLAG_IXANY;
    manager
        .set_attributes(pair.slave_object_id, attributes)
        .unwrap();
    manager.write(pair.master_object_id, b"\x13\x11").unwrap();
    manager.write(pair.slave_object_id, b"output").unwrap();
    assert_eq!(
        manager.read(pair.master_object_id, 100),
        Ok(b"output".to_vec())
    );
    assert_eq!(
        manager.read(pair.slave_object_id, 100),
        Ok(b"\x13\x11".to_vec())
    );
    attributes.input_flags |= wire::TERMINAL_IFLAG_IXON;
    manager
        .set_attributes(pair.slave_object_id, attributes)
        .unwrap();
    manager.write(pair.master_object_id, b"\x13").unwrap();
    manager.write(pair.slave_object_id, b"pending").unwrap();
    attributes.control_characters[wire::TERMINAL_CC_VSTOP] = 0;
    manager
        .set_attributes(pair.slave_object_id, attributes)
        .unwrap();
    manager.write(pair.master_object_id, b"\0").unwrap();
    assert_eq!(
        manager.read(pair.master_object_id, 100),
        Ok(b"pending".to_vec())
    );
    assert_eq!(manager.read(pair.slave_object_id, 100), Ok(vec![0]));
    assert!(
        include_str!("../../../user/libc-port/include/sys/termios.h")
            .contains("#define IXANY   (1U << 11)")
    );
}
