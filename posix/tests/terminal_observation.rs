use mnu_abi::provider;
use mochios_posix_protocol as wire;
use posix_service::pty::PtyManager;

#[test]
fn readonly_observations_match_control_values_without_changing_terminal_state() {
    let mut ptys = PtyManager::new();
    let pair = ptys.open().unwrap();
    let mut attrs = ptys.attributes(pair.slave_object_id).unwrap();
    attrs.control_characters[wire::TERMINAL_CC_VMIN] = 7;
    attrs.local_flags |= wire::TERMINAL_LFLAG_TOSTOP;
    ptys.set_attributes(pair.slave_object_id, attrs).unwrap();
    let size = wire::TerminalWindowSize {
        rows: 37,
        columns: 111,
        pixel_width: 900,
        pixel_height: 600,
    };
    let mut bytes = [0; wire::TERMINAL_WINDOW_SIZE_LEN];
    wire::encode_terminal_window_size(size, &mut bytes).unwrap();
    ptys.control(
        pair.master_object_id,
        wire::PTY_CONTROL_SET_WINDOW_SIZE,
        &bytes,
        0,
    )
    .unwrap();
    while ptys.take_terminal_signal().is_some() {}

    for object in [pair.master_object_id, pair.slave_object_id] {
        let signals = ptys.signals(object).unwrap();
        for (query, control, length) in [
            (
                wire::PTY_QUERY_ATTRIBUTES,
                wire::PTY_CONTROL_GET_ATTRIBUTES,
                wire::TERMINAL_ATTRIBUTES_LEN,
            ),
            (
                wire::PTY_QUERY_WINDOW_SIZE,
                wire::PTY_CONTROL_GET_WINDOW_SIZE,
                wire::TERMINAL_WINDOW_SIZE_LEN,
            ),
        ] {
            for capacity in [length, length + 8] {
                let expected = ptys.control(object, control, &[], capacity).unwrap();
                assert_eq!(expected.len(), length);
                assert_eq!(ptys.query(object, query, &[], capacity), Ok(expected));
                assert_eq!(
                    ptys.job_control_access(provider::RequestHeader {
                        opcode: provider::OP_QUERY,
                        object_id: object,
                        argument: 0,
                        basis: query,
                        length: capacity as u32,
                        data_length: 0,
                    }),
                    None
                );
            }
        }
        assert_eq!(ptys.signals(object), Ok(signals));
        assert_eq!(ptys.attributes(object), Ok(attrs));
    }
    assert!(ptys.take_terminal_signal().is_none());
}

#[test]
fn readonly_namespace_cannot_reach_controls_or_publish_partial_observations() {
    let mut ptys = PtyManager::new();
    let pair = ptys.open().unwrap();
    let object = pair.slave_object_id;
    let original = ptys.attributes(object).unwrap();
    for code in [
        wire::PTY_CONTROL_GET_ATTRIBUTES,
        wire::PTY_CONTROL_SET_ATTRIBUTES_NOW,
        wire::PTY_CONTROL_SET_ATTRIBUTES_DRAIN,
        wire::PTY_CONTROL_SET_ATTRIBUTES_FLUSH,
        wire::PTY_CONTROL_GET_WINDOW_SIZE,
        wire::PTY_CONTROL_SET_WINDOW_SIZE,
        wire::PTY_CONTROL_FLOW,
        wire::PTY_CONTROL_FLUSH,
        wire::PTY_CONTROL_DRAIN,
        u64::MAX,
    ] {
        assert_eq!(ptys.query(object, code, &[0; 8], 128), Err(95));
    }
    for (query, length) in [
        (wire::PTY_QUERY_ATTRIBUTES, wire::TERMINAL_ATTRIBUTES_LEN),
        (wire::PTY_QUERY_WINDOW_SIZE, wire::TERMINAL_WINDOW_SIZE_LEN),
    ] {
        assert_eq!(ptys.query(object, query, &[1], length), Err(22));
        for capacity in 0..length {
            assert_eq!(ptys.query(object, query, &[], capacity), Err(22));
        }
        assert_eq!(ptys.control(object, query, &[], length), Err(95));
    }
    assert_eq!(ptys.attributes(object), Ok(original));
    assert!(ptys.take_terminal_signal().is_none());
}

#[test]
fn released_objects_do_not_return_default_terminal_observations() {
    let mut ptys = PtyManager::new();
    let pair = ptys.open().unwrap();
    ptys.release(pair.slave_object_id).unwrap();
    for (query, length) in [
        (wire::PTY_QUERY_ATTRIBUTES, wire::TERMINAL_ATTRIBUTES_LEN),
        (wire::PTY_QUERY_WINDOW_SIZE, wire::TERMINAL_WINDOW_SIZE_LEN),
    ] {
        assert_eq!(ptys.query(pair.slave_object_id, query, &[], length), Err(9));
    }
}
