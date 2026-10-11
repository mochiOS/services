use mochios_posix_protocol as protocol;
use posix_service::pty::{PtyManager, BUFFER_CAPACITY, EAGAIN, EBADF, EINVAL};

fn flow(manager: &mut PtyManager, object: u64, action: u32) -> Result<Vec<u8>, i32> {
    let mut encoded = [0; protocol::TERMINAL_FLOW_LEN];
    protocol::encode_terminal_flow(action, &mut encoded).unwrap();
    manager.control(object, protocol::PTY_CONTROL_FLOW, &encoded, 0)
}

#[test]
fn explicit_stop_is_independent_of_ixon_and_shared_between_ends() {
    let mut manager = PtyManager::new();
    let pair = manager.open().unwrap();
    let mut attributes = manager.attributes(pair.slave_object_id).unwrap();
    attributes.input_flags = protocol::TERMINAL_IFLAG_IXON;
    attributes.local_flags = 0;
    manager
        .set_attributes(pair.slave_object_id, attributes)
        .unwrap();
    manager.write(pair.slave_object_id, b"queued").unwrap();
    flow(
        &mut manager,
        pair.slave_object_id,
        protocol::TERMINAL_FLOW_OUTPUT_STOP,
    )
    .unwrap();
    manager.write(pair.master_object_id, b"\x11").unwrap();
    attributes.input_flags = 0;
    manager
        .set_attributes(pair.slave_object_id, attributes)
        .unwrap();
    assert_eq!(manager.read(pair.master_object_id, 32), Err(EAGAIN));
    flow(
        &mut manager,
        pair.master_object_id,
        protocol::TERMINAL_FLOW_OUTPUT_START,
    )
    .unwrap();
    assert_eq!(
        manager.read(pair.master_object_id, 32),
        Ok(b"queued".to_vec())
    );
}

#[test]
fn input_flow_transmits_configured_characters_verbatim_without_ixon() {
    let mut manager = PtyManager::new();
    let pair = manager.open().unwrap();
    let mut attributes = manager.attributes(pair.slave_object_id).unwrap();
    attributes.input_flags = 0;
    attributes.control_characters[protocol::TERMINAL_CC_VSTOP] = b'\n';
    attributes.control_characters[protocol::TERMINAL_CC_VSTART] = b'q';
    manager
        .set_attributes(pair.slave_object_id, attributes)
        .unwrap();
    flow(
        &mut manager,
        pair.slave_object_id,
        protocol::TERMINAL_FLOW_INPUT_STOP,
    )
    .unwrap();
    flow(
        &mut manager,
        pair.slave_object_id,
        protocol::TERMINAL_FLOW_INPUT_START,
    )
    .unwrap();
    assert_eq!(manager.read(pair.master_object_id, 32), Ok(b"\nq".to_vec()));
    assert_eq!(manager.read(pair.slave_object_id, 32), Err(EAGAIN));
    attributes.control_characters[protocol::TERMINAL_CC_VSTOP] = 0;
    manager
        .set_attributes(pair.slave_object_id, attributes)
        .unwrap();
    flow(
        &mut manager,
        pair.slave_object_id,
        protocol::TERMINAL_FLOW_INPUT_STOP,
    )
    .unwrap();
    assert_eq!(manager.read(pair.master_object_id, 32), Err(EAGAIN));
}

#[test]
fn malformed_flow_controls_cannot_resume_output() {
    let mut manager = PtyManager::new();
    let pair = manager.open().unwrap();
    flow(
        &mut manager,
        pair.slave_object_id,
        protocol::TERMINAL_FLOW_OUTPUT_STOP,
    )
    .unwrap();
    manager.write(pair.slave_object_id, b"queued").unwrap();
    for input in [
        &[][..],
        &[0, 0, 0][..],
        &[4, 0, 0, 0][..],
        &[1, 0, 0, 0, 0][..],
    ] {
        assert_eq!(
            manager.control(pair.slave_object_id, protocol::PTY_CONTROL_FLOW, input, 0),
            Err(EINVAL)
        );
    }
    assert_eq!(
        manager.control(
            pair.slave_object_id,
            protocol::PTY_CONTROL_FLOW,
            &[1, 0, 0, 0],
            1
        ),
        Err(EINVAL)
    );
    assert_eq!(
        flow(&mut manager, 0, protocol::TERMINAL_FLOW_OUTPUT_START),
        Err(EBADF)
    );
    assert_eq!(manager.read(pair.master_object_id, 32), Err(EAGAIN));
    let mut encoded = [0; 4];
    assert!(protocol::encode_terminal_flow(4, &mut encoded).is_err());
    assert!(protocol::encode_terminal_flow(0, &mut encoded[..3]).is_err());
    for action in 0..=3 {
        protocol::encode_terminal_flow(action, &mut encoded).unwrap();
        assert_eq!(encoded, action.to_le_bytes());
        assert_eq!(protocol::decode_terminal_flow(&encoded), Ok(action));
    }
}

#[test]
fn full_output_flow_requests_are_atomic_and_retry_after_drain() {
    let mut manager = PtyManager::new();
    let pair = manager.open().unwrap();
    let bytes = vec![b'x'; BUFFER_CAPACITY];
    manager.write(pair.slave_object_id, &bytes).unwrap();
    assert_eq!(
        flow(
            &mut manager,
            pair.slave_object_id,
            protocol::TERMINAL_FLOW_INPUT_STOP
        ),
        Err(EAGAIN)
    );
    assert_eq!(
        manager.read(pair.master_object_id, BUFFER_CAPACITY),
        Ok(bytes)
    );
    flow(
        &mut manager,
        pair.slave_object_id,
        protocol::TERMINAL_FLOW_INPUT_STOP,
    )
    .unwrap();
    assert_eq!(manager.read(pair.master_object_id, 32), Ok(vec![19]));
}
