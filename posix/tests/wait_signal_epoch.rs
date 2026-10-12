use mochios_posix_protocol as protocol;

#[test]
fn guarded_child_wait_wire_has_no_identity_or_pointer_and_rejects_bad_lengths() {
    let request = protocol::WaitRequest {
        selector: -1,
        options: 0,
    };
    let mut bytes = [0; protocol::WAIT_GUARDED_REQUEST_LEN];
    protocol::encode_guarded_wait_request(request, 23, &mut bytes).unwrap();
    let (decoded, epoch) = protocol::decode_guarded_wait_request(&bytes).unwrap();
    assert_eq!((decoded.selector, decoded.options, epoch), (-1, 0, 23));
    assert_eq!(bytes.len(), 24);
    assert!(protocol::decode_guarded_wait_request(&bytes[..16]).is_err());
    bytes[12] = 1;
    assert!(protocol::decode_guarded_wait_request(&bytes).is_err());
    assert!(protocol::encode_guarded_wait_request(request, 23, &mut bytes[..16]).is_err());
}

#[test]
fn server_checks_interruption_before_consuming_a_child_event() {
    let source = include_str!("../src/main.rs");
    let pending = source
        .split("fn complete_pending_waits(")
        .nth(1)
        .unwrap()
        .split("fn wait_for_request_or_child(")
        .next()
        .unwrap();
    assert!(
        pending.find("validate_wait_delivery_epoch").unwrap()
            < pending.find("service.wait_child").unwrap()
    );
    let initial = source
        .split("protocol::decode_guarded_wait_request(payload)")
        .nth(1)
        .unwrap()
        .split("pending_waits.push(PendingWait")
        .next()
        .unwrap();
    assert!(initial.contains("endpoint_execution_identity(sender)"));
    assert!(
        initial.find("validate_wait_delivery_epoch").unwrap()
            < initial.find("service.wait_child").unwrap()
    );
}

#[test]
fn runtime_dispatches_before_restart_and_does_not_discard_successfully_reaped_events() {
    let runtime = include_str!("../../../user/crates/newlib-runtime/src/lib.rs");
    let wait = runtime
        .split("fn _waitpid(")
        .nth(1)
        .unwrap()
        .split("fn waitpid(")
        .next()
        .unwrap();
    assert!(wait.contains("nonrestart_signal_generation.load"));
    assert!(wait.contains(".thread_signal_epoch()"));
    assert!(wait.contains(".wait_child_since("));
    assert!(wait.contains("Ok(waited) => break waited"));
    assert!(wait.contains("drain_pending_signals()?"));
    assert!(wait.contains("return Err(EINTR)"));
    assert!(wait.contains("options & WNOHANG != 0"));
}
