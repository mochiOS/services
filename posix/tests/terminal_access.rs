use mnu_abi::provider;
use mochios_posix_protocol as protocol;
use posix_service::pty::PtyManager;

#[test]
fn only_nonempty_slave_data_requests_require_job_control() {
    let mut ptys = PtyManager::new();
    let pair = ptys.open().unwrap();
    let mut request = provider::RequestHeader {
        opcode: provider::OP_READ,
        object_id: pair.slave_object_id,
        argument: 0,
        basis: 0,
        length: 1,
        data_length: 0,
    };
    let terminal = ptys.slave_terminal_id(pair.slave_object_id).unwrap();
    assert_eq!(
        ptys.job_control_access(request),
        Some((terminal, true, false))
    );
    let mut attrs = ptys.attributes(pair.slave_object_id).unwrap();
    attrs.local_flags |= protocol::TERMINAL_LFLAG_TOSTOP;
    ptys.set_attributes(pair.slave_object_id, attrs).unwrap();
    request.opcode = provider::OP_WRITE;
    assert_eq!(
        ptys.job_control_access(request),
        Some((terminal, false, true))
    );
    request.object_id = pair.master_object_id;
    assert_eq!(ptys.job_control_access(request), None);
    request.object_id = pair.slave_object_id;
    request.length = 0;
    assert_eq!(ptys.job_control_access(request), None);
    request.length = 1;
    request.opcode = provider::OP_MEMORY_OBJECT;
    assert_eq!(ptys.job_control_access(request), None);
    ptys.discard(pair);
    assert_eq!(ptys.job_control_access(request), None);
}

#[test]
fn changing_terminal_parameters_enforces_ttou_even_with_tostop_clear() {
    let mut ptys = PtyManager::new();
    let pair = ptys.open().unwrap();
    let terminal = ptys.slave_terminal_id(pair.slave_object_id).unwrap();
    let mut header = provider::RequestHeader {
        opcode: provider::OP_CONTROL,
        object_id: pair.slave_object_id,
        argument: 0,
        basis: 0,
        length: 0,
        data_length: 0,
    };
    for stop in [false, true] {
        let mut attributes = ptys.attributes(pair.slave_object_id).unwrap();
        if stop {
            attributes.local_flags |= protocol::TERMINAL_LFLAG_TOSTOP;
        } else {
            attributes.local_flags &= !protocol::TERMINAL_LFLAG_TOSTOP;
        }
        ptys.set_attributes(pair.slave_object_id, attributes)
            .unwrap();
        for code in [
            protocol::PTY_CONTROL_SET_ATTRIBUTES_NOW,
            protocol::PTY_CONTROL_SET_ATTRIBUTES_DRAIN,
            protocol::PTY_CONTROL_SET_ATTRIBUTES_FLUSH,
            protocol::PTY_CONTROL_DRAIN,
            protocol::PTY_CONTROL_FLUSH,
            protocol::PTY_CONTROL_FLOW,
        ] {
            header.basis = code;
            header.object_id = pair.slave_object_id;
            assert_eq!(
                ptys.job_control_access(header),
                Some((terminal, false, true))
            );
            header.object_id = pair.master_object_id;
            assert_eq!(ptys.job_control_access(header), None);
        }
        header.object_id = pair.slave_object_id;
        for code in [
            protocol::PTY_CONTROL_GET_ATTRIBUTES,
            protocol::PTY_CONTROL_GET_WINDOW_SIZE,
            u64::MAX,
        ] {
            header.basis = code;
            assert_eq!(ptys.job_control_access(header), None);
        }
    }
}

#[test]
fn service_does_not_hold_posix_state_across_provider_rpc_or_wait() {
    let source = include_str!("../src/main.rs");
    let wait = source
        .find("let lifecycle_handles = service.child_lifecycle_handles();")
        .unwrap();
    let release = source[wait..].find("drop(service);").unwrap();
    let block = source[wait..].find("wait_for_request_or_child(").unwrap();
    assert!(release < block);
    let identify = source.find("let identified_terminal =").unwrap();
    let open = source[identify..].find("let opened_pty =").unwrap();
    let reacquire = source[identify..]
        .find("let mut service = service_state.lock()")
        .unwrap();
    assert!(open < reacquire);
    let provider = &source[source.find("fn run_pty_provider(").unwrap()..];
    assert!(provider.contains("platform::ipc::endpoint_execution_identity(sender)"));
    assert!(provider.contains("authorize_terminal_io("));
    let signal = provider.find("for signal in terminal_signals").unwrap();
    assert!(provider[..signal].ends_with("drop(policy);\n        "));
}
