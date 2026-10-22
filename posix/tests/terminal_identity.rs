use mnu_abi::{
    HANDLE_RIGHT_CONTROL as C, HANDLE_RIGHT_TRANSFER as T, IpcObjectHandle, IpcObjectHandles,
    status::Error,
};
use posix_service::{pty::PtyManager, terminal_identity::lookup};

fn attached() -> IpcObjectHandles {
    let mut value = IpcObjectHandles::default();
    value.delivery_flags = mnu_abi::IPC_DELIVERY_ENDPOINT_HANDLE;
    value.count = 1;
    value.handles[0] = IpcObjectHandle {
        handle: 84,
        reserved: 0,
        rights: T,
    };
    value
}

#[test]
fn only_the_identified_live_slave_can_name_a_terminal() {
    let mut manager = PtyManager::new();
    let pair = manager.open().unwrap();
    let terminal = manager.slave_terminal_id(pair.slave_object_id).unwrap();
    assert_eq!(
        lookup(&manager, &attached(), |handle| {
            assert_eq!(handle, 84);
            Ok(pair.slave_object_id)
        }),
        Ok(terminal)
    );
    assert_eq!(
        lookup(&manager, &attached(), |_| Ok(pair.master_object_id)),
        Err(25)
    );
    assert_eq!(lookup(&manager, &attached(), |_| Ok(u64::MAX)), Err(25));
    manager.discard(pair);
    assert_eq!(
        lookup(&manager, &attached(), |_| Ok(pair.slave_object_id)),
        Err(25)
    );
}

#[test]
fn provenance_and_exact_transfer_authority_precede_identity_lookup() {
    let manager = PtyManager::new();
    for flags in [0, u32::MAX] {
        let mut value = attached();
        value.delivery_flags = flags;
        assert_eq!(
            lookup(&manager, &value, |_| panic!("no provenance")),
            Err(13)
        );
    }
    for count in [0, 2, u32::MAX] {
        let mut value = attached();
        value.count = count;
        assert_eq!(
            lookup(&manager, &value, |_| panic!("wrong reference count")),
            Err(22)
        );
    }
    for (handle, reserved, rights) in [(0, 0, T), (84, 1, T), (84, 0, 0), (84, 0, C | T)] {
        let mut value = attached();
        value.handles[0] = IpcObjectHandle {
            handle,
            reserved,
            rights,
        };
        assert_eq!(
            lookup(&manager, &value, |_| panic!("invalid reference")),
            Err(13)
        );
    }
}

#[test]
fn foreign_resource_is_not_a_terminal_but_mechanism_failures_are_not_hidden() {
    let manager = PtyManager::new();
    for (error, errno) in [
        (Error::AccessDenied, 25),
        (Error::InvalidArgument, 25),
        (Error::NotFound, 9),
        (Error::BackingFailure, 5),
        (Error::NotReady, 11),
        (Error::ResourceUnavailable, 12),
        (Error::PeerClosed, 32),
        (Error::LimitExceeded, 75),
    ] {
        assert_eq!(
            lookup(&manager, &attached(), |_| Err(error.into_raw() as i64)),
            Err(errno)
        );
    }
    assert_eq!(lookup(&manager, &attached(), |_| Err(0)), Err(5));
}

#[test]
fn native_dispatcher_uses_attachment_identity_and_keeps_policy_authentication() {
    // Wiring checks only, not an emulation of native delivery or identity.
    let source = include_str!("../src/main.rs");
    let identify = source
        .split("if request[..request_length] == PTY_IDENTIFY_MAGIC {")
        .nth(1)
        .unwrap()
        .split("continue;")
        .next()
        .unwrap();
    assert!(identify.contains("terminal_identity::lookup("));
    assert!(identify.contains("identify_provider_object(handle)"));
    let policy = source
        .split("match identified_terminal.unwrap()")
        .nth(1)
        .unwrap()
        .split("(Some(peer)")
        .next()
        .unwrap();
    assert!(policy.contains("endpoint_execution_identity(sender)"));
    assert!(policy.contains("service.handle_terminal("));
}
