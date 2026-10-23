use mnu_abi::{IpcObjectHandle, IpcObjectHandles};
use mochios_posix_protocol as protocol;
use posix_service::{
    AttachedObject, AuthenticatedProcess, PeerIdentity, PosixService,
    pty::PtyManager,
    pty_grant::{self, RIGHTS},
    pty_grant_ipc as ipc,
    terminal_publication::{Lease, Name},
};
use std::{
    cell::RefCell,
    sync::{Mutex, mpsc},
};

fn name() -> Name {
    Name {
        component: b"71-2".to_vec(),
        device: 7,
        node_id: (7 << 32) | 8,
    }
}
fn source() -> IpcObjectHandle {
    IpcObjectHandle {
        handle: 77,
        reserved: 0,
        rights: RIGHTS | mnu_abi::HANDLE_RIGHT_READ,
    }
}
fn objects() -> IpcObjectHandles {
    let mut result = IpcObjectHandles::default();
    result.count = 1;
    result.delivery_flags = mnu_abi::IPC_DELIVERY_ENDPOINT_HANDLE;
    result.handles[0] = source();
    result
}
fn manager() -> (PtyManager, posix_service::pty::PtyPair) {
    let mut manager = PtyManager::new();
    let pair = manager.open_with_slave_lock(true).unwrap();
    let (retire, _) = mpsc::channel();
    manager
        .attach_slave_name(pair.master_object_id, Lease::new(name(), retire))
        .unwrap();
    (manager, pair)
}

#[test]
fn identity_is_resolved_only_from_an_explicit_writable_master_on_its_owner() {
    let (mut manager, pair) = manager();
    assert_eq!(
        ipc::lookup(&manager, &ipc::REQUEST, &objects(), |h| {
            assert_eq!(h, 77);
            Ok(pair.master_object_id)
        }),
        Ok(name())
    );
    assert_eq!(
        ipc::lookup(&manager, &ipc::REQUEST, &objects(), |_| Err(22)),
        Err(22)
    ); // foreign provider
    assert_eq!(
        ipc::lookup(&manager, &ipc::REQUEST, &objects(), |_| Ok(
            pair.slave_object_id
        )),
        Err(22)
    );
    let factory = manager.create_slave_factory(pair.master_object_id).unwrap();
    assert_eq!(
        ipc::lookup(&manager, &ipc::REQUEST, &objects(), |_| Ok(factory)),
        Err(9)
    );
    for rights in [
        0,
        mnu_abi::HANDLE_RIGHT_TRANSFER,
        RIGHTS & !mnu_abi::HANDLE_RIGHT_CONTROL,
        RIGHTS & !mnu_abi::HANDLE_RIGHT_WRITE,
    ] {
        let mut objects = objects();
        objects.handles[0].rights = rights;
        assert_eq!(
            ipc::lookup(&manager, &ipc::REQUEST, &objects, |_| panic!(
                "unidentified authority"
            )),
            Err(13)
        );
    }
    for which in 0..6 {
        let mut objects = objects();
        match which {
            0 => objects.count = 0,
            1 => objects.count = 2,
            2 => objects.delivery_flags = 0,
            3 => objects.handles[0].handle = 0,
            4 => objects.handles[0].reserved = 1,
            _ => {}
        }
        let bytes = if which == 5 {
            &ipc::REQUEST[..7]
        } else {
            &ipc::REQUEST
        };
        assert!(ipc::lookup(&manager, bytes, &objects, |_| panic!("malformed request")).is_err());
    }
    manager.release(pair.master_object_id).unwrap();
    assert_eq!(
        ipc::lookup(&manager, &ipc::REQUEST, &objects(), |_| Ok(
            pair.master_object_id
        )),
        Err(9)
    );
}

#[test]
fn provenance_query_validates_reply_framing_and_closes_received_not_borrowed_objects() {
    for case in 0..9 {
        let closed = RefCell::new(Vec::new());
        let result = ipc::query_with(
            11,
            source(),
            |endpoint, request, reply, objects| {
                assert_eq!((endpoint, request), (11, &ipc::REQUEST[..]));
                assert_eq!(objects.handles[0].rights, RIGHTS);
                if case == 1 {
                    return Err(-11);
                } // leaves borrowed request intact
                objects.count = 0;
                objects.delivery_flags = 0;
                let name = name();
                let length = mochios_filesystem_protocol::device_removal::encode(
                    mochios_filesystem_protocol::device_removal::Request {
                        device: name.device,
                        node_id: name.node_id,
                        name: &name.component,
                    },
                    &mut reply[8..],
                )
                .unwrap()
                    + 8;
                match case {
                    2 => return Ok(7),
                    3 => return Ok(length as u64 + 1),
                    4 => {
                        reply[..8].copy_from_slice(&(-13i64).to_le_bytes());
                        return Ok(8);
                    }
                    5 => {
                        reply[..8].copy_from_slice(&1i64.to_le_bytes());
                        return Ok(8);
                    }
                    6 => {
                        objects.delivery_flags = 1;
                    }
                    7 => {
                        objects.count = 2;
                        objects.handles[0] = IpcObjectHandle {
                            handle: 91,
                            reserved: 0,
                            rights: 0,
                        };
                        objects.handles[1] = objects.handles[0];
                    }
                    8 => return Ok(reply.len() as u64 + 1),
                    _ => {}
                }
                Ok(length as u64)
            },
            |h| closed.borrow_mut().push(h),
        );
        assert_eq!(
            result,
            match case {
                0 => Ok(name()),
                1 => Err(-11),
                4 => Err(-13),
                _ => Err(-5),
            }
        );
        assert_eq!(*closed.borrow(), if case == 7 { vec![91] } else { vec![] });
    }
}

#[test]
fn grant_captures_real_not_effective_ids_and_never_holds_state_across_peer_calls() {
    let mut state = PosixService::new();
    state
        .initialize_bootstrap_process(
            AuthenticatedProcess {
                handle: 1,
                process_id: 71,
            },
            0,
            0,
            &[],
        )
        .unwrap();
    let root = state.registered_peer(71).unwrap();
    for (opcode, value) in [
        (protocol::OP_SET_EFFECTIVE_GID, 20u32),
        (protocol::OP_SET_EFFECTIVE_UID, 501),
    ] {
        let peer = state.registered_peer(71).unwrap();
        assert_eq!(
            state
                .handle(
                    peer,
                    protocol::Header {
                        opcode,
                        ..Default::default()
                    },
                    &value.to_le_bytes()
                )
                .header
                .status,
            0
        );
    }
    let peer = state.registered_peer(71).unwrap();
    assert_ne!(peer, root);
    let state = Mutex::new(state);
    for error in [0, -13, -116] {
        let result = pty_grant::execute(
            &state,
            peer,
            protocol::Header {
                opcode: protocol::OP_PTY_GRANT_MASTER,
                request_id: 81,
                ..Default::default()
            },
            &[],
            &[AttachedObject {
                handle: 77,
                rights: source().rights,
            }],
            |object| {
                assert!(state.try_lock().is_ok());
                assert_eq!(object.rights, RIGHTS);
                Ok(name())
            },
            |identity, uid, gid| {
                assert!(state.try_lock().is_ok());
                assert_eq!(identity, &name());
                assert_eq!((uid, gid), (0, 0));
                if error == 0 { Ok(()) } else { Err(error) }
            },
        );
        assert_eq!(
            (
                result.response.header.opcode,
                result.response.header.request_id,
                result.response.header.status
            ),
            (protocol::OP_STATUS, 81, error)
        );
        assert!(result.handles.is_empty());
    }
    let header = protocol::Header {
        opcode: protocol::OP_PTY_GRANT_MASTER,
        ..Default::default()
    };
    let denied = pty_grant::execute(
        &state,
        PeerIdentity {
            effective_uid: 0,
            ..peer
        },
        header,
        &[],
        &[AttachedObject {
            handle: 77,
            rights: RIGHTS,
        }],
        |_| panic!("forged peer"),
        |_, _, _| unreachable!(),
    );
    assert_eq!(denied.response.header.status, -1);
    for bad in [
        protocol::Header { flags: 1, ..header },
        protocol::Header {
            status: 1,
            ..header
        },
        protocol::Header {
            payload_len: 4,
            ..header
        },
    ] {
        let denied = pty_grant::execute(
            &state,
            peer,
            bad,
            &[],
            &[AttachedObject {
                handle: 77,
                rights: RIGHTS,
            }],
            |_| panic!("invalid envelope"),
            |_, _, _| unreachable!(),
        );
        assert_eq!(denied.response.header.status, -22);
    }
    let failed = pty_grant::execute(
        &state,
        peer,
        header,
        &[],
        &[AttachedObject {
            handle: 77,
            rights: RIGHTS,
        }],
        |_| Err(-22),
        |_, _, _| panic!("foreign provider must not mutate filesystem"),
    );
    assert_eq!(failed.response.header.status, -22);
}

#[test]
fn grant_payload_and_reply_are_bound_to_the_original_inode_and_real_ids() {
    use mochios_filesystem_protocol as fs;
    let expected = fs::NodeStatus {
        device: name().device,
        node_id: name().node_id,
        kind: fs::NODE_TYPE_SPECIAL,
        uid: 501,
        gid: 20,
        mode: 0o020620,
        ..Default::default()
    };
    for field in 0..8 {
        let result = posix_service::terminal_publication::grant_with(&name(), 501, 20, |payload| {
            let request = fs::device_attributes::decode(payload).unwrap();
            assert_eq!((request.mode, request.uid, request.gid), (0o620, 501, 20));
            assert_eq!(
                (
                    request.identity.device,
                    request.identity.node_id,
                    request.identity.name
                ),
                (name().device, name().node_id, &b"71-2"[..])
            );
            let mut response = expected;
            match field {
                1 => response.device += 1,
                2 => response.node_id += 1,
                3 => response.uid += 1,
                4 => response.gid += 1,
                5 => response.mode |= 0o4,
                6 => response.kind = fs::NODE_TYPE_DIRECTORY,
                7 => return Err(-116),
                _ => {}
            }
            Ok(response)
        });
        assert_eq!(
            result,
            match field {
                0 => Ok(()),
                7 => Err(-116),
                _ => Err(-5),
            }
        );
    }
}

#[test]
fn native_dispatch_revalidates_grant_image_and_uses_owner_not_arbitrary_provider_identity() {
    let main = include_str!("../src/main.rs");
    let preflight = main
        .split("let granted_pty =")
        .nth(1)
        .unwrap()
        .split("let opened_pty =")
        .next()
        .unwrap();
    assert!(preflight.contains("request_image"));
    assert!(preflight.contains("provider_endpoint_handle"));
    let finish = main
        .split("if granted_pty.is_some()")
        .nth(1)
        .unwrap()
        .split("if opened_pty.is_some()")
        .next()
        .unwrap();
    assert!(finish.contains("validate_pending_request_image("));
    assert!(finish.contains("open_request::finish("));
    assert!(include_str!("../src/pty_grant_ipc.rs").contains("identify_provider_object(handle)"));
}
