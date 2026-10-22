use mnu_abi::{
    HANDLE_RIGHT_CONTROL as C, HANDLE_RIGHT_TRANSFER as T, IpcObjectHandle, IpcObjectHandles,
};
use mochios_filesystem_protocol as wire;
use posix_service::{
    PeerIdentity,
    pty::PtyManager,
    terminal_publication::{self, Lease, Name},
};
use std::sync::mpsc;

fn name(id: u64) -> Name {
    Name {
        component: id.to_string().into_bytes(),
        device: 3,
        node_id: id,
    }
}

#[test]
fn only_final_master_release_retires_the_name_not_factory_or_slave_closes() {
    let (sender, receiver) = mpsc::channel();
    let mut manager = PtyManager::new();
    let pair = manager.open().unwrap();
    let factory = manager.create_slave_factory(pair.master_object_id).unwrap();
    let slave = manager.open_slave_from_factory(factory).unwrap();
    manager
        .attach_slave_name(pair.master_object_id, Lease::new(name(7), sender))
        .unwrap();
    manager.release(pair.slave_object_id).unwrap();
    manager.release(factory).unwrap();
    assert!(receiver.try_recv().is_err());
    manager.release(pair.master_object_id).unwrap();
    assert_eq!(receiver.try_recv().unwrap().node_id, 7);
    assert!(receiver.try_recv().is_err());
    manager.release(slave).unwrap();
    assert!(receiver.try_recv().is_err());
}

#[test]
fn discarded_pairs_and_rejected_leases_queue_each_owned_name_once() {
    let (sender, receiver) = mpsc::channel();
    let mut manager = PtyManager::new();
    let pair = manager.open().unwrap();
    manager
        .attach_slave_name(pair.master_object_id, Lease::new(name(1), sender.clone()))
        .unwrap();
    assert_eq!(
        manager.attach_slave_name(pair.master_object_id, Lease::new(name(2), sender.clone())),
        Err(22)
    );
    assert_eq!(
        manager.attach_slave_name(pair.slave_object_id, Lease::new(name(3), sender.clone())),
        Err(9)
    );
    assert_eq!(
        manager.attach_slave_name(u64::MAX, Lease::new(name(4), sender.clone())),
        Err(9)
    );
    let rejected: Vec<_> = receiver.try_iter().map(|n| n.node_id).collect();
    assert_eq!(rejected, [2, 3, 4]);
    manager.discard(pair);
    assert_eq!(receiver.try_recv().unwrap().node_id, 1);
    manager.discard(pair);
    assert!(receiver.try_recv().is_err());
}

#[test]
fn cleanup_retries_failures_without_losing_batches_or_blocking_other_names() {
    let (sender, receiver) = mpsc::channel();
    for id in 1..=140 {
        sender.send(name(id)).unwrap();
    }
    drop(sender);
    let mut calls = std::collections::BTreeMap::<u64, usize>::new();
    let mut order = Vec::new();
    let mut reports = Vec::new();
    terminal_publication::retire(
        receiver,
        |name| {
            let count = calls.entry(name.node_id).or_default();
            *count += 1;
            order.push(name.node_id);
            match (name.node_id, *count) {
                (1, 1 | 2) => Err(-11),
                (2, _) => Err(-2),
                (3, _) => Err(-116),
                _ => Ok(()),
            }
        },
        |name, status| reports.push((name.node_id, status)),
    );
    assert_eq!(calls.len(), 140);
    assert_eq!(calls[&1], 3);
    assert!(
        calls
            .iter()
            .filter(|(id, _)| **id != 1)
            .all(|(_, count)| *count == 1)
    );
    assert_eq!(reports, [(1, -11)]);
    assert!(
        order.iter().position(|id| *id == 2).unwrap()
            < order.iter().rposition(|id| *id == 1).unwrap()
    );
}

#[test]
fn names_use_server_identity_and_authenticated_posix_ownership() {
    let peer = PeerIdentity {
        process_id: 51,
        effective_uid: 501,
        effective_gid: 20,
    };
    let (sender, receiver) = mpsc::channel();
    let lease = terminal_publication::register_with(81, 32, peer, sender, |payload| {
        let request = wire::device_registration::decode(payload).unwrap();
        assert_eq!(
            (request.name, request.mode, request.uid, request.gid),
            (&b"81-32"[..], 0o600, 501, 20)
        );
        assert_eq!(request.special_device, 32);
        Ok(wire::NodeStatus {
            device: 3,
            node_id: 500,
            kind: wire::NODE_TYPE_SPECIAL,
            ..Default::default()
        })
    })
    .unwrap();
    assert!(receiver.try_recv().is_err());
    drop(lease);
    let name = receiver.try_recv().unwrap();
    assert_eq!(
        (name.component, name.device, name.node_id),
        (b"81-32".to_vec(), 3, 500)
    );
    for error in [-17, -13, -5] {
        let (sender, receiver) = mpsc::channel();
        assert_eq!(
            terminal_publication::register_with(81, 32, peer, sender, |_| Err(error)).err(),
            Some(error)
        );
        assert!(receiver.try_recv().is_err());
    }
}

fn request() -> wire::Header {
    wire::Header {
        opcode: wire::OP_DEVICE_NODE_REGISTER_EXTERNAL,
        request_id: 74,
        ..Default::default()
    }
}
fn borrowed() -> IpcObjectHandles {
    let mut objects = IpcObjectHandles::default();
    objects.count = 1;
    objects.handles[0] = IpcObjectHandle {
        handle: 29,
        reserved: 0,
        rights: C | T,
    };
    objects
}
fn reply(output: &mut [u8], request_id: u64) -> usize {
    let status = wire::NodeStatus {
        device: 3,
        node_id: 500,
        kind: wire::NODE_TYPE_SPECIAL,
        ..Default::default()
    };
    let mut payload = vec![0; wire::NODE_STATUS_LEN];
    wire::encode_node_status(status, &mut payload).unwrap();
    wire::encode(
        wire::Header {
            opcode: wire::OP_STATUS,
            request_id,
            length: payload.len() as u32,
            ..Default::default()
        },
        &payload,
        output,
    )
    .unwrap()
}

#[test]
fn metadata_transport_never_closes_borrowed_requests_on_failure() {
    for error in [-5, -32, -11, -13] {
        let result = terminal_publication::status_with(
            request(),
            &[],
            borrowed(),
            |_, _, objects| {
                assert_eq!(objects.handles[0].handle, 29);
                Err(error)
            },
            |_| panic!("borrowed request must not be closed"),
        );
        assert_eq!(result.err(), Some(error));
    }
}

#[test]
fn only_exact_metadata_replies_escape_and_malformed_owned_objects_are_closed_once() {
    for scenario in 0..7 {
        let mut closed = Vec::new();
        let result = terminal_publication::status_with(
            request(),
            &[],
            borrowed(),
            |_, output, objects| {
                let mut length = reply(output, if scenario == 1 { 75 } else { 74 });
                *objects = IpcObjectHandles::default();
                match scenario {
                    2 => length -= 1,
                    3 => length += 1,
                    4 => objects.delivery_flags = 1,
                    5 | 6 => {
                        objects.count = if scenario == 5 { 2 } else { u32::MAX };
                        for slot in &mut objects.handles {
                            *slot = IpcObjectHandle {
                                handle: 88,
                                reserved: 0,
                                rights: T,
                            };
                        }
                    }
                    _ => {}
                }
                Ok(length as u64)
            },
            |handle| closed.push(handle),
        );
        if scenario == 0 {
            assert_eq!(result.unwrap().node_id, 500);
        } else {
            assert_eq!(result.err(), Some(-5));
        }
        assert_eq!(closed, if scenario >= 5 { vec![88] } else { vec![] });
    }
}

#[test]
fn native_wiring_publishes_before_reply_without_state_lock_and_cleans_failed_publication() {
    let source = include_str!("../src/main.rs");
    let preflight = source
        .split("let opened_pty =")
        .nth(1)
        .unwrap()
        .split("let opened_socket =")
        .next()
        .unwrap();
    assert!(preflight.contains("terminal_publication::publish_created_pair("));
    let create = source
        .split("fn open_pty_response(")
        .nth(1)
        .unwrap()
        .split("#[cfg")
        .next()
        .unwrap();
    assert!(
        create.find("publish(pair)").unwrap()
            > create.find("sync_pty_provider(endpoint, pair)").unwrap()
    );
    assert!(create.contains("if let Err(status) = publish(pair)"));
    assert!(create.contains("ptys.lock().unwrap().discard(pair)"));
    let startup = source
        .find("terminal_publication::Publisher::start(")
        .unwrap();
    assert!(
        startup
            < source
                .find("service_ready::notify_handle(ready_target, 0")
                .unwrap()
    );
}
