//! Actual factory exchange/state machine; attachment renumbering is modeled.
//! Native transport and pathname integration require separate OS validation.
use filesystem_service::device_factory::observe_with;
use mnu_abi::{
    HANDLE_RIGHT_TRANSFER as T, IPC_DELIVERY_ENDPOINT_HANDLE, IpcObjectHandle, IpcObjectHandles,
};
use mochios_filesystem_protocol::device_observation::Request;
use mochios_posix_protocol as wire;
use posix_service::{pty::PtyManager, pty_observation::observe};
use std::cell::Cell;

fn request() -> Request {
    Request {
        selector: wire::PTY_QUERY_LIMITS,
        capacity: wire::terminal_limits::RESPONSE_LEN as u32,
    }
}
fn attached() -> IpcObjectHandles {
    let mut objects = IpcObjectHandles::default();
    objects.delivery_flags = IPC_DELIVERY_ENDPOINT_HANDLE;
    objects.count = 1;
    objects.handles[0] = IpcObjectHandle {
        handle: 70,
        reserved: 0,
        rights: T,
    };
    objects
}

#[test]
fn exchange_observes_actual_owner_limits_without_opening_a_slave_or_consuming_data() {
    let mut manager = PtyManager::new();
    let pair = manager.open().unwrap();
    manager.write(pair.master_object_id, b"retained\n").unwrap();
    let factory = manager.create_slave_factory(pair.master_object_id).unwrap();
    let attributes = manager.attributes(pair.master_object_id).unwrap();
    let readiness = manager.signals(pair.master_object_id).unwrap();
    let bytes = observe_with(
        11,
        30,
        request(),
        |endpoint, bytes, reply, outgoing| {
            assert_eq!(endpoint, 11);
            assert_eq!(outgoing.count, 1);
            assert_eq!(
                outgoing.handles[0],
                IpcObjectHandle {
                    handle: 30,
                    reserved: 0,
                    rights: T
                }
            );
            let response = observe(&manager, bytes, &attached(), |received| {
                assert_eq!(received, 70);
                Ok(factory)
            })
            .unwrap();
            *outgoing = IpcObjectHandles::default();
            reply[..8].copy_from_slice(&0i64.to_le_bytes());
            reply[8..].copy_from_slice(&response);
            Ok(reply.len() as u64)
        },
        |_| panic!("no response handles are allowed"),
    )
    .unwrap();
    assert_eq!(
        wire::terminal_limits::Limits::decode(&bytes)
            .unwrap()
            .canonical_bytes as usize,
        posix_service::pty::CANONICAL_LINE_CAPACITY
    );
    assert_eq!(
        manager.attributes(pair.master_object_id).unwrap(),
        attributes
    );
    assert_eq!(manager.signals(pair.master_object_id).unwrap(), readiness);
    assert!(manager.take_terminal_signal().is_none());
    assert_eq!(
        manager.read(pair.slave_object_id, 64).unwrap(),
        b"retained\n"
    );
    // An observation allocated no open object ID between the factory and this open.
    assert_eq!(
        manager.reopen_slave(pair.master_object_id).unwrap(),
        factory + 1
    );
}

#[test]
fn owner_requires_endpoint_provenance_and_one_exact_scoped_factory_attachment() {
    let mut manager = PtyManager::new();
    let pair = manager.open().unwrap();
    let factory = manager.create_slave_factory(pair.master_object_id).unwrap();
    for change in 0..6 {
        let mut objects = attached();
        let expected = match change {
            0 => {
                objects.delivery_flags = 0;
                13
            }
            1 => {
                objects.count = 0;
                22
            }
            2 => {
                objects.count = 2;
                22
            }
            3 => {
                objects.handles[0].handle = 0;
                13
            }
            4 => {
                objects.handles[0].reserved = 1;
                13
            }
            _ => {
                objects.handles[0].rights |= mnu_abi::HANDLE_RIGHT_CONTROL;
                13
            }
        };
        assert_eq!(
            observe(&manager, &request().encode(), &objects, |_| panic!(
                "invalid admission must not identify"
            )),
            Err(expected)
        );
    }
    assert_eq!(
        observe(&manager, &request().encode(), &attached(), |_| Err(9)),
        Err(9)
    );
    for id in [pair.master_object_id, pair.slave_object_id, u64::MAX] {
        assert_eq!(
            observe(&manager, &request().encode(), &attached(), |_| Ok(id)),
            Err(9)
        );
    }
    manager.release(factory).unwrap();
    assert_eq!(
        observe(&manager, &request().encode(), &attached(), |_| Ok(factory)),
        Err(9)
    );
}

#[test]
fn mutation_selectors_and_short_reply_capacity_never_change_terminal_state() {
    let mut manager = PtyManager::new();
    let pair = manager.open().unwrap();
    let factory = manager.create_slave_factory(pair.master_object_id).unwrap();
    let before = manager.attributes(pair.master_object_id).unwrap();
    for selector in [
        wire::PTY_CONTROL_SET_ATTRIBUTES_NOW,
        wire::PTY_CONTROL_FLUSH,
        wire::PTY_CONTROL_FLOW,
        wire::PTY_QUERY_ATTRIBUTES,
        u64::MAX,
    ] {
        let r = Request {
            selector,
            ..request()
        };
        assert_eq!(
            observe(&manager, &r.encode(), &attached(), |_| Ok(factory)),
            Err(95)
        );
    }
    for capacity in 0..request().capacity {
        assert_eq!(
            observe(
                &manager,
                &Request {
                    capacity,
                    ..request()
                }
                .encode(),
                &attached(),
                |_| Ok(factory)
            ),
            Err(22)
        );
    }
    assert_eq!(manager.attributes(pair.master_object_id).unwrap(), before);
    assert!(manager.take_terminal_signal().is_none());
}

#[test]
fn framing_rejects_unknown_versions_reserved_bytes_and_unbounded_capacity() {
    let bytes = request().encode();
    assert_eq!(Request::decode(&bytes), Ok(request()));
    for length in 0..bytes.len() {
        assert_eq!(Request::decode(&bytes[..length]), Err(-22));
    }
    for index in [0, 4, 6, 20, 23] {
        let mut bad = bytes;
        bad[index] ^= 1;
        assert_eq!(Request::decode(&bad), Err(-22));
    }
    let mut extended = bytes.to_vec();
    extended.push(0);
    assert_eq!(Request::decode(&extended), Err(-22));
    let request = Request {
        capacity: u32::MAX,
        ..request()
    };
    assert_eq!(
        observe_with(
            11,
            30,
            request,
            |_, _, _, _| panic!("invalid local request"),
            |_| panic!()
        ),
        Err(22)
    );
}

#[test]
fn failed_transport_keeps_the_borrowed_request_grant_owned_by_the_caller() {
    assert_eq!(
        observe_with(
            11,
            30,
            request(),
            |_, _, _, _| Err(32),
            |_| panic!("request grant is borrowed")
        ),
        Err(32)
    );
    for (endpoint, factory) in [(0, 30), (11, 0), (11, 11)] {
        assert_eq!(
            observe_with(
                endpoint,
                factory,
                request(),
                |_, _, _, _| panic!(),
                |_| panic!()
            ),
            Err(13)
        );
    }
}

#[test]
fn malformed_success_reclaims_each_unexpected_reply_reference_once() {
    for flags in [0, IPC_DELIVERY_ENDPOINT_HANDLE] {
        let closed = std::cell::RefCell::new(Vec::new());
        let result = observe_with(
            11,
            30,
            request(),
            |_, _, reply, objects| {
                *objects = attached();
                objects.delivery_flags = flags;
                objects.count = 2;
                objects.handles[1] = objects.handles[0];
                reply.fill(0);
                Ok(reply.len() as u64)
            },
            |handle| closed.borrow_mut().push(handle),
        );
        assert_eq!(result, Err(5));
        assert_eq!(*closed.borrow(), [70]);
    }
}

#[test]
fn wire_status_and_length_errors_are_propagated_without_retry_or_fabricated_data() {
    for (status, length, error) in [
        (-13, 8, 13),
        (-9, 8, 9),
        (-95, 8, 95),
        (1, 8, 5),
        (i64::MIN, 8, 5),
        (-9, 9, 5),
        (0, 7, 5),
        (0, 21, 5),
    ] {
        let calls = Cell::new(0);
        assert_eq!(
            observe_with(
                11,
                30,
                request(),
                |_, _, reply, objects| {
                    calls.set(calls.get() + 1);
                    *objects = IpcObjectHandles::default();
                    reply[..8].copy_from_slice(&i64::to_le_bytes(status));
                    Ok(length)
                },
                |_| panic!()
            ),
            Err(error)
        );
        assert_eq!(calls.get(), 1);
    }
}
