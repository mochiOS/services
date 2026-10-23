use mochios_posix_client::{
    Client, ClientError, ObjectHandleAttachment, ObjectHandles, ObjectTransport, Transport,
};
use mochios_posix_protocol as protocol;
use posix_service::{
    pty::PtyManager,
    pty_factory::MASTER_RIGHTS,
    terminal_publication::{Lease, Name},
};
use std::{
    cell::{Cell, RefCell},
    sync::{Mutex, mpsc},
};

#[test]
fn master_creation_never_publishes_a_native_slave_and_is_locked_before_naming() {
    let manager = Mutex::new(PtyManager::new());
    let calls = Cell::new(0);
    let (retire, retired) = mpsc::channel();
    let response = posix_service::pty_master::open(
        &manager,
        71,
        |object, rights| {
            let mut manager = manager.try_lock().unwrap();
            assert_eq!(rights, MASTER_RIGHTS);
            assert_eq!(manager.signal_object_ids(object).unwrap(), [object]);
            assert_eq!(
                manager
                    .control(object, protocol::PTY_CONTROL_GET_SLAVE_LOCK, &[], 4)
                    .unwrap(),
                1u32.to_le_bytes()
            );
            calls.set(calls.get() + 1);
            Ok(61)
        },
        |pair| {
            let manager = manager.try_lock().unwrap();
            assert_eq!(
                manager.object_ids(pair.master_object_id).unwrap(),
                [pair.master_object_id, pair.slave_object_id]
            );
            assert_eq!(
                manager.signals(pair.master_object_id).unwrap(),
                mnu_abi::HANDLE_SIGNAL_PEER_CLOSED | mnu_abi::HANDLE_SIGNAL_IDLE
            );
            assert_eq!(manager.signals(pair.slave_object_id), Err(9));
            Ok(())
        },
        |pair| {
            let mut manager = manager.try_lock().unwrap();
            let factory = manager.create_slave_factory(pair.master_object_id).unwrap();
            assert_eq!(manager.open_slave_from_factory(factory), Err(5));
            manager
                .attach_slave_name(
                    pair.master_object_id,
                    Lease::new(
                        Name {
                            component: b"71-2".to_vec(),
                            device: 7,
                            node_id: 8,
                        },
                        retire,
                    ),
                )
                .unwrap();
            manager.release(factory).unwrap();
            Ok(())
        },
        |_| panic!("successful transfer must retain its outgoing master"),
    );
    assert_eq!(response.response.header.opcode, protocol::OP_STATUS);
    assert_eq!(response.response.header.request_id, 71);
    assert_eq!(response.response.header.status, 0);
    assert_eq!(calls.get(), 1);
    assert_eq!(
        response.handles,
        [posix_service::OpenedObject {
            handle: 61,
            rights: MASTER_RIGHTS
        }]
    );
    assert!(retired.try_recv().is_err());
    let mut manager = manager.lock().unwrap();
    manager
        .control(
            2,
            protocol::PTY_CONTROL_SET_SLAVE_LOCK,
            &0u32.to_le_bytes(),
            0,
        )
        .unwrap();
    let slave = manager.reopen_slave(2).unwrap();
    assert_ne!(slave, 3);
    manager.release(2).unwrap();
    assert_eq!(retired.recv().unwrap().component, b"71-2");
}

#[test]
fn every_master_publication_failure_reclaims_exact_owned_state_without_peer_rpc_under_lock() {
    for stage in 0..4 {
        let manager = Mutex::new(PtyManager::new());
        let closed = RefCell::new(Vec::new());
        let (retire, retired) = mpsc::channel();
        let result = posix_service::pty_master::open(
            &manager,
            72,
            |_, _| {
                assert!(manager.try_lock().is_ok());
                match stage {
                    0 => Err(-12),
                    1 => Ok(0),
                    _ => Ok(61),
                }
            },
            |_| {
                assert!(manager.try_lock().is_ok());
                if stage == 2 { Err(-5) } else { Ok(()) }
            },
            |pair| {
                let mut manager = manager.try_lock().unwrap();
                manager
                    .attach_slave_name(
                        pair.master_object_id,
                        Lease::new(
                            Name {
                                component: b"71-2".to_vec(),
                                device: 7,
                                node_id: 8,
                            },
                            retire,
                        ),
                    )
                    .unwrap();
                Err(-13)
            },
            |handle| {
                assert!(manager.try_lock().is_ok());
                closed.borrow_mut().push(handle);
            },
        );
        assert_eq!(result.response.header.opcode, protocol::OP_STATUS);
        assert_eq!(result.response.header.status, [-12, -5, -5, -13][stage]);
        assert!(result.handles.is_empty());
        assert_eq!(*closed.borrow(), if stage < 2 { vec![] } else { vec![61] });
        assert_eq!(manager.lock().unwrap().object_ids(2), Err(9));
        if stage == 3 {
            assert_eq!(retired.recv().unwrap().node_id, 8);
        } else {
            assert!(retired.try_recv().is_err());
        }
    }
}

struct Wire {
    values: Vec<u32>,
    closed: RefCell<Vec<u32>>,
    status: i32,
    transport_error: bool,
}
impl Transport for Wire {
    type Error = ();
    fn call(&self, _: &[u8], _: &mut [u8]) -> Result<usize, ()> {
        panic!("objects required")
    }
}
impl ObjectTransport for Wire {
    type Handle = u32;
    fn close_received_handle(&self, handle: u32) {
        self.closed.borrow_mut().push(handle);
    }
    fn call_with_handles(
        &self,
        request: &[u8],
        output: &mut [u8],
        objects: &mut ObjectHandles<u32>,
    ) -> Result<usize, ()> {
        let (header, payload) = protocol::decode(request).unwrap();
        assert_eq!(header.opcode, protocol::OP_PTY_OPEN_MASTER);
        assert_eq!(header.flags, 0);
        assert!(payload.is_empty() && objects.is_empty());
        for handle in &self.values {
            objects
                .push(ObjectHandleAttachment {
                    handle: *handle,
                    rights: MASTER_RIGHTS,
                })
                .unwrap();
        }
        if self.transport_error {
            return Err(());
        }
        protocol::encode(
            protocol::Header {
                opcode: protocol::OP_STATUS,
                request_id: header.request_id,
                status: self.status,
                ..Default::default()
            },
            &[],
            output,
        )
        .map_err(|_| ())
    }
}

#[test]
fn client_accepts_exactly_one_master_and_closes_all_rejected_received_references() {
    for values in [vec![], vec![61], vec![61, 62], vec![0], vec![61, 61]] {
        for (status, transport_error) in [(0, false), (-13, false), (0, true)] {
            let client = Client::new(Wire {
                values: values.clone(),
                closed: RefCell::new(Vec::new()),
                status,
                transport_error,
            });
            let result = client.open_pty_master();
            if values == [61] && status == 0 && !transport_error {
                assert_eq!(result.unwrap().handle, 61);
                assert!(client.transport().closed.borrow().is_empty());
            } else {
                assert!(result.is_err());
                let expected: std::collections::BTreeSet<_> =
                    values.iter().copied().filter(|v| *v != 0).collect();
                let closed = client.transport().closed.borrow();
                assert_eq!(
                    closed
                        .iter()
                        .copied()
                        .collect::<std::collections::BTreeSet<_>>(),
                    expected
                );
                assert_eq!(closed.len(), expected.len());
                if !transport_error && status != 0 {
                    assert_eq!(result, Err(ClientError::Remote(status)));
                }
            }
        }
    }
}

#[test]
fn master_requests_share_strict_envelope_validation_before_allocation() {
    let header = protocol::Header {
        opcode: protocol::OP_PTY_OPEN_MASTER,
        request_id: 73,
        ..Default::default()
    };
    for flags in [0, 1] {
        let response = posix_service::pty_request::execute(
            protocol::Header { flags, ..header },
            &[],
            &[] as &[posix_service::AttachedObject<u32>],
            || {
                assert_eq!(flags, 0);
                posix_service::ObjectResponse {
                    response: posix_service::Response {
                        header: protocol::Header {
                            request_id: 73,
                            ..Default::default()
                        },
                        payload: Vec::new(),
                    },
                    handles: Vec::new(),
                }
            },
        );
        assert_eq!(
            response.response.header.status,
            if flags == 0 { 0 } else { -22 }
        );
    }
}
