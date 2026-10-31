use mochios_posix_client::{
    Client, ClientError, ObjectHandleAttachment as Object, ObjectHandles, ObjectTransport,
    Transport,
};
use mochios_posix_protocol::{self as p, process_domain as w};
use std::cell::{Cell, RefCell};
#[derive(Default)]
struct Mock {
    mode: u8,
    calls: Cell<u32>,
    closed: RefCell<Vec<u32>>,
}
impl Transport for Mock {
    type Error = u32;
    fn call(&self, _: &[u8], _: &mut [u8]) -> Result<usize, u32> {
        panic!("domain operations must use object transfer")
    }
}
fn source(handle: u32, rights: u64) -> Object<u32> {
    Object { handle, rights }
}
impl ObjectTransport for Mock {
    type Handle = u32;
    fn close_received_handle(&self, value: u32) {
        self.closed.borrow_mut().push(value);
    }
    fn call_with_handles(
        &self,
        request: &[u8],
        response: &mut [u8],
        handles: &mut ObjectHandles<u32>,
    ) -> Result<usize, u32> {
        self.calls.set(self.calls.get() + 1);
        let (header, payload) = p::decode(request).unwrap();
        assert_eq!(header.flags, 0);
        match header.opcode {
            w::OP_CREATE => {
                assert!(payload.is_empty());
                for object in handles.iter() {
                    assert_eq!(object.rights, w::PROCESS_RIGHTS);
                }
            }
            w::OP_CONTAINS => {
                assert!(payload.is_empty());
                assert_eq!(handles.len(), 2);
                assert_eq!(handles.get(0), Some(source(80, w::ATTACH_RIGHTS)));
                assert_eq!(handles.get(1), Some(source(7, w::PROCESS_RIGHTS)));
            }
            w::OP_SPAWN => {
                let mut groups = [0; 2];
                assert_eq!(
                    p::decode_spawn_credentials(payload, &mut groups).unwrap(),
                    (501, 20, 2)
                );
                assert_eq!(groups, [20, 42]);
                assert_eq!(handles.get(0), Some(source(80, w::ATTACH_RIGHTS)));
                assert_eq!(
                    handles.get(1),
                    Some(source(7, w::PROCESS_RIGHTS | mnu_abi::HANDLE_RIGHT_SIGNAL))
                );
            }
            _ => panic!("unassigned opcode"),
        }
        if self.mode == 1 {
            return Err(9);
        }
        handles.clear();
        if header.opcode == w::OP_CREATE {
            handles
                .push(source(
                    if self.mode == 3 { 7 } else { 90 },
                    if self.mode == 4 {
                        w::ATTACH_RIGHTS
                    } else {
                        w::TOKEN_RIGHTS
                    },
                ))
                .unwrap();
        } else if self.mode == 5 {
            handles.push(source(90, w::TOKEN_RIGHTS)).unwrap();
        }
        let membership = [if self.mode == 6 { 2 } else { 1 }];
        p::encode(
            p::Header {
                opcode: p::OP_STATUS,
                request_id: header.request_id,
                flags: u32::from(self.mode == 2),
                payload_len: if header.opcode == w::OP_CONTAINS {
                    1
                } else {
                    0
                },
                ..Default::default()
            },
            if header.opcode == w::OP_CONTAINS {
                &membership
            } else {
                &[]
            },
            response,
        )
        .map_err(|_| 8)
    }
}
#[test]
fn roots_and_members_are_transferred_with_exact_rights_and_no_identity_payload() {
    let client = Client::new(Mock::default());
    let root = source(7, mnu_abi::HANDLE_RIGHT_WAIT | mnu_abi::HANDLE_RIGHT_SIGNAL);
    assert_eq!(
        client.create_process_domain(&[root]).unwrap(),
        source(90, w::TOKEN_RIGHTS)
    );
    assert!(
        client
            .process_domain_contains(source(80, w::TOKEN_RIGHTS), root)
            .unwrap()
    );
    client
        .register_spawned_child_in_domain(source(80, w::TOKEN_RIGHTS), root, 501, 20, &[20, 42])
        .unwrap();
    assert_eq!(client.into_transport().calls.get(), 3);
}
#[test]
fn failed_domain_publication_drains_owned_handles_without_closing_borrowed_sources() {
    for mode in 1..=4 {
        let client = Client::new(Mock {
            mode,
            ..Default::default()
        });
        assert!(
            client
                .create_process_domain(&[source(7, w::PROCESS_RIGHTS)])
                .is_err()
        );
        let transport = client.into_transport();
        assert_eq!(
            *transport.closed.borrow(),
            if mode == 2 || mode == 4 {
                vec![90]
            } else {
                vec![]
            }
        );
    }
    for mode in [1, 2, 5, 6] {
        let client = Client::new(Mock {
            mode,
            ..Default::default()
        });
        assert!(
            client
                .process_domain_contains(source(80, w::TOKEN_RIGHTS), source(7, w::PROCESS_RIGHTS))
                .is_err()
        );
        let transport = client.into_transport();
        assert_eq!(
            *transport.closed.borrow(),
            if mode == 5 { vec![90] } else { vec![] }
        );
    }
    let client = Client::new(Mock::default());
    assert_eq!(
        client.create_process_domain(&[source(7, 0)]),
        Err(ClientError::Remote(-13))
    );
    assert_eq!(
        client.process_domain_contains(source(80, 0), source(7, w::PROCESS_RIGHTS)),
        Err(ClientError::Remote(-13))
    );
    assert_eq!(client.into_transport().calls.get(), 0);
}
