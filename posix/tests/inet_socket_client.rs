use mochios_posix_client::{
    Client, ClientError, ObjectHandleAttachment, ObjectHandles, ObjectTransport, Transport,
};
use mochios_posix_protocol::{self as p, socket as w};
use std::{cell::RefCell, rc::Rc};
#[derive(Default)]
struct State {
    mode: u8,
    calls: usize,
}
#[derive(Clone)]
struct Mock(Rc<RefCell<State>>);
impl Transport for Mock {
    type Error = ();
    fn call(&self, _: &[u8], _: &mut [u8]) -> Result<usize, ()> {
        panic!("Handle-aware IPC required")
    }
}
impl ObjectTransport for Mock {
    type Handle = u32;
    fn close_received_handle(&self, _: u32) {
        panic!("caller owns response cleanup")
    }
    fn call_with_handles(
        &self,
        request: &[u8],
        output: &mut [u8],
        handles: &mut ObjectHandles<u32>,
    ) -> Result<usize, ()> {
        let (header, payload) = p::decode(request).unwrap();
        assert_eq!((header.opcode, header.flags), (p::OP_SOCKET_CREATE, 0));
        assert_eq!(w::Create::decode(payload).unwrap(), create());
        assert_eq!(handles.len(), 1);
        assert_eq!(
            handles.get(0).unwrap(),
            ObjectHandleAttachment {
                handle: 7,
                rights: w::inet_factory_rights()
            }
        );
        let mut s = self.0.borrow_mut();
        s.calls += 1;
        let mode = s.mode;
        handles.clear();
        let returned = ObjectHandleAttachment {
            handle: if mode == 5 { 7 } else { 41 },
            rights: if mode == 2 {
                w::descriptor_rights() | mnu_abi::HANDLE_RIGHT_MAP
            } else {
                w::descriptor_rights()
            },
        };
        handles.push(returned).unwrap();
        if mode == 3 {
            handles.push(returned).unwrap();
        }
        if mode == 4 {
            return Err(());
        }
        Ok(p::encode(
            p::Header {
                opcode: p::OP_STATUS,
                request_id: header.request_id + u64::from(mode == 6),
                status: if mode == 1 { -13 } else { 0 },
                ..Default::default()
            },
            &[],
            output,
        )
        .unwrap())
    }
}
fn create() -> w::Create {
    w::Create {
        domain: w::Domain::Ipv4,
        kind: w::Kind::Datagram,
        protocol: 17,
        options: w::NONBLOCKING,
    }
}
fn factory() -> ObjectHandleAttachment<u32> {
    ObjectHandleAttachment {
        handle: 7,
        rights: w::inet_factory_rights() | mnu_abi::HANDLE_RIGHT_DUPLICATE,
    }
}
#[test]
fn creation_transfers_factory_borrow_and_returns_one_socket_reference() {
    let state = Rc::new(RefCell::new(State::default()));
    let c = Client::new(Mock(state.clone()));
    let mut closed = vec![];
    assert_eq!(
        c.open_inet_datagram(create(), factory(), |h| closed.push(h)),
        Ok(ObjectHandleAttachment {
            handle: 41,
            rights: w::descriptor_rights()
        })
    );
    assert!(closed.is_empty());
    assert_eq!(state.borrow().calls, 1);
}
#[test]
fn malformed_replies_and_transport_failure_close_only_distinct_owned_results() {
    for mode in 1..=6 {
        let state = Rc::new(RefCell::new(State { mode, calls: 0 }));
        let c = Client::new(Mock(state.clone()));
        let mut closed = vec![];
        assert!(
            c.open_inet_datagram(create(), factory(), |h| closed.push(h))
                .is_err()
        );
        assert_eq!(closed, if mode == 5 { vec![] } else { vec![41] });
        assert_eq!(state.borrow().calls, 1);
    }
}
#[test]
fn invalid_requests_do_not_contact_the_service_or_consume_the_factory() {
    let state = Rc::new(RefCell::new(State::default()));
    let c = Client::new(Mock(state.clone()));
    for request in [
        w::Create {
            domain: w::Domain::Unix,
            ..create()
        },
        w::Create {
            kind: w::Kind::Stream,
            ..create()
        },
        w::Create {
            protocol: 6,
            ..create()
        },
        w::Create {
            options: 2,
            ..create()
        },
    ] {
        assert_eq!(
            c.open_inet_datagram(request, factory(), |_| panic!()),
            Err(ClientError::Remote(-22))
        );
    }
    assert_eq!(
        c.open_inet_datagram(
            create(),
            ObjectHandleAttachment {
                handle: 7,
                rights: mnu_abi::HANDLE_RIGHT_CONTROL
            },
            |_| panic!()
        ),
        Err(ClientError::Remote(-13))
    );
    assert_eq!(state.borrow().calls, 0);
}
