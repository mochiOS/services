use mochios_net_device_protocol::datagram_authority as a;
use mochios_posix_client::{
    Client, ClientError, ObjectHandleAttachment as Handle, ObjectHandles, ObjectTransport,
    Transport, network,
};
use mochios_posix_protocol as p;
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
        panic!("Handle-aware endpoint required")
    }
}
impl ObjectTransport for Mock {
    type Handle = u32;
    fn close_received_handle(&self, _: u32) {
        panic!("caller cleanup owns replies")
    }
    fn call_with_handles(
        &self,
        request: &[u8],
        response: &mut [u8],
        handles: &mut ObjectHandles<u32>,
    ) -> Result<usize, ()> {
        assert!(handles.is_empty());
        let mut s = self.0.borrow_mut();
        s.calls += 1;
        let mode = s.mode;
        let stream = request.starts_with(b"NTCP");
        let factory = stream || request == a::ACQUIRE;
        let rights = if factory {
            mnu_abi::HANDLE_RIGHT_CONTROL
                | mnu_abi::HANDLE_RIGHT_DUPLICATE
                | mnu_abi::HANDLE_RIGHT_TRANSFER
        } else {
            p::network::client_endpoint_rights()
        };
        if mode != 1 {
            handles
                .push(Handle {
                    handle: 41,
                    rights: if mode == 2 {
                        rights | mnu_abi::HANDLE_RIGHT_MAP
                    } else {
                        rights
                    },
                })
                .unwrap();
        }
        if mode == 3 {
            handles.push(Handle { handle: 41, rights }).unwrap();
        }
        if mode == 4 {
            return Err(());
        }
        if stream {
            use mochios_net_device_protocol::stream as w;
            let scopes = u32::from_le_bytes(request[8..12].try_into().unwrap());
            assert_eq!(request, w::scoped(w::ACQUIRE, scopes).unwrap());
            w::reply(w::ACQUIRE, if mode == 1 { -13 } else { 0 }, response).unwrap();
            if mode == 5 {
                response[12] = 1;
            }
            Ok(w::REPLY_LEN)
        } else if factory {
            a::reply(if mode == 1 { -13 } else { 0 }, response).unwrap();
            if mode == 5 {
                response[12] = 1;
            }
            Ok(a::REPLY_LEN)
        } else {
            let (header, payload) = p::decode(request).unwrap();
            assert_eq!(header.opcode, p::OP_NETWORK_ENDPOINT_GET);
            assert!(payload.is_empty());
            Ok(p::encode(
                p::Header {
                    opcode: p::OP_STATUS,
                    request_id: header.request_id + u64::from(mode == 5),
                    status: if mode == 1 { -6 } else { 0 },
                    ..Default::default()
                },
                &[],
                response,
            )
            .unwrap())
        }
    }
}
#[test]
fn getter_grants_only_callable_endpoint_and_factory_is_acquired_in_a_separate_call() {
    let state = Rc::new(RefCell::new(State::default()));
    let transport = Mock(state.clone());
    let client = Client::new(transport.clone());
    assert_eq!(
        client.network_endpoint(|_| panic!()),
        Ok(Handle {
            handle: 41,
            rights: p::network::client_endpoint_rights()
        })
    );
    let factory = network::acquire_factory(&transport, |_| panic!()).unwrap();
    assert_eq!(
        factory.rights,
        mnu_abi::HANDLE_RIGHT_CONTROL
            | mnu_abi::HANDLE_RIGHT_DUPLICATE
            | mnu_abi::HANDLE_RIGHT_TRANSFER
    );
    assert_eq!(state.borrow().calls, 2);
}
#[test]
fn getter_and_factory_failure_cleanup_are_owned_distinct_and_never_replayed() {
    for factory in [false, true] {
        for mode in 1..=5 {
            let state = Rc::new(RefCell::new(State { mode, calls: 0 }));
            let transport = Mock(state.clone());
            let mut closed = vec![];
            let result = if factory {
                network::acquire_factory(&transport, |h| closed.push(h))
            } else {
                Client::new(transport).network_endpoint(|h| closed.push(h))
            };
            assert!(result.is_err());
            assert_eq!(state.borrow().calls, 1);
            assert_eq!(closed, if mode == 1 { vec![] } else { vec![41] });
            if mode == 1 {
                assert_eq!(
                    result,
                    Err(ClientError::Remote(if factory { -13 } else { -6 }))
                );
            }
        }
    }
}

#[test]
fn tcp_acquisition_preserves_scope_subset_and_checks_reply_ownership() {
    for scopes in [
        network::CONNECT_SCOPE,
        network::LISTEN_SCOPE,
        network::CONNECT_SCOPE | network::LISTEN_SCOPE,
    ] {
        for mode in 0..=5 {
            let state = Rc::new(RefCell::new(State { mode, calls: 0 }));
            let transport = Mock(state.clone());
            let mut closed = Vec::new();
            let result = network::acquire_stream_factory(&transport, scopes, |h| closed.push(h));
            assert_eq!(result.is_ok(), mode == 0);
            assert_eq!(state.borrow().calls, 1);
            assert_eq!(
                closed,
                if matches!(mode, 0 | 1) {
                    vec![]
                } else {
                    vec![41]
                }
            );
        }
    }
    let state = Rc::new(RefCell::new(State::default()));
    let transport = Mock(state.clone());
    for scopes in [0, 4, u32::MAX] {
        assert_eq!(
            network::acquire_stream_factory(&transport, scopes, |_| panic!()),
            Err(ClientError::Remote(-22))
        );
    }
    assert_eq!(state.borrow().calls, 0);
}
