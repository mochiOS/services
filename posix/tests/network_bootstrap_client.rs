use mochios_posix_client::{
    Client, ClientError, ObjectHandleAttachment, ObjectHandles, ObjectTransport, Transport,
};
use mochios_posix_protocol as wire;
use std::{cell::RefCell, rc::Rc};
#[derive(Default)]
struct State {
    mode: u8,
    calls: usize,
    closed: Vec<u32>,
}
#[derive(Clone)]
struct Mock(Rc<RefCell<State>>);
impl Transport for Mock {
    type Error = ();
    fn call(&self, _: &[u8], _: &mut [u8]) -> Result<usize, ()> {
        panic!("Handle attachment required")
    }
}
impl ObjectTransport for Mock {
    type Handle = u32;
    fn close_received_handle(&self, handle: u32) {
        self.0.borrow_mut().closed.push(handle);
    }
    fn call_with_handles(
        &self,
        request: &[u8],
        output: &mut [u8],
        handles: &mut ObjectHandles<u32>,
    ) -> Result<usize, ()> {
        let (header, payload) = wire::decode(request).unwrap();
        assert_eq!(
            (header.opcode, header.flags),
            (wire::OP_NETWORK_ENDPOINT_INSTALL, 0)
        );
        assert!(payload.is_empty());
        assert_eq!(handles.len(), 1);
        assert_eq!(
            handles.get(0),
            Some(ObjectHandleAttachment {
                handle: 7,
                rights: wire::network::endpoint_rights()
            })
        );
        let mut state = self.0.borrow_mut();
        state.calls += 1;
        let mode = state.mode;
        handles.clear();
        if matches!(mode, 1 | 2 | 3 | 4 | 5 | 6) {
            handles
                .push(ObjectHandleAttachment {
                    handle: if mode == 6 { 7 } else { 41 },
                    rights: wire::network::endpoint_rights(),
                })
                .unwrap();
        }
        if mode == 4 {
            return Err(());
        }
        let response = wire::Header {
            opcode: wire::OP_STATUS,
            flags: if mode == 3 { 1 } else { 0 },
            status: if mode == 1 { -12 } else { 0 },
            request_id: header.request_id + u64::from(mode == 5),
            ..Default::default()
        };
        Ok(wire::encode(response, &[], output).unwrap())
    }
}
fn endpoint() -> ObjectHandleAttachment<u32> {
    ObjectHandleAttachment {
        handle: 7,
        rights: wire::network::endpoint_rights() | mnu_abi::HANDLE_RIGHT_RECEIVE,
    }
}
#[test]
fn installation_uses_one_rights_restricted_attachment_and_no_wire_identity() {
    let state = Rc::new(RefCell::new(State::default()));
    let c = Client::new(Mock(Rc::clone(&state)));
    assert_eq!(c.install_network_endpoint(endpoint()), Ok(()));
    assert_eq!(state.borrow().calls, 1);
    assert!(state.borrow().closed.is_empty());
    assert_eq!(
        c.install_network_endpoint(ObjectHandleAttachment {
            handle: 0,
            ..endpoint()
        }),
        Err(ClientError::Remote(-13))
    );
    assert_eq!(
        c.install_network_endpoint(ObjectHandleAttachment {
            handle: 7,
            rights: mnu_abi::HANDLE_RIGHT_SEND
        }),
        Err(ClientError::Remote(-13))
    );
    assert_eq!(state.borrow().calls, 1);
}
#[test]
fn failed_handoffs_never_retry_or_close_the_borrowed_endpoint() {
    for mode in 1..=6 {
        let state = Rc::new(RefCell::new(State {
            mode,
            ..Default::default()
        }));
        let c = Client::new(Mock(Rc::clone(&state)));
        assert!(c.install_network_endpoint(endpoint()).is_err());
        assert_eq!(state.borrow().calls, 1);
        assert_eq!(
            state.borrow().closed,
            if mode == 6 { vec![] } else { vec![41] }
        );
    }
}
