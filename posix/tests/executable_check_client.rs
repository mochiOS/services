use mochios_posix_client::{
    Client, ClientError, ObjectHandleAttachment, ObjectHandles, ObjectTransport, Transport,
};
use mochios_posix_protocol as wire;
use std::{cell::RefCell, rc::Rc};

#[derive(Default)]
struct State {
    calls: usize,
    closed: Vec<u32>,
    status: i32,
    flags: u32,
    extra: bool,
    body: bool,
    transport_error: bool,
}
#[derive(Clone)]
struct Mock(Rc<RefCell<State>>);
impl Transport for Mock {
    type Error = ();
    fn call(&self, _: &[u8], _: &mut [u8]) -> Result<usize, ()> {
        panic!("explicit Handle required")
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
        assert_eq!(header.opcode, wire::OP_CHECK_EXECUTABLE);
        assert_eq!(header.flags, 0);
        assert!(payload.is_empty());
        assert_eq!(handles.len(), 1);
        assert_eq!(
            handles.get(0).unwrap(),
            ObjectHandleAttachment {
                handle: 19,
                rights: wire::CHECK_EXECUTABLE_RIGHTS
            }
        );
        handles.clear();
        let mut state = self.0.borrow_mut();
        state.calls += 1;
        if state.extra {
            handles
                .push(ObjectHandleAttachment {
                    handle: 42,
                    rights: 1,
                })
                .unwrap();
        }
        if state.transport_error {
            return Err(());
        }
        let payload = if state.body { &[1][..] } else { &[] };
        wire::encode(
            wire::Header {
                opcode: wire::OP_STATUS,
                request_id: header.request_id,
                flags: state.flags,
                status: state.status,
                payload_len: payload.len() as u32,
            },
            payload,
            output,
        )
        .map_err(|_| ())
    }
}

#[test]
fn client_attenuates_explicit_authority_and_preserves_failures_without_leaking_replies() {
    for (status, flags, extra, body, transport_error) in [
        (0, 0, false, false, false),
        (-13, 0, false, false, false),
        (-9, 0, false, false, false),
        (-5, 0, false, false, false),
        (0, 1, false, false, false),
        (0, 0, true, false, false),
        (-13, 0, true, false, false),
        (0, 0, true, false, true),
        (0, 0, false, true, false),
    ] {
        let state = Rc::new(RefCell::new(State {
            status,
            flags,
            extra,
            body,
            transport_error,
            ..Default::default()
        }));
        let client = Client::new(Mock(state.clone()));
        let file = ObjectHandleAttachment {
            handle: 19,
            rights: wire::CHECK_EXECUTABLE_RIGHTS
                | mnu_abi::HANDLE_RIGHT_WRITE
                | mnu_abi::HANDLE_RIGHT_CONTROL
                | mnu_abi::HANDLE_RIGHT_DUPLICATE,
        };
        let result = client.check_executable(file);
        if status != 0 && !transport_error {
            assert!(matches!(result, Err(ClientError::Remote(s)) if s == status));
        }
        assert_eq!(
            result.is_ok(),
            status == 0 && flags == 0 && !extra && !body && !transport_error
        );
        assert_eq!(state.borrow().calls, 1);
        assert_eq!(state.borrow().closed, if extra { vec![42] } else { vec![] });
    }
}

#[test]
fn missing_read_or_transfer_fails_before_transport_even_if_control_is_present() {
    let state = Rc::new(RefCell::new(State::default()));
    let client = Client::new(Mock(state.clone()));
    for rights in [
        0,
        mnu_abi::HANDLE_RIGHT_READ,
        mnu_abi::HANDLE_RIGHT_TRANSFER,
        mnu_abi::HANDLE_RIGHT_CONTROL | mnu_abi::HANDLE_RIGHT_TRANSFER,
    ] {
        assert!(matches!(
            client.check_executable(ObjectHandleAttachment { handle: 19, rights }),
            Err(ClientError::Remote(-13))
        ));
    }
    assert_eq!(state.borrow().calls, 0);
    assert!(state.borrow().closed.is_empty());
}
