use mochios_posix_client::{
    Client, ObjectHandleAttachment, ObjectHandles, ObjectTransport, Transport,
};
use mochios_posix_protocol as protocol;

struct AttachedTransport;
impl Transport for AttachedTransport {
    type Error = ();
    fn call(&self, _: &[u8], _: &mut [u8]) -> Result<usize, ()> {
        panic!("attachment required")
    }
}
impl ObjectTransport for AttachedTransport {
    type Handle = u32;

    fn close_received_handle(&self, _: u32) {
        panic!("unexpected owned reply Handle in this fixture");
    }
    fn call_with_handles(
        &self,
        request: &[u8],
        response: &mut [u8],
        handles: &mut ObjectHandles<u32>,
    ) -> Result<usize, ()> {
        let (header, payload) = protocol::decode(request).unwrap();
        assert_eq!(header.opcode, protocol::OP_SIGNAL_THREAD_SEND);
        let send = protocol::decode_signal_send_request(payload).unwrap();
        assert_eq!((send.selector, send.signal), (0, 10));
        assert_eq!(handles.len(), 1);
        assert_eq!(
            handles.get(0),
            Some(ObjectHandleAttachment {
                handle: 17,
                rights: mnu_abi::HANDLE_RIGHT_WAIT | mnu_abi::HANDLE_RIGHT_SIGNAL
            })
        );
        handles.clear();
        protocol::encode(
            protocol::Header {
                opcode: protocol::OP_STATUS,
                request_id: header.request_id,
                ..Default::default()
            },
            &[],
            response,
        )
        .map_err(|_| ())
    }
}

#[test]
fn client_sends_an_explicit_attenuated_handle_and_no_target_identity() {
    Client::new(AttachedTransport)
        .send_thread_signal(
            10,
            ObjectHandleAttachment {
                handle: 17,
                rights: mnu_abi::HANDLE_RIGHT_WAIT | mnu_abi::HANDLE_RIGHT_SIGNAL,
            },
        )
        .unwrap();
}

#[test]
fn runtime_publishes_readiness_after_handle_registration_and_uses_posix_return_codes() {
    let runtime = include_str!("../../../user/crates/newlib-runtime/src/lib.rs");
    let entry = runtime
        .split("fn pthread_start_trampoline(")
        .nth(1)
        .unwrap()
        .split("fn __getreent(")
        .next()
        .unwrap();
    assert!(
        entry.find("setup_signal_delivery(control)").unwrap()
            < entry.find("THREAD_RUNNING").unwrap()
    );
    assert!(entry.contains("native_mutex_wake_all(&control.state)"));
    let send = runtime
        .split("fn pthread_kill(")
        .nth(1)
        .unwrap()
        .split("fn _times(")
        .next()
        .unwrap();
    assert!(send.contains(".send_thread_signal("));
    assert!(send.contains("control.native_handle.load"));
    assert!(send.contains("result.err().unwrap_or(0)"));
    assert!(!send.contains("set_errno("));
    let main = include_str!("../src/main.rs");
    let path = main
        .split("if header.opcode == protocol::OP_SIGNAL_THREAD_SEND")
        .nth(1)
        .unwrap()
        .split("if header.opcode == protocol::OP_SIGNAL_THREAD_REGISTER")
        .next()
        .unwrap();
    assert!(path.contains("endpoint_execution_identity(sender)"));
    assert!(path.contains("handle_status(attached.handle)"));
    assert!(path.contains("attached.rights & required != required"));
}
