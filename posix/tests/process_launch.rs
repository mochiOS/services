use mochios_posix_client::{
    Client, ObjectHandleAttachment, ObjectHandles, ObjectTransport, Transport,
};
use mochios_posix_protocol as protocol;

struct LaunchTransport;
impl Transport for LaunchTransport {
    type Error = ();
    fn call(&self, _: &[u8], _: &mut [u8]) -> Result<usize, ()> {
        panic!("launch must carry authenticated process objects")
    }
}

struct AbortTransport;
impl Transport for AbortTransport {
    type Error = ();
    fn call(&self, _: &[u8], _: &mut [u8]) -> Result<usize, ()> {
        panic!("abort must attach an authenticated child")
    }
}
impl ObjectTransport for AbortTransport {
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
        assert_eq!(header.opcode, protocol::OP_PROCESS_LAUNCH_ABORT);
        assert_eq!(header.flags, 0);
        assert!(payload.is_empty());
        assert_eq!(handles.len(), 1);
        assert_eq!(
            handles.get(0),
            Some(ObjectHandleAttachment {
                handle: 52,
                rights: mnu_abi::HANDLE_RIGHT_WAIT
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
fn failed_launch_cleanup_carries_only_a_wait_handle_not_a_pid() {
    Client::new(AbortTransport)
        .abort_launched_child(ObjectHandleAttachment {
            handle: 52,
            rights: mnu_abi::HANDLE_RIGHT_WAIT,
        })
        .unwrap();
}
impl ObjectTransport for LaunchTransport {
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
        assert_eq!(header.opcode, protocol::OP_PROCESS_LAUNCHED);
        assert_eq!(header.flags, 0);
        assert!(payload.is_empty());
        assert_eq!(handles.len(), 2);
        assert_eq!(
            handles.get(0),
            Some(ObjectHandleAttachment {
                handle: 51,
                rights: mnu_abi::HANDLE_RIGHT_WAIT,
            })
        );
        assert_eq!(
            handles.get(1),
            Some(ObjectHandleAttachment {
                handle: 52,
                rights: mnu_abi::HANDLE_RIGHT_WAIT | mnu_abi::HANDLE_RIGHT_SIGNAL,
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
fn launch_request_carries_two_attenuated_handles_without_identity_bytes() {
    Client::new(LaunchTransport)
        .register_launched_child(
            ObjectHandleAttachment {
                handle: 51,
                rights: mnu_abi::HANDLE_RIGHT_WAIT,
            },
            ObjectHandleAttachment {
                handle: 52,
                rights: mnu_abi::HANDLE_RIGHT_WAIT | mnu_abi::HANDLE_RIGHT_SIGNAL,
            },
        )
        .unwrap();
}

#[test]
fn native_launch_checks_both_process_objects_and_retains_only_the_child() {
    let runtime = include_str!("../src/main.rs");
    let implementation = runtime
        .split("fn adopt_launched_child(")
        .nth(1)
        .unwrap()
        .split("fn invalid_response(")
        .next()
        .unwrap();
    assert!(implementation.contains("requester.rights != platform::handle::HANDLE_RIGHT_WAIT"));
    assert!(implementation.contains("platform::process::handle_status(requester.handle)"));
    assert!(implementation.contains("platform::process::handle_status(child.handle)"));
    assert!(implementation.contains("process_id: parent_status.process_id"));
    assert!(implementation.contains("process_id: child_status.process_id"));
    let branch = runtime
        .split("if header.opcode == protocol::OP_PROCESS_LAUNCHED")
        .nth(1)
        .unwrap()
        .split("if matches!(")
        .next()
        .unwrap();
    assert!(branch.contains("payload.is_empty()"));
    assert!(branch.contains("attachments.len() == 2"));
    assert!(branch.contains("retained_handle = Some(attachments[1].handle)"));
    assert!(!branch.contains("retained_handle = Some(attachments[0].handle)"));
}
