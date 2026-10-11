use std::cell::Cell;

use mochios_posix_client::{
    Client, ClientError, ObjectHandleAttachment, ObjectHandles, ObjectTransport, Transport,
};
use mochios_posix_protocol as protocol;

struct TreeTransport {
    opcode: u16,
    status: i32,
    unexpected_handle: bool,
    unexpected_payload: bool,
    transport_failure: bool,
    calls: Cell<u64>,
}

impl Default for TreeTransport {
    fn default() -> Self {
        Self {
            opcode: protocol::OP_PROCESS_TREE_TERMINATE,
            status: 0,
            unexpected_handle: false,
            unexpected_payload: false,
            transport_failure: false,
            calls: Cell::new(0),
        }
    }
}

impl Transport for TreeTransport {
    type Error = u32;
    fn call(&self, _: &[u8], _: &mut [u8]) -> Result<usize, u32> {
        panic!("tree termination must attach a ProcessHandle")
    }
}

impl ObjectTransport for TreeTransport {
    type Handle = u32;
    fn call_with_handles(
        &self,
        request: &[u8],
        response: &mut [u8],
        handles: &mut ObjectHandles<u32>,
    ) -> Result<usize, u32> {
        let (header, payload) = protocol::decode(request).unwrap();
        let calls = self.calls.get() + 1;
        self.calls.set(calls);
        assert_eq!(header.request_id, calls);
        assert_eq!(header.opcode, self.opcode);
        assert_eq!(header.flags, 0);
        assert!(payload.is_empty());
        assert_eq!(handles.len(), 1);
        assert_eq!(handles.get(0), Some(root()));
        handles.clear();
        if self.transport_failure {
            return Err(7);
        }
        if self.unexpected_handle {
            handles.push(root()).unwrap();
        }
        protocol::encode(
            protocol::Header {
                opcode: protocol::OP_STATUS,
                request_id: header.request_id,
                status: self.status,
                payload_len: u32::from(self.unexpected_payload),
                ..Default::default()
            },
            if self.unexpected_payload { &[0] } else { &[] },
            response,
        )
        .map_err(|_| 8)
    }
}

fn root() -> ObjectHandleAttachment<u32> {
    ObjectHandleAttachment {
        handle: 52,
        rights: mnu_abi::HANDLE_RIGHT_WAIT | mnu_abi::HANDLE_RIGHT_SIGNAL,
    }
}

#[test]
fn tree_request_attaches_only_the_explicit_root_without_identity_bytes() {
    let client = Client::new(TreeTransport::default());
    client.terminate_launched_tree(root()).unwrap();
    client.terminate_launched_tree(root()).unwrap();
    assert_eq!(client.into_transport().calls.get(), 2);
}

#[test]
fn reclaim_uses_its_own_opcode_and_does_not_swallow_missing_process_errors() {
    let client = Client::new(TreeTransport {
        opcode: protocol::OP_PROCESS_TREE_RECLAIM,
        ..Default::default()
    });
    client.reclaim_launched_tree(root()).unwrap();
    client.reclaim_launched_tree(root()).unwrap();
    assert_eq!(client.into_transport().calls.get(), 2);
    for status in [
        protocol::STATUS_ESRCH,
        protocol::STATUS_EPERM,
        protocol::STATUS_EAGAIN,
        -5,
    ] {
        let client = Client::new(TreeTransport {
            opcode: protocol::OP_PROCESS_TREE_RECLAIM,
            status,
            ..Default::default()
        });
        assert_eq!(
            client.reclaim_launched_tree(root()),
            Err(ClientError::Remote(status))
        );
    }
    let client = Client::new(TreeTransport {
        opcode: protocol::OP_PROCESS_TREE_RECLAIM,
        unexpected_handle: true,
        ..Default::default()
    });
    assert_eq!(
        client.reclaim_launched_tree(root()),
        Err(ClientError::MismatchedResponse)
    );
    let client = Client::new(TreeTransport {
        opcode: protocol::OP_PROCESS_TREE_RECLAIM,
        transport_failure: true,
        ..Default::default()
    });
    assert_eq!(
        client.reclaim_launched_tree(root()),
        Err(ClientError::Transport(7))
    );
}

#[test]
fn tree_request_preserves_authority_and_delayed_exit_errors() {
    for status in [
        protocol::STATUS_EPERM,
        protocol::STATUS_EAGAIN,
        protocol::STATUS_ESRCH,
        -5,
    ] {
        let client = Client::new(TreeTransport {
            status,
            ..Default::default()
        });
        assert_eq!(
            client.terminate_launched_tree(root()),
            Err(ClientError::Remote(status))
        );
    }
}

#[test]
fn tree_request_propagates_service_transport_failure() {
    let client = Client::new(TreeTransport {
        transport_failure: true,
        ..Default::default()
    });
    assert_eq!(
        client.terminate_launched_tree(root()),
        Err(ClientError::Transport(7))
    );
}

#[test]
fn tree_request_rejects_unrequested_response_objects_and_payload() {
    let client = Client::new(TreeTransport {
        unexpected_handle: true,
        ..Default::default()
    });
    assert_eq!(
        client.terminate_launched_tree(root()),
        Err(ClientError::MismatchedResponse)
    );
    let client = Client::new(TreeTransport {
        unexpected_payload: true,
        ..Default::default()
    });
    assert_eq!(
        client.terminate_launched_tree(root()),
        Err(ClientError::ResponseTooLarge)
    );
}
