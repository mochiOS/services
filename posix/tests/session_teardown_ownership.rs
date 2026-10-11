extern crate alloc;

use mochios_posix_client::{
    Client, ClientError, ObjectHandleAttachment, ObjectHandles, ObjectTransport, Transport,
};
use mochios_posix_protocol as protocol;
use std::cell::Cell;
use std::collections::BTreeMap;
use std::rc::Rc;

mod native_process {
    use super::*;
    pub struct NativeProcess {
        pub handle: u32,
        pub closed: Rc<Cell<usize>>,
    }
    impl NativeProcess {
        pub fn termination_attachment(&self) -> ObjectHandleAttachment<u32> {
            ObjectHandleAttachment {
                handle: self.handle,
                rights: mnu_abi::HANDLE_RIGHT_WAIT | mnu_abi::HANDLE_RIGHT_SIGNAL,
            }
        }
    }
    impl Drop for NativeProcess {
        fn drop(&mut self) {
            self.closed.set(self.closed.get() + 1);
        }
    }
}
#[path = "../../service-manager/src/session_teardown.rs"]
mod production;

struct Replies {
    status: Cell<i32>,
    fail_transport: Cell<bool>,
    calls: Cell<usize>,
}
impl Transport for Replies {
    type Error = u32;
    fn call(&self, _: &[u8], _: &mut [u8]) -> Result<usize, u32> {
        panic!("explicit Handle required")
    }
}
impl ObjectTransport for Replies {
    type Handle = u32;
    fn call_with_handles(
        &self,
        request: &[u8],
        response: &mut [u8],
        handles: &mut ObjectHandles<u32>,
    ) -> Result<usize, u32> {
        self.calls.set(self.calls.get() + 1);
        let (header, payload) = protocol::decode(request).unwrap();
        assert_eq!(header.opcode, protocol::OP_PROCESS_TREE_TERMINATE);
        assert!(payload.is_empty());
        assert_eq!(handles.len(), 1);
        assert_eq!(
            handles.get(0),
            Some(ObjectHandleAttachment {
                handle: 52,
                rights: mnu_abi::HANDLE_RIGHT_WAIT | mnu_abi::HANDLE_RIGHT_SIGNAL
            })
        );
        handles.clear();
        if self.fail_transport.get() {
            return Err(7);
        }
        protocol::encode(
            protocol::Header {
                opcode: protocol::OP_STATUS,
                request_id: header.request_id,
                status: self.status.get(),
                ..Default::default()
            },
            &[],
            response,
        )
        .map_err(|_| 8)
    }
}

#[test]
fn failed_or_delayed_teardown_keeps_the_actual_process_owner_until_success() {
    let closed = Rc::new(Cell::new(0));
    let mut owners = BTreeMap::new();
    owners.insert(
        1030,
        native_process::NativeProcess {
            handle: 52,
            closed: Rc::clone(&closed),
        },
    );
    let client = Client::new(Replies {
        status: Cell::new(0),
        fail_transport: Cell::new(false),
        calls: Cell::new(0),
    });
    for error in [protocol::STATUS_EAGAIN, protocol::STATUS_EPERM, -5] {
        client.transport().status.set(error);
        assert_eq!(
            production::terminate_owned_root(&client, &mut owners, 1030),
            Err(ClientError::Remote(error))
        );
        assert!(owners.contains_key(&1030));
        assert_eq!(closed.get(), 0);
    }
    client.transport().status.set(0);
    client.transport().fail_transport.set(true);
    assert_eq!(
        production::terminate_owned_root(&client, &mut owners, 1030),
        Err(ClientError::Transport(7))
    );
    assert!(owners.contains_key(&1030));
    assert_eq!(closed.get(), 0);
    client.transport().fail_transport.set(false);
    production::terminate_owned_root(&client, &mut owners, 1030).unwrap();
    assert!(!owners.contains_key(&1030));
    assert_eq!(closed.get(), 1);
    let calls = client.transport().calls.get();
    assert_eq!(
        production::terminate_owned_root(&client, &mut owners, 1030),
        Err(ClientError::Remote(protocol::STATUS_ESRCH))
    );
    assert_eq!(client.transport().calls.get(), calls);
}

#[test]
fn teardown_never_captures_an_arbitrary_pid_or_discards_an_owner_before_reply() {
    let source = include_str!("../../service-manager/src/session_teardown.rs");
    assert!(!source.contains("open_handle_for_process_id"));
    assert!(!source.contains("process::list"));
    assert!(
        source.find("client.terminate_launched_tree").unwrap()
            < source.find("owners.remove").unwrap()
    );
    let owner = include_str!("../../service-manager/src/native_process.rs");
    assert!(owner.contains("handle: self.handle"));
    assert!(owner.contains("HANDLE_RIGHT_WAIT | platform::handle::HANDLE_RIGHT_SIGNAL"));
}
