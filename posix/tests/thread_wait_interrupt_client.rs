use mochios_posix_client::{
    Client, ClientError, ObjectHandleAttachment, ObjectHandles, ObjectTransport, Transport,
};
use mochios_posix_protocol as wire;
use std::cell::Cell;

struct Backend {
    calls: Cell<usize>,
    status: Cell<i32>,
}
impl Transport for Backend {
    type Error = ();
    fn call(&self, _: &[u8], _: &mut [u8]) -> Result<usize, ()> {
        panic!("explicit ThreadHandle required")
    }
}
impl ObjectTransport for Backend {
    type Handle = u32;
    fn close_received_handle(&self, _: u32) {
        panic!("interrupt replies carry no handles")
    }
    fn call_with_handles(
        &self,
        request: &[u8],
        response: &mut [u8],
        handles: &mut ObjectHandles<u32>,
    ) -> Result<usize, ()> {
        let (header, payload) = wire::decode(request).unwrap();
        assert_eq!(header.opcode, wire::OP_THREAD_WAIT_INTERRUPT);
        assert!(payload.is_empty());
        assert_eq!(handles.len(), 1);
        assert_eq!(
            handles.get(0).unwrap(),
            ObjectHandleAttachment {
                handle: 71,
                rights: wire::THREAD_WAIT_INTERRUPT_RIGHTS
            }
        );
        handles.clear();
        self.calls.set(self.calls.get() + 1);
        wire::encode(
            wire::Header {
                opcode: wire::OP_STATUS,
                request_id: header.request_id,
                status: self.status.get(),
                ..Default::default()
            },
            &[],
            response,
        )
        .map_err(|_| ())
    }
}
#[test]
fn interrupt_attaches_only_wait_transfer_and_propagates_remote_errors() {
    let client = Client::new(Backend {
        calls: Cell::new(0),
        status: Cell::new(0),
    });
    assert_eq!(
        client.interrupt_thread_waits(ObjectHandleAttachment {
            handle: 71,
            rights: u64::MAX
        }),
        Ok(())
    );
    client.transport().status.set(-3);
    assert_eq!(
        client.interrupt_thread_waits(ObjectHandleAttachment {
            handle: 71,
            rights: u64::MAX
        }),
        Err(ClientError::Remote(-3))
    );
    assert_eq!(client.transport().calls.get(), 2);
}
#[test]
fn insufficient_thread_authority_never_enters_ipc() {
    let client = Client::new(Backend {
        calls: Cell::new(0),
        status: Cell::new(0),
    });
    for right in [mnu_abi::HANDLE_RIGHT_WAIT, mnu_abi::HANDLE_RIGHT_TRANSFER] {
        assert_eq!(
            client.interrupt_thread_waits(ObjectHandleAttachment {
                handle: 71,
                rights: wire::THREAD_WAIT_INTERRUPT_RIGHTS & !right
            }),
            Err(ClientError::Remote(-13))
        );
    }
    assert_eq!(client.transport().calls.get(), 0);
}
