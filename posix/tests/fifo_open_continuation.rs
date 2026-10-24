use mochios_posix_client::{
    Client, ClientError, ObjectHandleAttachment as Object, ObjectHandles, ObjectTransport,
    OpenAtBase, Transport, file_admission::Error,
};
use mochios_posix_protocol as wire;
use std::cell::{Cell, RefCell};
struct Replies {
    mode: u8,
    calls: Cell<usize>,
    closed: RefCell<Vec<u32>>,
}
impl Transport for &Replies {
    type Error = u8;
    fn call(&self, _: &[u8], _: &mut [u8]) -> Result<usize, u8> {
        panic!("explicit Handles")
    }
}
impl ObjectTransport for &Replies {
    type Handle = u32;
    fn close_received_handle(&self, handle: u32) {
        self.closed.borrow_mut().push(handle);
    }
    fn call_with_handles(
        &self,
        bytes: &[u8],
        response: &mut [u8],
        objects: &mut ObjectHandles<u32>,
    ) -> Result<usize, u8> {
        let (request, body) = wire::decode(bytes).unwrap();
        assert_eq!(request.opcode, wire::OP_OPEN_AT);
        assert_ne!(request.flags & wire::fifo::OPEN_CONTINUATION, 0);
        assert_eq!(wire::decode_open_at(body).unwrap().path, b"original-fifo");
        let attempt = self.calls.get();
        self.calls.set(attempt + 1);
        assert_eq!(objects.get(0).unwrap().handle, 7);
        if self.mode == 1 && attempt == 1 {
            assert_eq!(objects.get(1).unwrap().handle, 90);
        }
        objects.clear();
        if self.mode == 1 && attempt == 0 {
            objects
                .push(Object {
                    handle: 90,
                    rights: mnu_abi::HANDLE_RIGHT_WAIT | mnu_abi::HANDLE_RIGHT_TRANSFER,
                })
                .unwrap();
            return wire::encode(
                wire::Header {
                    opcode: wire::OP_STATUS,
                    request_id: request.request_id,
                    status: wire::STATUS_MEMORY_ADMISSION_BUSY,
                    ..Default::default()
                },
                &[],
                response,
            )
            .map_err(|_| 1);
        }
        let mut data = Object {
            handle: 91,
            rights: wire::fifo::data_rights(wire::OPEN_READ).unwrap(),
        };
        let mut notify = Object {
            handle: 92,
            rights: wire::fifo::NOTIFICATION_RIGHTS,
        };
        match self.mode {
            2 => data.rights |= mnu_abi::HANDLE_RIGHT_WRITE,
            3 => notify.rights |= mnu_abi::HANDLE_RIGHT_READ,
            4 => notify.handle = data.handle,
            5 => notify.handle = 7,
            6 => data.handle = 0,
            _ => (),
        }
        objects.push(data).unwrap();
        objects.push(notify).unwrap();
        if self.mode == 7 {
            objects
                .push(Object {
                    handle: 93,
                    rights: 1,
                })
                .unwrap();
        }
        wire::encode(
            wire::Header {
                opcode: wire::OP_STATUS,
                request_id: request.request_id,
                flags: if self.mode == 8 {
                    2
                } else {
                    wire::fifo::OPEN_PENDING_REPLY
                },
                status: if self.mode == 9 { -5 } else { 0 },
                ..Default::default()
            },
            &[],
            response,
        )
        .map_err(|_| 1)
    }
}
fn replies(mode: u8) -> Replies {
    Replies {
        mode,
        calls: Cell::new(0),
        closed: RefCell::new(Vec::new()),
    }
}
fn base() -> OpenAtBase<u32> {
    OpenAtBase::Directory(Object {
        handle: 7,
        rights: mnu_abi::HANDLE_RIGHT_READ | mnu_abi::HANDLE_RIGHT_TRANSFER,
    })
}
#[test]
fn pending_open_keeps_data_and_returns_it_without_replaying_the_path() {
    for mode in [0, 1] {
        let transport = replies(mode);
        let client = Client::new(&transport);
        let mut waits = Vec::new();
        let opened = client
            .open_at_with_wait(
                base(),
                wire::OPEN_READ,
                0,
                b"original-fifo",
                |notification| {
                    assert!(!transport.closed.borrow().contains(&91));
                    if notification.handle == 92 && mode == 1 {
                        assert!(transport.closed.borrow().contains(&90));
                    }
                    waits.push(notification.handle);
                    Ok::<_, u8>(())
                },
            )
            .unwrap();
        assert_eq!(
            (opened.handle, opened.rights),
            (91, wire::fifo::data_rights(wire::OPEN_READ).unwrap())
        );
        assert_eq!(transport.calls.get(), usize::from(mode == 1) + 1);
        assert_eq!(waits, if mode == 1 { vec![90, 92] } else { vec![92] });
        assert_eq!(
            *transport.closed.borrow(),
            if mode == 1 { vec![90, 92] } else { vec![92] }
        );
    }
}
#[test]
fn interruption_and_unwind_cancel_both_refs_before_control_returns_to_libc() {
    let transport = replies(0);
    let client = Client::new(&transport);
    let result =
        client.open_at_with_wait(base(), wire::OPEN_READ, 0, b"original-fifo", |_| Err(4u8));
    assert_eq!(result, Err(Error::Wait(4)));
    assert_eq!(*transport.closed.borrow(), [92, 91]);
    assert_eq!(transport.calls.get(), 1);
    let transport = replies(0);
    let client = Client::new(&transport);
    let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = client.open_at_with_wait(
            base(),
            wire::OPEN_READ,
            0,
            b"original-fifo",
            |_| -> Result<(), u8> { panic!("wait unwinds") },
        );
    }));
    assert!(panic.is_err());
    assert_eq!(*transport.closed.borrow(), [92, 91]);
    assert_eq!(transport.calls.get(), 1);
}
#[test]
fn malformed_continuations_never_wait_and_close_owned_handles_once() {
    for mode in 2..10 {
        let transport = replies(mode);
        let client = Client::new(&transport);
        assert_eq!(
            client.open_at_with_wait(
                base(),
                wire::OPEN_READ,
                0,
                b"original-fifo",
                |_| -> Result<(), u8> { panic!("malformed ownership") }
            ),
            Err(Error::Operation(ClientError::MismatchedResponse))
        );
        let mut expected = match mode {
            4 => vec![91],
            5 => vec![91],
            6 => vec![92],
            7 => vec![91, 92, 93],
            _ => vec![91, 92],
        };
        expected.sort_unstable();
        let mut closed = transport.closed.borrow().clone();
        closed.sort_unstable();
        assert_eq!(closed, expected);
        assert!(!closed.contains(&7));
        assert_eq!(transport.calls.get(), 1);
    }
    for options in [
        wire::OPEN_READ | wire::OPEN_NONBLOCK,
        wire::OPEN_READ | wire::OPEN_WRITE,
    ] {
        let transport = replies(0);
        let client = Client::new(&transport);
        assert_eq!(
            client.open_at_with_wait(
                base(),
                options,
                0,
                b"original-fifo",
                |_| -> Result<(), u8> { panic!("pending reply forbidden") }
            ),
            Err(Error::Operation(ClientError::MismatchedResponse))
        );
        assert_eq!(*transport.closed.borrow(), [91, 92]);
    }
}
