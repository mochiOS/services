use mochios_posix_client::{
    Client, ClientError, ObjectHandleAttachment as Object, ObjectHandles, ObjectTransport,
    OpenAtBase, StatAtBase, Transport, file_admission::Error,
};
use mochios_posix_protocol as wire;
use std::cell::{Cell, RefCell};

const TICKET: u64 = mnu_abi::HANDLE_RIGHT_WAIT | mnu_abi::HANDLE_RIGHT_TRANSFER;
struct Replies {
    opcode: u16,
    mode: u8,
    source: bool,
    calls: Cell<usize>,
    closed: RefCell<Vec<u32>>,
    payloads: RefCell<Vec<Vec<u8>>>,
}
impl Replies {
    fn new(opcode: u16, mode: u8, source: bool) -> Self {
        Self {
            opcode,
            mode,
            source,
            calls: Cell::new(0),
            closed: RefCell::new(vec![]),
            payloads: RefCell::new(vec![]),
        }
    }
}
impl Transport for &Replies {
    type Error = u8;
    fn call(&self, _: &[u8], _: &mut [u8]) -> Result<usize, u8> {
        panic!("explicit objects required")
    }
}
impl ObjectTransport for &Replies {
    type Handle = u32;
    fn close_received_handle(&self, handle: u32) {
        self.closed.borrow_mut().push(handle);
    }
    fn call_with_handles(
        &self,
        request: &[u8],
        response: &mut [u8],
        handles: &mut ObjectHandles<u32>,
    ) -> Result<usize, u8> {
        let (header, payload) = wire::decode(request).unwrap();
        let attempt = self.calls.get();
        self.calls.set(attempt + 1);
        assert_eq!(header.opcode, self.opcode);
        assert_eq!(
            header.flags,
            wire::MUTATION_ADMISSION
                | if attempt > 0 {
                    wire::MUTATION_ADMISSION_ATTACHED
                } else {
                    0
                }
        );
        assert_eq!(
            handles.len(),
            usize::from(self.source) + usize::from(attempt > 0)
        );
        if self.source {
            let rights = mnu_abi::HANDLE_RIGHT_TRANSFER
                | if self.opcode == wire::OP_FTRUNCATE {
                    mnu_abi::HANDLE_RIGHT_WRITE
                } else {
                    mnu_abi::HANDLE_RIGHT_READ
                };
            assert_eq!(handles.get(0), Some(Object { handle: 7, rights }));
        }
        if attempt > 0 {
            assert_eq!(
                handles.get(handles.len() - 1),
                Some(Object {
                    handle: 89 + attempt as u32,
                    rights: TICKET
                })
            );
            assert!(
                !self.closed.borrow().contains(&(89 + attempt as u32)),
                "retain old position until IPC completes"
            );
        }
        self.payloads.borrow_mut().push(payload.to_vec());
        if self.mode == 3 {
            return Err(42);
        } // Fault-injected borrowed labels.
        handles.clear();
        if self.mode == 1 {
            return wire::encode(
                wire::Header {
                    opcode: wire::OP_STATUS,
                    request_id: header.request_id,
                    status: -11,
                    ..Default::default()
                },
                &[],
                response,
            )
            .map_err(|_| 99);
        }
        let busy = self.mode != 14 && (self.mode != 0 || attempt < 2);
        if busy && self.mode != 4 {
            handles
                .push(Object {
                    handle: if self.mode == 7 {
                        7
                    } else {
                        90 + attempt as u32
                    },
                    rights: if self.mode == 5 { TICKET | 1 } else { TICKET },
                })
                .unwrap();
            if self.mode == 6 {
                handles.push(handles.get(0).unwrap()).unwrap();
            }
        } else if !busy && self.opcode == wire::OP_OPEN_AT {
            handles
                .push(Object {
                    handle: 200,
                    rights: mnu_abi::HANDLE_RIGHT_READ | mnu_abi::HANDLE_RIGHT_TRANSFER,
                })
                .unwrap();
        }
        if self.mode == 14 {
            handles.clear();
            for handle in [90, 91] {
                handles
                    .push(Object {
                        handle,
                        rights: TICKET,
                    })
                    .unwrap();
            }
        }
        if self.mode == 2 {
            return Err(42);
        }
        if self.mode == 12 {
            return Ok(response.len() + 1);
        }
        if self.mode == 13 {
            response[0] = 0;
            return Ok(1);
        }
        let payload: &[u8] = if self.mode == 11 { &[1] } else { &[] };
        wire::encode(
            wire::Header {
                opcode: if self.mode == 9 {
                    wire::OP_PING
                } else {
                    wire::OP_STATUS
                },
                request_id: header.request_id + u64::from(self.mode == 8),
                flags: u32::from(self.mode == 10),
                status: if self.mode == 15 {
                    11
                } else if self.mode == 16 {
                    -5
                } else if busy {
                    wire::STATUS_MEMORY_ADMISSION_BUSY
                } else {
                    0
                },
                payload_len: payload.len() as u32,
            },
            payload,
            response,
        )
        .map_err(|_| 99)
    }
}

fn invoke(
    replies: &Replies,
    wait: impl FnMut(&Object<u32>) -> Result<(), u8>,
) -> Result<Option<Object<u32>>, Error<u8, u8>> {
    let client = Client::new(replies);
    let source = Object {
        handle: 7,
        rights: mnu_abi::HANDLE_RIGHT_ALL,
    };
    match replies.opcode {
        wire::OP_OPEN_AT => client
            .open_at_with_wait(
                if replies.source {
                    OpenAtBase::Directory(source)
                } else {
                    OpenAtBase::ProcessRoot
                },
                wire::OPEN_READ | wire::OPEN_WRITE | wire::OPEN_CREATE | wire::OPEN_EXCLUSIVE,
                0o600,
                "file",
                wait,
            )
            .map(Some),
        wire::OP_FTRUNCATE => client.ftruncate_with_wait(source, 5000, wait).map(|_| None),
        _ => client
            .truncate_at_with_wait(
                if replies.source {
                    StatAtBase::Directory(source)
                } else {
                    StatAtBase::ProcessCwd
                },
                "file",
                5000,
                wait,
            )
            .map(|_| None),
    }
}

#[test]
fn validated_positions_are_reattached_in_order_and_closed_exactly_once() {
    for opcode in [wire::OP_OPEN_AT, wire::OP_FTRUNCATE, wire::OP_TRUNCATE_AT] {
        for source in [true, false] {
            if opcode == wire::OP_FTRUNCATE && !source {
                continue;
            }
            let replies = Replies::new(opcode, 0, source);
            let waits = Cell::new(0);
            let result = invoke(&replies, |ticket| {
                assert_eq!(
                    *ticket,
                    Object {
                        handle: 90 + waits.get(),
                        rights: TICKET
                    }
                );
                waits.set(waits.get() + 1);
                Ok(())
            })
            .unwrap();
            assert_eq!(replies.calls.get(), 3);
            assert_eq!(waits.get(), 2);
            assert_eq!(*replies.closed.borrow(), [90, 91]);
            assert_eq!(
                result.map(|object| object.handle),
                (opcode == wire::OP_OPEN_AT).then_some(200)
            );
            let payloads = replies.payloads.borrow();
            assert!(payloads.windows(2).all(|pair| pair[0] == pair[1]));
            match opcode {
                wire::OP_OPEN_AT => {
                    let input = wire::decode_open_at(&payloads[0]).unwrap();
                    assert_eq!(input.path, "file");
                    assert_eq!(input.mode, 0o600);
                }
                wire::OP_FTRUNCATE => assert_eq!(wire::decode_file_length(&payloads[0]), Ok(5000)),
                _ => assert_eq!(wire::decode_truncate_at(&payloads[0]).unwrap().length, 5000),
            }
        }
    }
}

#[test]
fn malformed_and_uncertain_responses_never_wait_or_repeat() {
    for opcode in [wire::OP_OPEN_AT, wire::OP_FTRUNCATE, wire::OP_TRUNCATE_AT] {
        for mode in 1..=16 {
            let replies = Replies::new(opcode, mode, true);
            let result = invoke(&replies, |_| -> Result<(), u8> {
                panic!("no replay guarantee")
            });
            assert!(matches!(result, Err(Error::Operation(_))));
            assert_eq!(replies.calls.get(), 1);
            let closed = replies.closed.borrow();
            assert!(!closed.contains(&7));
            assert_eq!(
                *closed,
                match mode {
                    1 | 3 | 4 | 7 => vec![],
                    14 => vec![90, 91],
                    _ => vec![90],
                }
            );
        }
    }
}

#[test]
fn interruption_and_rust_unwinding_cancel_the_latest_position() {
    let replies = Replies::new(wire::OP_FTRUNCATE, 0, true);
    let calls = Cell::new(0);
    assert_eq!(
        invoke(&replies, |_| {
            calls.set(calls.get() + 1);
            if calls.get() == 2 { Err(4) } else { Ok(()) }
        }),
        Err(Error::Wait(4))
    );
    assert_eq!(replies.calls.get(), 2);
    assert_eq!(*replies.closed.borrow(), [90, 91]);
    let replies = Replies::new(wire::OP_FTRUNCATE, 0, true);
    let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        invoke(&replies, |_| -> Result<(), u8> { panic!("caller unwinds") })
    }));
    assert!(panic.is_err());
    assert_eq!(*replies.closed.borrow(), [90]);
}

#[test]
fn insufficient_source_rights_are_rejected_without_rpc() {
    let replies = Replies::new(wire::OP_FTRUNCATE, 0, true);
    let client = Client::new(&replies);
    let source = Object {
        handle: 7,
        rights: mnu_abi::HANDLE_RIGHT_READ | mnu_abi::HANDLE_RIGHT_TRANSFER,
    };
    let result =
        client.ftruncate_with_wait(source, 5000, |_| -> Result<(), u8> { panic!("no wait") });
    assert_eq!(result, Err(Error::Operation(ClientError::Remote(-13))));
    assert_eq!(replies.calls.get(), 0);
    assert!(replies.closed.borrow().is_empty());
}
