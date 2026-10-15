use mochios_posix_client::{
    file_admission::{Error, retry},
    Client, ClientError, ObjectHandleAttachment, ObjectHandles, ObjectTransport, OpenAtBase,
    StatAtBase, Transport,
};
use mochios_posix_protocol as wire;
use std::cell::{Cell, RefCell};

#[test]
fn only_pre_mutation_busy_is_replayed_and_wait_can_abort() {
    let calls = Cell::new(0);
    let waits = Cell::new(0);
    let result = retry(
        || {
            calls.set(calls.get() + 1);
            if calls.get() <= 3 {
                Err(ClientError::<u8>::Remote(
                    wire::STATUS_MEMORY_ADMISSION_BUSY,
                ))
            } else {
                Ok(42)
            }
        },
        || {
            waits.set(waits.get() + 1);
            Ok::<_, u8>(())
        },
    );
    assert_eq!(result, Ok(42));
    assert_eq!((calls.get(), waits.get()), (4, 3));
    for error in [
        ClientError::Remote(-11),
        ClientError::Remote(-5),
        ClientError::Remote(wire::STATUS_FILE_SIZE_LIMIT),
        ClientError::Transport(7),
        ClientError::MismatchedResponse,
        ClientError::ResponseTooLarge,
    ] {
        let result = retry(
            || Err::<(), _>(error),
            || -> Result<(), u8> { panic!("not replayable") },
        );
        assert_eq!(result, Err(Error::Operation(error)));
    }
    assert_eq!(
        retry(
            || Err::<(), _>(ClientError::<u8>::Remote(
                wire::STATUS_MEMORY_ADMISSION_BUSY
            )),
            || Err(4u8)
        ),
        Err(Error::Wait(4))
    );
}

struct Replies {
    mode: u8,
    calls: Cell<usize>,
    closed: RefCell<Vec<u32>>,
}
impl Transport for &Replies {
    type Error = u8;
    fn call(&self, _: &[u8], _: &mut [u8]) -> Result<usize, u8> {
        panic!("objects required")
    }
}
impl ObjectTransport for &Replies {
    type Handle = u32;
    fn close_received_handle(&self, handle: u32) {
        self.closed.borrow_mut().push(handle);
    }
    fn call_with_handles(
        &self,
        input: &[u8],
        output: &mut [u8],
        handles: &mut ObjectHandles<u32>,
    ) -> Result<usize, u8> {
        let (request, _) = wire::decode(input).unwrap();
        assert_eq!(handles.len(), 1);
        assert_eq!(
            handles.get(0),
            Some(ObjectHandleAttachment {
                handle: 7,
                rights: if request.opcode == wire::OP_FTRUNCATE {
                    mnu_abi::HANDLE_RIGHT_WRITE | mnu_abi::HANDLE_RIGHT_TRANSFER
                } else {
                    mnu_abi::HANDLE_RIGHT_ALL
                }
            })
        );
        handles.clear();
        let attempt = self.calls.get();
        self.calls.set(attempt + 1);
        let busy = self.mode != 0 || attempt == 0;
        if self.mode == 2 || (!busy && request.opcode == wire::OP_OPEN_AT) {
            handles
                .push(ObjectHandleAttachment {
                    handle: 90,
                    rights: 1,
                })
                .unwrap();
        }
        let payload: &[u8] = if self.mode == 1 { b"unexpected" } else { &[] };
        wire::encode(
            wire::Header {
                opcode: if self.mode == 3 {
                    wire::OP_PING
                } else {
                    wire::OP_STATUS
                },
                request_id: request.request_id + u64::from(self.mode == 4),
                status: if busy {
                    wire::STATUS_MEMORY_ADMISSION_BUSY
                } else {
                    0
                },
                payload_len: payload.len() as u32,
                flags: u32::from(self.mode == 5),
                ..Default::default()
            },
            payload,
            output,
        )
        .map_err(|_| 99)
    }
}

#[test]
fn real_client_rebuilds_borrowed_attachments_and_rejects_malformed_retry_replies() {
    for opcode in [wire::OP_OPEN_AT, wire::OP_FTRUNCATE, wire::OP_TRUNCATE_AT] {
        for mode in 0..=5 {
            let replies = Replies {
                mode,
                calls: Cell::new(0),
                closed: RefCell::new(vec![]),
            };
            let client = Client::new(&replies);
            let source = ObjectHandleAttachment {
                handle: 7,
                rights: mnu_abi::HANDLE_RIGHT_ALL,
            };
            let waits = Cell::new(0);
            let result = retry(
                || match opcode {
                    wire::OP_OPEN_AT => client
                        .open_at(
                            OpenAtBase::Directory(source),
                            wire::OPEN_WRITE | wire::OPEN_TRUNCATE,
                            0,
                            "file",
                        )
                        .map(|opened| {
                            assert_eq!(opened.handle, 90);
                        }),
                    wire::OP_FTRUNCATE => client.ftruncate(source, 5000),
                    _ => client.truncate_at(StatAtBase::Directory(source), "file", 5000),
                },
                || {
                    waits.set(waits.get() + 1);
                    Ok::<_, u8>(())
                },
            );
            if mode == 0 {
                assert_eq!(result, Ok(()));
                assert_eq!((replies.calls.get(), waits.get()), (2, 1));
            } else {
                assert_eq!(
                    result,
                    Err(Error::Operation(ClientError::MismatchedResponse))
                );
                assert_eq!((replies.calls.get(), waits.get()), (1, 0));
            }
            assert_eq!(
                *replies.closed.borrow(),
                if mode == 2 { vec![90] } else { vec![] }
            );
        }
    }
}

#[test]
fn other_operations_cannot_request_metadata_replay() {
    let replies = Replies {
        mode: 0,
        calls: Cell::new(0),
        closed: RefCell::new(vec![]),
    };
    let client = Client::new(&replies);
    assert_eq!(
        client.fsync(ObjectHandleAttachment {
            handle: 7,
            rights: mnu_abi::HANDLE_RIGHT_ALL,
        }),
        Err(ClientError::MismatchedResponse)
    );
    assert_eq!(replies.calls.get(), 1);
}

#[test]
fn filesystem_retry_guarantee_requires_well_formed_object_free_reply() {
    use mochios_filesystem_protocol as fs;
    use posix_service::filesystem_transport::metadata_status;
    let response = fs::Header {
        opcode: fs::OP_STATUS,
        request_id: 7,
        status: -fs::ERROR_MEMORY_ADMISSION_BUSY,
        ..Default::default()
    };
    for success_objects in [0, 1] {
        assert_eq!(
            metadata_status(response, 7, &[], 0, success_objects),
            Err(response.status)
        );
        assert_eq!(
            metadata_status(response, 8, &[], 0, success_objects),
            Err(-5)
        );
        assert_eq!(
            metadata_status(response, 7, b"bad", 0, success_objects),
            Err(-5)
        );
        assert_eq!(
            metadata_status(response, 7, &[], 1, success_objects),
            Err(-5)
        );
        assert_eq!(
            metadata_status(
                fs::Header {
                    opcode: fs::OP_OPEN_AT,
                    ..response
                },
                7,
                &[],
                0,
                success_objects
            ),
            Err(-5)
        );
    }
    for status in [-11, -5, -27] {
        assert_eq!(posix_service::mutation_filesystem_status(status), status);
        assert_eq!(posix_service::truncate_filesystem_status(status), status);
    }
    assert_eq!(
        posix_service::mutation_filesystem_status(response.status),
        wire::STATUS_MEMORY_ADMISSION_BUSY
    );
    assert_eq!(
        posix_service::truncate_filesystem_status(response.status),
        wire::STATUS_MEMORY_ADMISSION_BUSY
    );
}
