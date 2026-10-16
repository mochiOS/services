use mochios_posix_client::{
    Client, ClientError, ObjectHandleAttachment, ObjectHandles, ObjectTransport, Transport,
};
use mochios_posix_protocol::{self as protocol, shared_memory as wire};
use std::sync::{Arc, Mutex};

#[derive(Default)]
struct Reply {
    status: i32,
    mismatch: bool,
    attachments: Vec<ObjectHandleAttachment<u32>>,
    transport_error: bool,
    response_shape: u8,
    calls: usize,
}
#[derive(Clone)]
struct Mock(Arc<Mutex<Reply>>);
impl Transport for Mock {
    type Error = ();
    fn call(&self, _: &[u8], _: &mut [u8]) -> Result<usize, ()> {
        panic!("shared memory requires Handle-aware IPC")
    }
}
impl ObjectTransport for Mock {
    type Handle = u32;

    fn close_received_handle(&self, _: u32) {
        panic!("unexpected owned reply Handle in this fixture");
    }
    fn call_with_handles(
        &self,
        request: &[u8],
        output: &mut [u8],
        handles: &mut ObjectHandles<u32>,
    ) -> Result<usize, ()> {
        let (header, payload) = protocol::decode(request).unwrap();
        assert_eq!(header.flags, 0);
        if header.opcode == protocol::OP_SHARED_MEMORY_BACKING {
            assert_eq!(payload.len(), 4);
            let writable = u32::from_le_bytes(payload.try_into().unwrap()) != 0;
            assert_eq!(handles.len(), 1);
            let outgoing = handles.get(0).unwrap();
            assert_eq!(outgoing.handle, 99);
            assert_eq!(
                outgoing.rights,
                mnu_abi::HANDLE_RIGHT_READ
                    | mnu_abi::HANDLE_RIGHT_CONTROL
                    | mnu_abi::HANDLE_RIGHT_TRANSFER
                    | if writable {
                        mnu_abi::HANDLE_RIGHT_WRITE
                    } else {
                        0
                    }
            );
        } else if header.opcode == protocol::OP_SHARED_MEMORY_OPEN {
            assert!(handles.is_empty());
            wire::decode_open(payload).unwrap();
        } else {
            assert!(handles.is_empty());
            assert_eq!(header.opcode, protocol::OP_SHARED_MEMORY_UNLINK);
            wire::decode_name(payload).unwrap();
        }
        handles.clear();
        let mut reply = self.0.lock().unwrap();
        reply.calls += 1;
        for attachment in &reply.attachments {
            handles.push(*attachment).unwrap();
        }
        if reply.transport_error {
            return Err(());
        }
        match reply.response_shape {
            1 => return Ok(output.len() + 1),
            2 => {
                output[0] = 0;
                return Ok(1);
            }
            _ => {}
        }
        let payload = if reply.response_shape == 3 {
            &[1u8][..]
        } else {
            &[]
        };
        Ok(protocol::encode(
            protocol::Header {
                opcode: protocol::OP_STATUS,
                request_id: header.request_id + u64::from(reply.mismatch),
                status: reply.status,
                payload_len: payload.len() as u32,
                ..Default::default()
            },
            payload,
            output,
        )
        .unwrap())
    }
}

#[test]
fn shared_memory_replies_never_close_invalid_duplicate_or_borrowed_handles() {
    for operation in 0..3 {
        for writable in [false, true] {
            let rights = if operation == 1 {
                wire::mapping_rights(writable)
            } else {
                wire::descriptor_rights(writable)
            };
            for mode in 0..7 {
                for incoming in [
                    vec![],
                    vec![7],
                    vec![0],
                    vec![99],
                    vec![7, 7],
                    vec![7, 99, 7, 0],
                    vec![7, 8, 8, 0],
                ] {
                    let state = Arc::new(Mutex::new(Reply {
                        attachments: incoming
                            .iter()
                            .map(|handle| ObjectHandleAttachment {
                                handle: *handle,
                                rights,
                            })
                            .collect(),
                        transport_error: mode == 1,
                        mismatch: mode == 2,
                        status: if mode == 3 { -13 } else { 0 },
                        response_shape: match mode {
                            4 => 1,
                            5 => 2,
                            6 => 3,
                            _ => 0,
                        },
                        ..Default::default()
                    }));
                    let client = Client::new(Mock(state.clone()));
                    let mut closed = vec![];
                    let result = match operation {
                        0 => client
                            .open_shared_memory(
                                wire::Open {
                                    options: wire::CREATE
                                        | wire::EXCLUSIVE
                                        | if writable { wire::READ_WRITE } else { 0 },
                                    mode: 0o600,
                                    name: b"/buffer",
                                },
                                |handle| closed.push(handle),
                            )
                            .map(Some),
                        1 => client
                            .shared_memory_backing(
                                ObjectHandleAttachment {
                                    handle: 99,
                                    rights: wire::descriptor_rights(writable),
                                },
                                writable,
                                |handle| closed.push(handle),
                            )
                            .map(Some),
                        _ => client
                            .unlink_shared_memory(b"/buffer", |handle| closed.push(handle))
                            .map(|_| None),
                    };
                    let accepted = mode == 0
                        && if operation == 2 {
                            incoming.is_empty()
                        } else {
                            incoming.len() == 1
                                && incoming[0] != 0
                                && (operation != 1 || incoming[0] != 99)
                        };
                    match mode {
                        0 if accepted => assert_eq!(
                            result,
                            Ok(if operation == 2 {
                                None
                            } else {
                                Some(ObjectHandleAttachment {
                                    handle: incoming[0],
                                    rights,
                                })
                            })
                        ),
                        0 | 2 => assert_eq!(result, Err(ClientError::MismatchedResponse)),
                        1 => assert_eq!(result, Err(ClientError::Transport(()))),
                        3 => assert_eq!(result, Err(ClientError::Remote(-13))),
                        4 | 6 => assert_eq!(result, Err(ClientError::ResponseTooLarge)),
                        5 => assert!(matches!(result, Err(ClientError::Protocol(_)))),
                        _ => unreachable!(),
                    }
                    let mut expected = vec![];
                    if !accepted {
                        for handle in incoming {
                            if handle != 0
                                && (operation != 1 || handle != 99)
                                && !expected.contains(&handle)
                            {
                                expected.push(handle);
                            }
                        }
                    }
                    assert_eq!(
                        closed, expected,
                        "operation={operation} mode={mode} writable={writable}"
                    );
                    assert_eq!(state.lock().unwrap().calls, 1);
                }
            }
        }
    }
}

#[test]
fn invalid_mapping_descriptor_is_rejected_before_ipc_or_cleanup() {
    let state = Arc::new(Mutex::new(Reply::default()));
    let client = Client::new(Mock(state.clone()));
    assert_eq!(
        client.shared_memory_backing(
            ObjectHandleAttachment {
                handle: 0,
                rights: wire::descriptor_rights(true)
            },
            false,
            |_| panic!("borrowed or invalid Handle")
        ),
        Err(ClientError::Remote(-13))
    );
    assert_eq!(state.lock().unwrap().calls, 0);
}

#[test]
fn mapping_borrows_descriptor_and_closes_only_owned_failed_replies() {
    let state = Arc::new(Mutex::new(Reply::default()));
    let client = Client::new(Mock(state.clone()));
    let descriptor = ObjectHandleAttachment {
        handle: 99,
        rights: wire::descriptor_rights(true),
    };
    let mut closed = Vec::new();
    for writable in [false, true] {
        let backing = ObjectHandleAttachment {
            handle: 7,
            rights: wire::mapping_rights(writable),
        };
        *state.lock().unwrap() = Reply {
            attachments: vec![backing],
            ..Default::default()
        };
        assert_eq!(
            client.shared_memory_backing(descriptor, writable, |handle| closed.push(handle)),
            Ok(backing)
        );
        assert!(closed.is_empty());
        for case in 0..6 {
            let mut reply = state.lock().unwrap();
            *reply = Reply {
                attachments: vec![backing],
                ..Default::default()
            };
            match case {
                0 => reply.status = -13,
                1 => reply.mismatch = true,
                2 => reply.transport_error = true,
                3 => reply.attachments[0].rights |= mnu_abi::HANDLE_RIGHT_CONTROL,
                4 => reply.attachments.push(ObjectHandleAttachment {
                    handle: 8,
                    ..backing
                }),
                _ => {
                    reply.transport_error = true;
                    reply.attachments.clear();
                }
            }
            drop(reply);
            closed.clear();
            assert!(
                client
                    .shared_memory_backing(descriptor, writable, |handle| closed.push(handle))
                    .is_err()
            );
            assert_eq!(
                closed,
                match case {
                    4 => vec![7, 8],
                    5 => vec![],
                    _ => vec![7],
                }
            );
            assert!(!closed.contains(&99));
        }
        closed.clear();
    }
    let readonly = ObjectHandleAttachment {
        rights: wire::descriptor_rights(false),
        ..descriptor
    };
    assert_eq!(
        client.shared_memory_backing(readonly, true, |handle| closed.push(handle)),
        Err(ClientError::Remote(-13))
    );
    assert!(closed.is_empty());
    let mut borrowed = ObjectHandles::new();
    borrowed.push(descriptor).unwrap();
    assert_eq!(
        client.request_with_handles(
            protocol::OP_SHARED_MEMORY_BACKING,
            0,
            &vec![0; protocol::MAX_CONTROL_PAYLOAD_LEN + 1],
            &mut [],
            &mut borrowed
        ),
        Err(ClientError::RequestTooLarge)
    );
    assert!(borrowed.is_empty());
}

#[test]
fn newlib_shm_flags_and_inherited_descriptor_kind_are_canonical() {
    use mochios_posix_client::shared_memory::newlib_open_options;
    assert_eq!(newlib_open_options(0), Some(0));
    assert_eq!(newlib_open_options(2), Some(wire::READ_WRITE));
    assert_eq!(
        newlib_open_options(2 | 0x200 | 0x800 | 0x40000),
        Some(wire::READ_WRITE | wire::CREATE | wire::EXCLUSIVE)
    );
    assert_eq!(
        newlib_open_options(2 | 0x400),
        Some(wire::READ_WRITE | wire::TRUNCATE)
    );
    for flags in [1, 3, -1, 0x800, 0x400, 0x8, 0x4000, 0x200000] {
        assert_eq!(newlib_open_options(flags), None);
    }
    let metadata = protocol::InheritedFdMetadata {
        kind: protocol::INHERITED_FD_KIND_SHARED_MEMORY,
        open_flags: 2,
        descriptor_flags: 0,
    };
    assert_eq!(
        protocol::decode_inherited_fd_metadata(
            protocol::encode_inherited_fd_metadata(metadata).unwrap()
        ),
        Some(metadata)
    );
    assert_eq!(
        protocol::inherited_fd_kind_requires_handle(metadata.kind),
        Some(true)
    );
    let runtime =
        include_str!("../../../user/crates/newlib-runtime/src/shared_memory_namespace.rs");
    assert!(runtime.contains("(flags & 3) | O_CLOEXEC"));
    assert!(runtime.contains("reserve_from(0, limit)"));
    assert!(runtime.contains("commit_reservation"));
    let backing = include_str!("../../../user/crates/newlib-runtime/src/mapping_backing.rs");
    let reply = include_str!("../../../user/crates/newlib-runtime/src/object_reply.rs");
    assert!(reply.contains("impl Drop for Reply"));
    assert!(backing.contains("io_resources::with("));
    assert!(reply.contains("&mut self.native as *mut syscall::IpcObjectHandles"));
}
#[test]
fn valid_response_transfers_one_owned_reference_and_all_failed_shapes_close_attachments() {
    let state = Arc::new(Mutex::new(Reply::default()));
    let client = Client::new(Mock(state.clone()));
    let reader = ObjectHandleAttachment {
        handle: 7,
        rights: mochios_posix_client::shared_memory::rights(false),
    };
    state.lock().unwrap().attachments.push(reader);
    let request = wire::Open {
        options: 0,
        mode: 0,
        name: b"/buffer",
    };
    let mut closed = Vec::new();
    assert_eq!(
        client.open_shared_memory(request, |handle| closed.push(handle)),
        Ok(reader)
    );
    assert!(closed.is_empty());
    for case in 0..5 {
        let mut reply = state.lock().unwrap();
        *reply = Reply {
            attachments: vec![reader],
            ..Default::default()
        };
        match case {
            0 => reply.status = -13,
            1 => reply.mismatch = true,
            2 => reply.transport_error = true,
            3 => reply.attachments[0].rights |= mnu_abi::HANDLE_RIGHT_MAP,
            _ => reply.attachments.push(ObjectHandleAttachment {
                handle: 8,
                ..reader
            }),
        }
        drop(reply);
        closed.clear();
        assert!(
            client
                .open_shared_memory(request, |handle| closed.push(handle))
                .is_err()
        );
        assert_eq!(closed, if case == 4 { vec![7, 8] } else { vec![7] });
    }
    *state.lock().unwrap() = Reply::default();
    assert_eq!(
        client.unlink_shared_memory(b"/buffer", |handle| closed.push(handle)),
        Ok(())
    );
    state.lock().unwrap().attachments.push(reader);
    closed.clear();
    assert_eq!(
        client.unlink_shared_memory(b"/buffer", |handle| closed.push(handle)),
        Err(ClientError::MismatchedResponse)
    );
    assert_eq!(closed, vec![7]);
}
