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
        let reply = self.0.lock().unwrap();
        for attachment in &reply.attachments {
            handles.push(*attachment).unwrap();
        }
        if reply.transport_error {
            return Err(());
        }
        Ok(protocol::encode(
            protocol::Header {
                opcode: protocol::OP_STATUS,
                request_id: header.request_id + u64::from(reply.mismatch),
                status: reply.status,
                ..Default::default()
            },
            &[],
            output,
        )
        .unwrap())
    }
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
