use mochios_filesystem_protocol::volume_status::{RESPONSE_LEN, Status};
use mochios_posix_client::{
    Client, ObjectHandleAttachment, ObjectHandles, ObjectTransport, StatAtBase, Transport,
};
use mochios_posix_protocol as wire;
use std::{cell::RefCell, rc::Rc};
struct Reply {
    flags: u32,
    status: i32,
    length: usize,
    extra: bool,
    closed: Vec<u32>,
}
#[derive(Clone)]
struct Mock(Rc<RefCell<Reply>>);
impl Transport for Mock {
    type Error = ();
    fn call(&self, _: &[u8], _: &mut [u8]) -> Result<usize, ()> {
        panic!("Handle transport")
    }
}
impl ObjectTransport for Mock {
    type Handle = u32;
    fn close_received_handle(&self, h: u32) {
        self.0.borrow_mut().closed.push(h);
    }
    fn call_with_handles(
        &self,
        request: &[u8],
        output: &mut [u8],
        handles: &mut ObjectHandles<u32>,
    ) -> Result<usize, ()> {
        let (header, payload) = wire::decode(request).unwrap();
        assert_eq!(handles.len(), 1);
        assert_eq!(handles.get(0).unwrap().handle, 19);
        if header.opcode == wire::OP_VOLUME_STATUS_AT {
            let request = wire::decode_stat_at(payload).unwrap();
            assert_eq!(request.path, b"file\xff");
            assert_eq!(request.flags, 0);
            assert_eq!(request.base, wire::OpenBase::AttachedDirectory);
        } else {
            assert_eq!(header.opcode, wire::OP_VOLUME_STATUS_HANDLE);
            assert!(payload.is_empty());
            assert_eq!(
                handles.get(0).unwrap().rights,
                mnu_abi::HANDLE_RIGHT_TRANSFER
            );
        }
        handles.clear();
        let s = self.0.borrow();
        if s.extra {
            handles
                .push(ObjectHandleAttachment {
                    handle: 42,
                    rights: 1,
                })
                .unwrap();
        }
        let bytes = Status {
            block_bytes: 4096,
            flags: 0,
            blocks: 1 << 36,
            free_blocks: 1 << 35,
            inodes: 1024,
            free_inodes: 1000,
            filesystem_id: 7,
            name_bytes_max: 255,
        }
        .encode();
        wire::encode(
            wire::Header {
                opcode: wire::OP_STATUS,
                request_id: header.request_id,
                payload_len: s.length as u32,
                flags: s.flags,
                status: s.status,
            },
            &bytes[..s.length],
            output,
        )
        .map_err(|_| ())
    }
}
#[test]
fn path_and_fd_observations_validate_response_and_clean_unexpected_handles() {
    for (flags, status, length, extra, ok) in [
        (0, 0, RESPONSE_LEN, false, true),
        (1, 0, RESPONSE_LEN, false, false),
        (0, -13, 0, false, false),
        (0, 0, RESPONSE_LEN - 1, false, false),
        (0, 0, RESPONSE_LEN, true, false),
    ] {
        for fd in [false, true] {
            let state = Rc::new(RefCell::new(Reply {
                flags,
                status,
                length,
                extra,
                closed: vec![],
            }));
            let client = Client::new(Mock(state.clone()));
            let object = ObjectHandleAttachment {
                handle: 19,
                rights: mnu_abi::HANDLE_RIGHT_TRANSFER | mnu_abi::HANDLE_RIGHT_READ,
            };
            let result = if fd {
                client.volume_status(object)
            } else {
                client.volume_status_at(StatAtBase::Directory(object), b"file\xff")
            };
            assert_eq!(result.is_ok(), ok);
            assert_eq!(state.borrow().closed, if extra { vec![42] } else { vec![] });
        }
    }
}
