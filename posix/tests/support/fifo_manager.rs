use mnu_abi::{IpcObjectHandle, IpcObjectHandles, provider};
use mochios_filesystem_protocol as wire;
use posix_service::{
    fifo::Access,
    fifo_inode::METADATA_RIGHTS,
    fifo_manager::{AdmittedInode, FilesystemScope, Manager, Opened},
    filesystem_reference::{Backend, Reference},
};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

#[derive(Debug)]
struct Pin {
    pub id: u32,
    pub closed: Arc<AtomicUsize>,
}
impl Backend for Pin {
    fn duplicate(&self, _: u64) -> Result<u32, i32> {
        Ok(self.id + 1000)
    }
}
impl Drop for Pin {
    fn drop(&mut self) {
        self.closed.fetch_add(1, Ordering::Relaxed);
    }
}

pub fn admit(
    scope: FilesystemScope,
    inode: u32,
    access: Access,
    closed: &Arc<AtomicUsize>,
) -> AdmittedInode {
    let node_id = (1 << 32) | u64::from(inode);
    let mut payload = vec![0; wire::NODE_STATUS_LEN];
    wire::encode_node_status(
        wire::NodeStatus {
            node_id,
            device: 1,
            kind: wire::NODE_TYPE_FIFO,
            mode: 0o600,
            ..Default::default()
        },
        &mut payload,
    )
    .unwrap();
    let header = wire::Header {
        opcode: wire::OP_STATUS,
        request_id: 1,
        flags: wire::OPEN_REPLY_FIFO,
        node_id,
        open_id: 7,
        length: payload.len() as u32,
        ..Default::default()
    };
    let mut objects = IpcObjectHandles::default();
    objects.count = 1;
    objects.handles[0] = IpcObjectHandle {
        handle: inode + 70,
        rights: METADATA_RIGHTS,
        reserved: 0,
    };
    let reference = scope
        .admit(header, 1, &payload, &mut objects, access, |object| {
            Reference::new(
                Box::new(Pin {
                    id: object.handle,
                    closed: closed.clone(),
                }),
                object.rights,
            )
        })
        .unwrap();
    assert_eq!(objects.count, 0);
    assert_eq!(objects.handles[0].handle, 0);
    reference
}

pub fn open(manager: &mut Manager, admitted: AdmittedInode) -> Opened {
    manager
        .open(
            admitted,
            true,
            |id, _, _| Ok(id as u32 + 10000),
            |_| panic!("no committed object to close"),
        )
        .unwrap()
}

pub fn frame(opcode: u16, id: u64, bytes: &[u8], length: usize) -> Vec<u8> {
    let mut request = vec![0; provider::REQUEST_HEADER_LEN + bytes.len()];
    let length = provider::RequestHeader {
        opcode,
        object_id: id,
        argument: 0,
        basis: 0,
        length: length as u32,
        data_length: bytes.len() as u32,
    }
    .encode(bytes, &mut request)
    .unwrap();
    request.truncate(length);
    request
}

pub fn call(
    manager: &mut Manager,
    opcode: u16,
    id: u64,
    bytes: &[u8],
    length: usize,
) -> (i64, Vec<u8>) {
    let request = frame(opcode, id, bytes, length);
    let mut response = vec![0; provider::RESPONSE_HEADER_LEN + provider::MAX_DATA_LEN];
    let dispatch = manager
        .handle_provider_request(
            &request,
            mnu_abi::IPC_DELIVERY_NATIVE_OBJECT,
            0,
            &mut response,
        )
        .unwrap();
    let (header, payload) =
        provider::ResponseHeader::decode(&response[..dispatch.reply_length.unwrap()]).unwrap();
    assert_eq!(header.opcode, opcode);
    assert_eq!(header.object_id, id);
    (header.status, payload.to_vec())
}

pub fn release(manager: &mut Manager, id: u64) {
    let request = frame(provider::OP_RELEASE, id, &[], 0);
    let dispatch = manager
        .handle_provider_request(&request, mnu_abi::IPC_DELIVERY_NATIVE_OBJECT, 0, &mut [])
        .unwrap();
    assert_eq!(dispatch.reply_length, None);
}
