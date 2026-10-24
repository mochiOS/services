use mnu_abi::{IpcObjectHandle, IpcObjectHandles};
use mochios_filesystem_protocol as fs;
use posix_service::{
    fifo::Access,
    fifo_inode::METADATA_RIGHTS,
    fifo_manager::{FilesystemScope, Manager},
    fifo_open_ipc as wire,
    filesystem_reference::{Backend, Reference},
};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
#[derive(Debug)]
struct Pin(Arc<AtomicUsize>);
impl Backend for Pin {
    fn duplicate(&self, _: u64) -> Result<u32, i32> {
        Ok(99)
    }
}
impl Drop for Pin {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }
}
fn request(access: Access, nonblocking: bool) -> (Vec<u8>, IpcObjectHandles) {
    let node_id = (1 << 32) | 9;
    let mut payload = vec![0; fs::NODE_STATUS_LEN];
    fs::encode_node_status(
        fs::NodeStatus {
            device: 1,
            node_id,
            kind: fs::NODE_TYPE_FIFO,
            mode: 0o600,
            ..Default::default()
        },
        &mut payload,
    )
    .unwrap();
    let bytes = wire::encode(
        fs::Header {
            opcode: fs::OP_STATUS,
            request_id: 7,
            open_id: 8,
            node_id,
            flags: fs::OPEN_REPLY_FIFO,
            length: payload.len() as u32,
            ..Default::default()
        },
        &payload,
        access,
        nonblocking,
    )
    .unwrap();
    let mut objects = IpcObjectHandles::default();
    objects.count = 1;
    objects.delivery_flags = mnu_abi::IPC_DELIVERY_ENDPOINT_HANDLE;
    objects.handles[0] = IpcObjectHandle {
        handle: 77,
        reserved: 0,
        rights: METADATA_RIGHTS,
    };
    (bytes, objects)
}
#[test]
fn untrusted_clients_cannot_turn_metadata_into_read_or_write_authority() {
    let scope = FilesystemScope::new().unwrap();
    for access in [Access::Read, Access::Write] {
        let (bytes, mut objects) = request(access, true);
        assert_eq!(
            wire::admit_with(scope, false, &bytes, &mut objects, |_| panic!(
                "untrusted direction cannot be admitted"
            ))
            .err(),
            Some(-13)
        );
        assert_eq!(objects.count, 1);
        assert_eq!(objects.handles[0].handle, 77);
    }
    let (good, objects) = request(Access::Read, true);
    let mut cases = Vec::new();
    for index in [0, 4, 5, 6, 7] {
        let mut bytes = good.clone();
        bytes[index] = 255;
        cases.push((bytes, objects));
    }
    cases.push((good[..good.len() - 1].to_vec(), objects));
    let mut bytes = good.clone();
    bytes.push(0);
    cases.push((bytes, objects));
    for delivery in [0, mnu_abi::IPC_DELIVERY_NATIVE_OBJECT, u32::MAX] {
        let mut a = objects;
        a.delivery_flags = delivery;
        cases.push((good.clone(), a));
    }
    for count in [0, 2, u32::MAX] {
        let mut a = objects;
        a.count = count;
        cases.push((good.clone(), a));
    }
    let mut a = objects;
    a.handles[0].rights |= mnu_abi::HANDLE_RIGHT_READ;
    cases.push((good.clone(), a));
    for (bytes, mut objects) in cases {
        let count = objects.count;
        assert!(
            wire::admit_with(scope, true, &bytes, &mut objects, |_| panic!(
                "malformed admission"
            ))
            .is_err()
        );
        assert_eq!(objects.count, count);
        assert_eq!(objects.handles[0].handle, 77);
    }
}
#[test]
fn admitted_direction_and_nonblocking_policy_survive_private_handoff() {
    let scope = FilesystemScope::new().unwrap();
    let closed = Arc::new(AtomicUsize::new(0));
    let mut manager = Manager::default();
    let mut ids = Vec::new();
    for (access, nonblocking, ready) in [(Access::Read, false, false), (Access::Write, true, true)]
    {
        let (bytes, mut objects) = request(access, nonblocking);
        let (admitted, mode) = wire::admit_with(scope, true, &bytes, &mut objects, |object| {
            Reference::new(Box::new(Pin(closed.clone())), object.rights)
        })
        .unwrap();
        assert_eq!(mode, nonblocking);
        assert_eq!(objects.count, 0);
        let opened = manager
            .open(
                admitted,
                mode,
                |id, rights, options| {
                    assert_eq!(rights, wire::data_rights(access));
                    assert_eq!(
                        options,
                        if mode {
                            mnu_abi::HANDLE_OPTION_NONBLOCKING
                        } else {
                            0
                        }
                    );
                    Ok(id as u32 + 100)
                },
                |_| panic!("no failed native reference"),
            )
            .unwrap();
        assert_eq!(
            manager.readiness(opened.object_id).unwrap().open_ready,
            ready
        );
        ids.push(opened.object_id);
    }
    assert!(manager.readiness(ids[0]).unwrap().open_ready);
    let source = mnu_abi::HANDLE_RIGHT_TRANSFER;
    let opened = posix_service::pty_metadata_ipc::lookup_with(
        &fs::device_metadata::Request { rights: source }.encode(),
        &{
            let mut a = IpcObjectHandles::default();
            a.count = 1;
            a.delivery_flags = mnu_abi::IPC_DELIVERY_ENDPOINT_HANDLE;
            a.handles[0] = IpcObjectHandle {
                handle: 5,
                reserved: 0,
                rights: source,
            };
            a
        },
        |_| Ok(ids[0]),
        |id, source, requested| {
            manager
                .duplicate_metadata(id, source, requested)
                .map_err(|error| -error)
        },
    )
    .unwrap();
    assert_eq!((opened.handle, opened.rights), (99, source));
    assert!(!manager.is_empty());
    drop(manager);
    assert_eq!(closed.load(Ordering::Relaxed), 2);
}
