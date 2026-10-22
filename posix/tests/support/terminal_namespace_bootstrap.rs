use super::*;
use posix_service::{
    OpenedObject,
    terminal_namespace::{Backend, RIGHTS, prepare},
};
use std::collections::BTreeMap;

// Native identities and delivery are simulated here; the filesystem's real
// namespace operations and configuration authorization run unchanged.
struct Client<'a> {
    service: &'a mut FilesystemService,
    handles: BTreeMap<u32, u64>,
    next: u32,
}
impl Backend for Client<'_> {
    fn open_directory(
        &mut self,
        path: &[u8],
        parent: Option<OpenedObject<u32>>,
    ) -> Result<OpenedObject<u32>, i32> {
        let base = parent.map(|p| {
            assert_eq!(p.rights & RIGHTS, RIGHTS);
            self.handles[&p.handle]
        });
        let flags = protocol::OPEN_AT_READ
            | protocol::OPEN_AT_DIRECTORY
            | protocol::OPEN_AT_NOFOLLOW
            | if base.is_some() {
                protocol::OPEN_AT_BASE_ATTACHED
            } else {
                0
            };
        let response = self
            .service
            .open_at(
                protocol::Header {
                    flags,
                    ..Default::default()
                },
                path,
                PathAnchors {
                    root_open_id: None,
                    base_open_id: base,
                },
                root_credentials(),
            )
            .map_err(|error| -error)?;
        let handle = self.next;
        self.next += 1;
        self.handles.insert(handle, response.header.open_id);
        Ok(OpenedObject {
            handle,
            rights: filesystem_service::handle_access::open_rights(flags),
        })
    }
    fn create_directory(&mut self, parent: OpenedObject<u32>, name: &[u8]) -> Result<(), i32> {
        let (header, payload) = device_configuration(
            protocol::OP_DEVICE_NODE_CREATE,
            protocol::device_namespace::Request {
                kind: protocol::device_namespace::KIND_DIRECTORY,
                mode: 0o755,
                uid: 0,
                gid: 0,
                name,
            },
        );
        let open = self.handles[&parent.handle];
        let mut received = mnu_abi::IpcObjectHandles::default();
        received.delivery_flags = mnu_abi::IPC_DELIVERY_ENDPOINT_HANDLE;
        received.count = 1;
        received.handles[0] = mnu_abi::IpcObjectHandle {
            handle: parent.handle,
            reserved: 0,
            rights: mnu_abi::HANDLE_RIGHT_CONTROL | mnu_abi::HANDLE_RIGHT_TRANSFER,
        };
        filesystem_service::device_namespace_ipc::handle(
            self.service,
            header,
            &payload,
            &received,
            |source| {
                assert_eq!(source, parent.handle);
                Ok(open)
            },
        )
        .map(|_| ())
        .map_err(|error| -error)
    }
    fn close(&mut self, handle: u32) {
        let open = self.handles.remove(&handle).unwrap();
        self.service.provider_close(open).unwrap();
    }
}

#[test]
fn terminal_bootstrap_retains_a_real_directory_and_restarts_without_replacing_it() {
    let f = Fixture::new();
    let mut service = FilesystemService::new(f.volume("terminal-bootstrap"));
    service.mount_devices(b"/dev", Default::default()).unwrap();
    let mut client = Client {
        service: &mut service,
        handles: BTreeMap::new(),
        next: 10,
    };
    let first = prepare(&mut client).unwrap();
    assert_eq!(first.rights, RIGHTS);
    assert_eq!(client.handles.len(), 1);
    let before = client
        .service
        .stat_handle(protocol::Header::default(), client.handles[&first.handle])
        .unwrap();
    let node = protocol::decode_node_status(&before.payload).unwrap();
    assert_eq!(
        (node.kind, node.mode & 0o7777, node.uid, node.gid),
        (protocol::NODE_TYPE_DIRECTORY, 0o755, 0, 0)
    );
    let second = prepare(&mut client).unwrap();
    assert_ne!(first.handle, second.handle);
    let after = client
        .service
        .stat_handle(protocol::Header::default(), client.handles[&second.handle])
        .unwrap();
    assert_eq!(before.payload, after.payload);
    assert_eq!(client.handles.len(), 2);
    client.close(first.handle);
    client.close(second.handle);
    assert!(client.handles.is_empty());
}

#[test]
fn terminal_bootstrap_rejects_an_existing_wrong_kind_without_overwriting_it() {
    let f = Fixture::new();
    let mut service = FilesystemService::new(f.volume("terminal-bootstrap-wrong-kind"));
    service.mount_devices(b"/dev", Default::default()).unwrap();
    let parent = device_open(
        &mut service,
        b"/dev",
        protocol::OPEN_AT_READ | protocol::OPEN_AT_DIRECTORY,
        PathAnchors::default(),
    )
    .unwrap();
    configure_received_device(
        &mut service,
        parent,
        protocol::OP_DEVICE_NODE_CREATE,
        protocol::device_namespace::Request {
            kind: protocol::device_namespace::KIND_NULL,
            mode: 0o660,
            uid: 501,
            gid: 20,
            name: b"pts",
        },
    );
    service.provider_close(parent).unwrap();
    let mut client = Client {
        service: &mut service,
        handles: BTreeMap::new(),
        next: 10,
    };
    assert_eq!(prepare(&mut client).err(), Some(-20));
    assert!(client.handles.is_empty());
    let reply = client
        .service
        .stat_at(
            protocol::Header::default(),
            b"/dev/pts",
            PathAnchors::default(),
            root_credentials(),
        )
        .unwrap();
    let node = protocol::decode_node_status(&reply.payload).unwrap();
    assert_eq!(
        (node.kind, node.uid, node.gid, node.mode & 0o7777),
        (protocol::NODE_TYPE_SPECIAL, 501, 20, 0o660)
    );
}
