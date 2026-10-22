use super::*;
use mnu_abi::{
    HANDLE_RIGHT_CONTROL as C, HANDLE_RIGHT_TRANSFER as T, IPC_DELIVERY_ENDPOINT_HANDLE,
    IpcObjectHandle, IpcObjectHandles,
};
use protocol::device_removal::{self as wire, Request};

fn packet(identity: protocol::NodeStatus, name: &[u8]) -> (protocol::Header, Vec<u8>) {
    let mut payload = vec![0; wire::HEADER_LEN + name.len()];
    let length = wire::encode(
        Request {
            device: identity.device,
            node_id: identity.node_id,
            name,
        },
        &mut payload,
    )
    .unwrap();
    (
        protocol::Header {
            opcode: protocol::OP_DEVICE_NODE_REMOVE_IF_SAME,
            request_id: 87,
            length: length as u32,
            ..Default::default()
        },
        payload,
    )
}

fn attached() -> IpcObjectHandles {
    let mut objects = IpcObjectHandles::default();
    objects.delivery_flags = IPC_DELIVERY_ENDPOINT_HANDLE;
    objects.count = 1;
    objects.handles[0] = IpcObjectHandle {
        handle: 29,
        reserved: 0,
        rights: C | T,
    };
    objects
}

fn remove(
    service: &mut FilesystemService,
    parent: u64,
    identity: protocol::NodeStatus,
    name: &[u8],
) -> Result<protocol::NodeStatus, i32> {
    let (header, payload) = packet(identity, name);
    assert!(filesystem_service::device_namespace_ipc::requested(header));
    filesystem_service::device_namespace_ipc::handle(service, header, &payload, &attached(), |h| {
        assert_eq!(h, 29);
        Ok(parent)
    })
    .map(|reply| protocol::decode_node_status(&reply.payload).unwrap())
}

fn create(
    service: &mut FilesystemService,
    parent: u64,
    name: &[u8],
    kind: u16,
) -> protocol::NodeStatus {
    let reply = configure_received_device(
        service,
        parent,
        protocol::OP_DEVICE_NODE_CREATE,
        protocol::device_namespace::Request {
            kind,
            mode: 0o755,
            uid: 0,
            gid: 0,
            name,
        },
    )
    .unwrap();
    protocol::decode_node_status(&reply.payload).unwrap()
}

fn setup(fixture: &Fixture, label: &str) -> (FilesystemService, u64) {
    let mut service = FilesystemService::new(fixture.volume(label));
    service.mount_devices(b"/dev", Default::default()).unwrap();
    let parent = device_open(
        &mut service,
        b"/dev",
        protocol::OPEN_AT_READ | protocol::OPEN_AT_DIRECTORY,
        PathAnchors::default(),
    )
    .unwrap();
    (service, parent)
}

#[test]
fn conditional_removal_preserves_replacements_and_retained_open_descriptions() {
    let fixture = Fixture::new();
    let (mut service, parent) = setup(&fixture, "conditional-device-removal");
    let old = create(
        &mut service,
        parent,
        b"0",
        protocol::device_namespace::KIND_NULL,
    );
    let open = device_open(
        &mut service,
        b"/dev/0",
        protocol::OPEN_AT_READ | protocol::OPEN_AT_WRITE,
        PathAnchors::default(),
    )
    .unwrap();
    for wrong in [
        protocol::NodeStatus {
            device: old.device + 1,
            ..old
        },
        protocol::NodeStatus {
            node_id: old.node_id + 1,
            ..old
        },
    ] {
        assert_eq!(remove(&mut service, parent, wrong, b"0"), Err(116));
    }
    let removed = remove(&mut service, parent, old, b"0").unwrap();
    assert_eq!(
        (removed.device, removed.node_id, removed.link_count),
        (old.device, old.node_id, 0)
    );
    assert_eq!(remove(&mut service, parent, old, b"0"), Err(2));
    let replacement = create(
        &mut service,
        parent,
        b"0",
        protocol::device_namespace::KIND_NULL,
    );
    assert_ne!(replacement.node_id, old.node_id);
    assert_eq!(remove(&mut service, parent, old, b"0"), Err(116));
    let current = device_open(
        &mut service,
        b"/dev/0",
        protocol::OPEN_AT_READ,
        PathAnchors::default(),
    )
    .unwrap();
    let status = service
        .stat_handle(protocol::Header::default(), current)
        .unwrap();
    assert_eq!(
        protocol::decode_node_status(&status.payload)
            .unwrap()
            .node_id,
        replacement.node_id
    );
    // Unpublication retires the name, not already-open resources.
    assert_eq!(service.provider_write(open, b"still open").unwrap(), 10);
    assert!(service.provider_read(open, 3).unwrap().is_empty());
    let status = service
        .stat_handle(protocol::Header::default(), open)
        .unwrap();
    let retained = protocol::decode_node_status(&status.payload).unwrap();
    assert_eq!((retained.node_id, retained.link_count), (old.node_id, 0));
    remove(&mut service, parent, replacement, b"0").unwrap();
    service.provider_close(open).unwrap();
    service.provider_close(current).unwrap();
    service.provider_close(parent).unwrap();
}

#[test]
fn conditional_removal_keeps_parent_scope_and_mount_nonempty_guards() {
    let fixture = Fixture::new();
    let (mut service, parent) = setup(&fixture, "conditional-device-scope");
    let directory = create(
        &mut service,
        parent,
        b"group",
        protocol::device_namespace::KIND_DIRECTORY,
    );
    let child_parent = device_open(
        &mut service,
        b"/dev/group",
        protocol::OPEN_AT_READ | protocol::OPEN_AT_DIRECTORY,
        PathAnchors::default(),
    )
    .unwrap();
    let leaf = create(
        &mut service,
        child_parent,
        b"0",
        protocol::device_namespace::KIND_NULL,
    );
    assert_eq!(remove(&mut service, parent, leaf, b"0"), Err(2));
    assert_eq!(remove(&mut service, parent, directory, b"group"), Err(39));
    service
        .mount_devices(b"/dev/covered", Default::default())
        .unwrap();
    let covered = device_open(
        &mut service,
        b"/dev/covered",
        protocol::OPEN_AT_READ | protocol::OPEN_AT_DIRECTORY,
        PathAnchors::default(),
    )
    .unwrap();
    let reply = service
        .stat_handle(protocol::Header::default(), covered)
        .unwrap();
    let mount = protocol::decode_node_status(&reply.payload).unwrap();
    assert_eq!(remove(&mut service, parent, mount, b"covered"), Err(16));
    remove(&mut service, child_parent, leaf, b"0").unwrap();
    remove(&mut service, parent, directory, b"group").unwrap();
    for open in [covered, child_parent, parent] {
        service.provider_close(open).unwrap();
    }
}

#[test]
fn conditional_external_unpublication_preserves_the_admitted_factory_lifetime() {
    use super::external_namespace::factory::{Calls, definition};
    let fixture = Fixture::new();
    let (mut service, parent) = setup(&fixture, "conditional-external-lifetime");
    let calls = Arc::new(Mutex::new(Calls::default()));
    let mut payload = vec![0; protocol::device_registration::HEADER_LEN + 1];
    protocol::device_registration::encode(
        protocol::device_registration::Request {
            mode: 0o600,
            uid: 0,
            gid: 0,
            special_device: 17,
            name: b"0",
        },
        &mut payload,
    )
    .unwrap();
    let header = protocol::Header {
        opcode: protocol::OP_DEVICE_NODE_REGISTER_EXTERNAL,
        length: payload.len() as u32,
        ..Default::default()
    };
    let mut objects = attached();
    objects.count = 3;
    objects.handles[1] = IpcObjectHandle {
        handle: 31,
        reserved: 0,
        rights: mnu_abi::HANDLE_RIGHT_SEND,
    };
    objects.handles[2] = IpcObjectHandle {
        handle: 33,
        reserved: 0,
        rights: T,
    };
    // Simulate native identification/adoption only; execute the actual FS
    // registration, namespace comparison and retained-open ownership paths.
    let reply = filesystem_service::device_registration_ipc::handle(
        &mut service,
        header,
        &payload,
        &mut objects,
        |_| Ok(parent),
        |_, _| Ok(definition(&calls, 17).factory),
    )
    .unwrap();
    let original = protocol::decode_node_status(&reply.payload).unwrap();
    let open = device_open(
        &mut service,
        b"/dev/0",
        protocol::OPEN_AT_READ,
        PathAnchors::default(),
    )
    .unwrap();
    assert!(service.external_open(open).unwrap().is_some());
    remove(&mut service, parent, original, b"0").unwrap();
    assert_eq!(calls.lock().unwrap().dropped, 0);
    let replacement = create(
        &mut service,
        parent,
        b"0",
        protocol::device_namespace::KIND_NULL,
    );
    assert_eq!(remove(&mut service, parent, original, b"0"), Err(116));
    let retained = service
        .stat_handle(protocol::Header::default(), open)
        .unwrap();
    let retained = protocol::decode_node_status(&retained.payload).unwrap();
    assert_eq!(
        (retained.node_id, retained.link_count),
        (original.node_id, 0)
    );
    service.provider_close(open).unwrap();
    assert_eq!(calls.lock().unwrap().dropped, 1);
    remove(&mut service, parent, replacement, b"0").unwrap();
    service.provider_close(parent).unwrap();
    assert_eq!(calls.lock().unwrap().dropped, 1);
}

#[test]
fn known_identity_never_replaces_native_parent_authority() {
    let fixture = Fixture::new();
    let (mut service, parent) = setup(&fixture, "conditional-device-authority");
    let node = create(
        &mut service,
        parent,
        b"0",
        protocol::device_namespace::KIND_NULL,
    );
    let (header, payload) = packet(node, b"0");
    let base = attached();
    for rights in [0, T, C, mnu_abi::HANDLE_RIGHT_READ | T] {
        let mut denied = base;
        denied.handles[0].rights = rights;
        let result = filesystem_service::device_namespace_ipc::handle(
            &mut service,
            header,
            &payload,
            &denied,
            |_| panic!("reject before identifying"),
        );
        assert_eq!(result.err(), Some(13));
    }
    for denied in [
        IpcObjectHandles { count: 0, ..base },
        IpcObjectHandles { count: 2, ..base },
        IpcObjectHandles {
            delivery_flags: 0,
            ..base
        },
    ] {
        assert!(
            filesystem_service::device_namespace_ipc::handle(
                &mut service,
                header,
                &payload,
                &denied,
                |_| panic!("reject before identifying")
            )
            .is_err()
        );
    }
    for mut denied in [header; 2].into_iter().enumerate() {
        if denied.0 == 0 {
            denied.1.node_id = node.node_id;
        } else {
            denied.1.open_id = parent;
        }
        assert_eq!(
            filesystem_service::device_namespace_ipc::handle(
                &mut service,
                denied.1,
                &payload,
                &base,
                |_| panic!("inline IDs confer no authority")
            )
            .err(),
            Some(22)
        );
    }
    assert_eq!(
        filesystem_service::device_namespace_ipc::handle(
            &mut service,
            header,
            &payload,
            &base,
            |_| Err(9)
        )
        .err(),
        Some(9)
    );
    // Failed authorization has left the real node in place.
    remove(&mut service, parent, node, b"0").unwrap();
    service.provider_close(parent).unwrap();
}

#[test]
fn conditional_removal_wire_is_versioned_bounded_and_canonical() {
    let request = Request {
        device: u64::MAX,
        node_id: u64::MAX,
        name: b"0",
    };
    let mut bytes = vec![0; wire::HEADER_LEN + 255];
    let length = wire::encode(request, &mut bytes).unwrap();
    assert_eq!(wire::decode(&bytes[..length]).unwrap(), request);
    for size in 0..length {
        assert!(wire::decode(&bytes[..size]).is_err());
    }
    assert!(wire::decode(&bytes[..length + 1]).is_err());
    for index in (2..8).chain(26..32) {
        let mut malformed = bytes[..length].to_vec();
        malformed[index] = 1;
        assert!(wire::decode(&malformed).is_err());
    }
    let mut malformed = bytes[..length].to_vec();
    malformed[0] = 2;
    assert_eq!(
        wire::decode(&malformed),
        Err(protocol::ProtocolError::UnsupportedVersion)
    );
    for name in [&b""[..], b".", b"..", b"a/b", b"a\0b", &[b'x'; 256]] {
        assert!(wire::encode(Request { name, ..request }, &mut bytes).is_err());
    }
    assert!(
        wire::encode(
            Request {
                node_id: 0,
                ..request
            },
            &mut bytes
        )
        .is_err()
    );
    let length = wire::encode(
        Request {
            name: &[b'x'; 255],
            ..request
        },
        &mut bytes,
    )
    .unwrap();
    assert_eq!(wire::decode(&bytes[..length]).unwrap().name.len(), 255);
}
