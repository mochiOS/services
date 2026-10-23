use super::*;
use mnu_abi::{
    HANDLE_RIGHT_CONTROL as C, HANDLE_RIGHT_TRANSFER as T, IpcObjectHandle, IpcObjectHandles,
};
use protocol::device_attributes::{self as wire, Request};
use std::cell::Cell;

thread_local! {
    static CLOCK_ERROR: Cell<i32> = const { Cell::new(0) };
    static CLOCK_CALLS: Cell<u32> = const { Cell::new(0) };
}
fn clock() -> Result<ext4plus::inode::InodeTimestamp, i32> {
    CLOCK_CALLS.set(CLOCK_CALLS.get() + 1);
    let error = CLOCK_ERROR.get();
    if error > 0 {
        return Err(error);
    }
    Ok(ext4plus::inode::InodeTimestamp {
        seconds: -7,
        nanoseconds: if error < 0 { 1_000_000_000 } else { 321 },
    })
}
fn setup(fixture: &Fixture) -> (FilesystemService, u64) {
    let mut service =
        FilesystemService::new_with_clock(fixture.volume("conditional-attributes"), clock);
    service.mount_devices(b"/dev", Default::default()).unwrap();
    let parent = device_open(
        &mut service,
        b"/dev",
        protocol::OPEN_AT_READ | protocol::OPEN_AT_DIRECTORY,
        PathAnchors::default(),
    )
    .unwrap();
    CLOCK_ERROR.set(0);
    CLOCK_CALLS.set(0);
    (service, parent)
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
            mode: 0o700,
            uid: 0,
            gid: 0,
            name,
        },
    )
    .unwrap();
    protocol::decode_node_status(&reply.payload).unwrap()
}
fn attached() -> IpcObjectHandles {
    let mut result = IpcObjectHandles::default();
    result.delivery_flags = mnu_abi::IPC_DELIVERY_ENDPOINT_HANDLE;
    result.count = 1;
    result.handles[0] = IpcObjectHandle {
        handle: 29,
        reserved: 0,
        rights: C | T,
    };
    result
}
fn packet(node: protocol::NodeStatus, name: &[u8]) -> (protocol::Header, Vec<u8>) {
    let mut bytes = vec![0; wire::HEADER_LEN + name.len()];
    let length = wire::encode(
        Request {
            mode: 0o620,
            uid: 501,
            gid: 20,
            identity: protocol::device_removal::Request {
                device: node.device,
                node_id: node.node_id,
                name,
            },
        },
        &mut bytes,
    )
    .unwrap();
    (
        protocol::Header {
            opcode: protocol::OP_DEVICE_NODE_SET_ATTRIBUTES_IF_SAME,
            request_id: 81,
            length: length as u32,
            ..Default::default()
        },
        bytes,
    )
}
fn update(
    service: &mut FilesystemService,
    parent: u64,
    node: protocol::NodeStatus,
    name: &[u8],
) -> Result<protocol::NodeStatus, i32> {
    let (header, bytes) = packet(node, name);
    assert!(filesystem_service::device_namespace_ipc::requested(header));
    filesystem_service::device_namespace_ipc::handle(
        service,
        header,
        &bytes,
        &attached(),
        |handle| {
            assert_eq!(handle, 29);
            Ok(parent)
        },
    )
    .map(|reply| {
        assert_eq!(reply.header.request_id, 81);
        protocol::decode_node_status(&reply.payload).unwrap()
    })
}
fn status(service: &FilesystemService, open: u64) -> protocol::NodeStatus {
    protocol::decode_node_status(
        &service
            .stat_handle(protocol::Header::default(), open)
            .unwrap()
            .payload,
    )
    .unwrap()
}

#[test]
fn conditional_configuration_updates_one_retained_inode_but_never_its_replacement() {
    let fixture = Fixture::new();
    let (mut service, parent) = setup(&fixture);
    let original = create(
        &mut service,
        parent,
        b"0",
        protocol::device_namespace::KIND_NULL,
    );
    let retained = device_open(
        &mut service,
        b"/dev/0",
        protocol::OPEN_AT_READ | protocol::OPEN_AT_WRITE,
        PathAnchors::default(),
    )
    .unwrap();
    for wrong in [
        protocol::NodeStatus {
            device: original.device + 1,
            ..original
        },
        protocol::NodeStatus {
            node_id: original.node_id + 1,
            ..original
        },
    ] {
        assert_eq!(update(&mut service, parent, wrong, b"0"), Err(116));
        assert_eq!(status(&service, retained), original);
    }
    assert_eq!(CLOCK_CALLS.get(), 0);
    let changed = update(&mut service, parent, original, b"0").unwrap();
    assert_eq!(
        (changed.mode & 0o7777, changed.uid, changed.gid),
        (0o620, 501, 20)
    );
    assert_eq!(
        (
            changed.device,
            changed.node_id,
            changed.special_device,
            changed.kind,
            changed.link_count
        ),
        (
            original.device,
            original.node_id,
            original.special_device,
            original.kind,
            original.link_count
        )
    );
    assert_eq!(
        (changed.change_time_seconds, changed.change_time_nanoseconds),
        (-7, 321)
    );
    assert_eq!(
        (
            changed.access_time_seconds,
            changed.modification_time_seconds
        ),
        (
            original.access_time_seconds,
            original.modification_time_seconds
        )
    );
    assert_eq!(CLOCK_CALLS.get(), 1);
    assert_eq!(status(&service, retained), changed);
    configure_received_device(
        &mut service,
        parent,
        protocol::OP_DEVICE_NODE_REMOVE,
        protocol::device_namespace::Request {
            kind: 0,
            mode: 0,
            uid: 0,
            gid: 0,
            name: b"0",
        },
    )
    .unwrap();
    assert_eq!(update(&mut service, parent, original, b"0"), Err(2));
    let replacement = create(
        &mut service,
        parent,
        b"0",
        protocol::device_namespace::KIND_NULL,
    );
    assert_ne!(replacement.node_id, original.node_id);
    assert_eq!(update(&mut service, parent, original, b"0"), Err(116));
    let current = device_open(
        &mut service,
        b"/dev/0",
        protocol::OPEN_AT_READ,
        PathAnchors::default(),
    )
    .unwrap();
    assert_eq!(status(&service, current), replacement);
    let old = status(&service, retained);
    assert_eq!(
        (old.uid, old.mode & 0o7777, old.link_count),
        (501, 0o620, 0)
    );
    service.provider_write(retained, b"retained").unwrap();
    for open in [current, retained, parent] {
        service.provider_close(open).unwrap();
    }
}

#[test]
fn clock_failures_and_parent_or_mount_mismatch_leave_every_attribute_unchanged() {
    let fixture = Fixture::new();
    let (mut service, parent) = setup(&fixture);
    let original = create(
        &mut service,
        parent,
        b"0",
        protocol::device_namespace::KIND_NULL,
    );
    let retained = device_open(
        &mut service,
        b"/dev/0",
        protocol::OPEN_AT_READ,
        PathAnchors::default(),
    )
    .unwrap();
    for (error, expected) in [(5, 5), (-1, 22)] {
        CLOCK_ERROR.set(error);
        assert_eq!(update(&mut service, parent, original, b"0"), Err(expected));
        assert_eq!(status(&service, retained), original);
    }
    CLOCK_ERROR.set(0);
    let directory = create(
        &mut service,
        parent,
        b"scope",
        protocol::device_namespace::KIND_DIRECTORY,
    );
    let child_parent = device_open(
        &mut service,
        b"/dev/scope",
        protocol::OPEN_AT_READ | protocol::OPEN_AT_DIRECTORY,
        PathAnchors::default(),
    )
    .unwrap();
    assert_eq!(update(&mut service, child_parent, original, b"0"), Err(2));
    let child = create(
        &mut service,
        child_parent,
        b"0",
        protocol::device_namespace::KIND_NULL,
    );
    assert_eq!(update(&mut service, child_parent, original, b"0"), Err(116));
    assert_eq!(update(&mut service, parent, child, b"0"), Err(116));
    service
        .mount_devices(b"/dev/scope", Default::default())
        .unwrap();
    assert_eq!(update(&mut service, parent, directory, b"scope"), Err(16));
    assert_eq!(status(&service, retained), original);
    for open in [child_parent, retained, parent] {
        service.provider_close(open).unwrap();
    }
}

#[test]
fn caller_selected_identity_and_uid_zero_do_not_replace_received_parent_authority() {
    let fixture = Fixture::new();
    let (mut service, parent) = setup(&fixture);
    let node = create(
        &mut service,
        parent,
        b"0",
        protocol::device_namespace::KIND_NULL,
    );
    let (header, mut bytes) = packet(node, b"0");
    bytes[4..8].fill(0); // A requested uid 0 is configuration, never identity.
    let base = attached();
    for rights in [0, C, T, mnu_abi::HANDLE_RIGHT_READ | T] {
        let mut objects = base;
        objects.handles[0].rights = rights;
        assert_eq!(
            filesystem_service::device_namespace_ipc::handle(
                &mut service,
                header,
                &bytes,
                &objects,
                |_| panic!("no parent authority")
            )
            .err(),
            Some(13)
        );
    }
    for mut bad in [header; 8].into_iter().enumerate() {
        match bad.0 {
            0 => bad.1.mount_id = 1,
            1 => bad.1.node_id = node.node_id,
            2 => bad.1.open_id = parent,
            3 => bad.1.offset = 1,
            4 => bad.1.flags = 1,
            5 => bad.1.status = 1,
            6 => bad.1.mode = 0o777,
            _ => bad.1.length += 1,
        }
        assert_eq!(
            filesystem_service::device_namespace_ipc::handle(
                &mut service,
                bad.1,
                &bytes,
                &base,
                |_| panic!("invalid envelope")
            )
            .err(),
            Some(22)
        );
    }
    for which in 0..5 {
        let mut objects = base;
        match which {
            0 => objects.delivery_flags = 0,
            1 => objects.count = 0,
            2 => objects.count = 2,
            3 => objects.handles[0].handle = 0,
            _ => objects.handles[0].reserved = 1,
        }
        assert!(
            filesystem_service::device_namespace_ipc::handle(
                &mut service,
                header,
                &bytes,
                &objects,
                |_| panic!("invalid attachment")
            )
            .is_err()
        );
    }
    assert_eq!(
        filesystem_service::device_namespace_ipc::handle(
            &mut service,
            header,
            &bytes,
            &base,
            |_| Err(9)
        )
        .err(),
        Some(9)
    );
    let mut malformed = bytes.clone();
    malformed[12] = 1;
    assert_eq!(
        filesystem_service::device_namespace_ipc::handle(
            &mut service,
            header,
            &malformed,
            &base,
            |_| panic!("invalid payload")
        )
        .err(),
        Some(22)
    );
    assert_eq!(CLOCK_CALLS.get(), 0);
    let file = device_open(
        &mut service,
        b"/dev/0",
        protocol::OPEN_AT_READ,
        PathAnchors::default(),
    )
    .unwrap();
    assert_eq!(status(&service, file), node);
    for open in [file, parent] {
        service.provider_close(open).unwrap();
    }
}

#[test]
fn external_devices_use_updated_permissions_without_replacing_factory_or_old_metadata() {
    use super::external_namespace::factory::{Calls, definition};
    let fixture = Fixture::new();
    let (mut service, parent) = setup(&fixture);
    let calls = Arc::new(Mutex::new(Calls::default()));
    let mut bytes = vec![0; protocol::device_registration::HEADER_LEN + 1];
    protocol::device_registration::encode(
        protocol::device_registration::Request {
            mode: 0o600,
            uid: 0,
            gid: 0,
            special_device: 71,
            name: b"0",
        },
        &mut bytes,
    )
    .unwrap();
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
    let response = filesystem_service::device_registration_ipc::handle(
        &mut service,
        protocol::Header {
            opcode: protocol::OP_DEVICE_NODE_REGISTER_EXTERNAL,
            length: bytes.len() as u32,
            ..Default::default()
        },
        &bytes,
        &mut objects,
        |_| Ok(parent),
        |_, _| Ok(definition(&calls, 71).factory),
    )
    .unwrap();
    let original = protocol::decode_node_status(&response.payload).unwrap();
    let retained = device_open(
        &mut service,
        b"/dev/0",
        protocol::OPEN_AT_READ,
        PathAnchors::default(),
    )
    .unwrap();
    let open = |service: &mut FilesystemService, uid, gid, flags| {
        let mut credentials = root_credentials();
        credentials.effective_uid = uid;
        credentials.effective_gid = gid;
        service
            .open_at(
                protocol::Header {
                    flags,
                    ..Default::default()
                },
                b"/dev/0",
                PathAnchors::default(),
                credentials,
            )
            .map(|response| response.header.open_id)
    };
    assert_eq!(open(&mut service, 501, 20, protocol::OPEN_AT_READ), Err(13));
    let name = posix_service::terminal_publication::Name {
        component: b"0".to_vec(),
        device: original.device,
        node_id: original.node_id,
    };
    let mut changed = None;
    posix_service::terminal_publication::grant_with(&name, 501, 20, |payload| {
        let reply = filesystem_service::device_namespace_ipc::handle(
            &mut service,
            protocol::Header {
                opcode: protocol::OP_DEVICE_NODE_SET_ATTRIBUTES_IF_SAME,
                length: payload.len() as u32,
                ..Default::default()
            },
            payload,
            &attached(),
            |_| Ok(parent),
        )
        .map_err(|error| -error)?;
        let status = protocol::decode_node_status(&reply.payload).unwrap();
        changed = Some(status);
        Ok(status)
    })
    .unwrap();
    let changed = changed.unwrap();
    assert_eq!(status(&service, retained), changed);
    assert_eq!(changed.special_device, 71);
    assert!(service.external_open(retained).unwrap().is_some());
    let owner = open(
        &mut service,
        501,
        20,
        protocol::OPEN_AT_READ | protocol::OPEN_AT_WRITE,
    )
    .unwrap();
    let group = open(&mut service, 999, 20, protocol::OPEN_AT_WRITE).unwrap();
    assert_eq!(open(&mut service, 999, 20, protocol::OPEN_AT_READ), Err(13));
    assert_eq!(
        open(&mut service, 999, 999, protocol::OPEN_AT_WRITE),
        Err(13)
    );
    assert_eq!(calls.lock().unwrap().dropped, 0);
    for object in [retained, owner, group, parent] {
        service.provider_close(object).unwrap();
    }
    // Configuration changes never drop or replace the registered factory.
    assert_eq!(calls.lock().unwrap().dropped, 0);
}

#[test]
fn conditional_attributes_wire_is_bounded_versioned_and_rejects_noncanonical_fields() {
    let request = Request {
        mode: 0o7777,
        uid: u32::MAX,
        gid: u32::MAX,
        identity: protocol::device_removal::Request {
            device: u64::MAX,
            node_id: u64::MAX,
            name: b"0",
        },
    };
    let mut bytes = vec![0; wire::HEADER_LEN + 256];
    let length = wire::encode(request, &mut bytes).unwrap();
    assert_eq!(wire::decode(&bytes[..length]).unwrap(), request);
    for size in 0..length {
        assert!(wire::decode(&bytes[..size]).is_err());
    }
    assert!(wire::decode(&bytes[..length + 1]).is_err());
    for index in (12..16).chain(18..24).chain(42..48) {
        let mut malformed = bytes[..length].to_vec();
        malformed[index] = 1;
        assert!(wire::decode(&malformed).is_err());
    }
    for index in [0, 16] {
        let mut malformed = bytes[..length].to_vec();
        malformed[index] = 2;
        assert_eq!(
            wire::decode(&malformed),
            Err(protocol::ProtocolError::UnsupportedVersion)
        );
    }
    assert!(
        wire::encode(
            Request {
                mode: 0o10000,
                ..request
            },
            &mut bytes
        )
        .is_err()
    );
    for name in [&b""[..], b".", b"..", b"a/b", b"a\0b", &[b'x'; 256]] {
        assert!(
            wire::encode(
                Request {
                    identity: protocol::device_removal::Request {
                        name,
                        ..request.identity
                    },
                    ..request
                },
                &mut bytes
            )
            .is_err()
        );
    }
    assert!(
        wire::encode(
            Request {
                identity: protocol::device_removal::Request {
                    node_id: 0,
                    ..request.identity
                },
                ..request
            },
            &mut bytes
        )
        .is_err()
    );
    let name = [b'x'; 255];
    let request = Request {
        identity: protocol::device_removal::Request {
            name: &name,
            ..request.identity
        },
        ..request
    };
    let length = wire::encode(request, &mut bytes).unwrap();
    assert_eq!(wire::decode(&bytes[..length]).unwrap(), request);
}
