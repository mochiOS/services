use super::external_namespace::factory::{Calls, definition};
use super::{
    FilesystemService, Fixture, PathAnchors, configure_received_device, device_open,
    root_credentials,
};
use filesystem_service::device_registration_ipc::handle;
use mnu_abi::{
    HANDLE_RIGHT_CONTROL as C, HANDLE_RIGHT_DUPLICATE as D, HANDLE_RIGHT_SEND as S,
    HANDLE_RIGHT_TRANSFER as T, IpcObjectHandle, IpcObjectHandles,
};
use mochios_filesystem_protocol as wire;
use std::sync::{Arc, Mutex};
fn packet(name: &[u8]) -> (wire::Header, Vec<u8>) {
    let mut bytes = vec![0; wire::device_registration::HEADER_LEN + name.len()];
    let length = wire::device_registration::encode(
        wire::device_registration::Request {
            mode: 0o620,
            uid: 501,
            gid: 20,
            special_device: 0x1234_5678_9abc_def0,
            name,
        },
        &mut bytes,
    )
    .unwrap();
    (
        wire::Header {
            opcode: wire::OP_DEVICE_NODE_REGISTER_EXTERNAL,
            request_id: 77,
            length: length as u32,
            ..Default::default()
        },
        bytes,
    )
}
fn attachments() -> IpcObjectHandles {
    let mut a = IpcObjectHandles::default();
    a.delivery_flags = mnu_abi::IPC_DELIVERY_ENDPOINT_HANDLE;
    a.count = 3;
    a.handles[0] = IpcObjectHandle {
        handle: 29,
        reserved: 0,
        rights: C | T,
    };
    a.handles[1] = IpcObjectHandle {
        handle: 31,
        reserved: 0,
        rights: S,
    };
    a.handles[2] = IpcObjectHandle {
        handle: 33,
        reserved: 0,
        rights: D | T,
    };
    a
}
fn service(fixture: &Fixture, name: &str) -> (FilesystemService, u64) {
    let mut service = FilesystemService::new(fixture.volume(name));
    service
        .mount_devices(
            b"/managed",
            filesystem_service::devfs::DeviceFilesystem::default(),
        )
        .unwrap();
    let parent = device_open(
        &mut service,
        b"/managed",
        wire::OPEN_AT_READ | wire::OPEN_AT_DIRECTORY,
        PathAnchors::default(),
    )
    .unwrap();
    (service, parent)
}
fn register(
    service: &mut FilesystemService,
    parent: u64,
    header: wire::Header,
    bytes: &[u8],
    a: &mut IpcObjectHandles,
    calls: &Arc<Mutex<Calls>>,
) -> Result<filesystem_service::service::Response, i32> {
    handle(
        service,
        header,
        bytes,
        a,
        |raw| {
            assert_eq!(raw, 29);
            Ok(parent)
        },
        |endpoint, factory| {
            assert_eq!(endpoint, attachments().handles[1]);
            assert_eq!(factory, attachments().handles[2]);
            Ok(definition(calls, 0).factory)
        },
    )
}

#[test]
fn received_registration_publishes_real_vfs_metadata_and_transfers_capability_ownership() {
    let fixture = Fixture::new();
    let (mut service, parent) = service(&fixture, "received-external-registration");
    let calls = Arc::new(Mutex::new(Calls::default()));
    let (header, bytes) = packet(b"device");
    let mut a = attachments();
    let response = register(&mut service, parent, header, &bytes, &mut a, &calls).unwrap();
    assert_eq!(a.handles[0], attachments().handles[0]);
    assert_eq!(a.handles[1].handle, 0);
    assert_eq!(a.handles[2].handle, 0);
    let status = wire::decode_node_status(&response.payload).unwrap();
    assert_eq!(
        (status.kind, status.mode, status.uid, status.gid),
        (wire::NODE_TYPE_SPECIAL, 0o020620, 501, 20)
    );
    assert_eq!(status.special_device, 0x1234_5678_9abc_def0);
    assert_eq!(response.header.request_id, 77);
    let stat = service
        .stat_at(
            wire::Header::default(),
            b"/managed/device",
            PathAnchors::default(),
            root_credentials(),
        )
        .unwrap();
    assert_eq!(wire::decode_node_status(&stat.payload).unwrap(), status);
    assert!(calls.lock().unwrap().requests.is_empty());
    assert_eq!(calls.lock().unwrap().dropped, 0);
    configure_received_device(
        &mut service,
        parent,
        wire::OP_DEVICE_NODE_SET_ATTRIBUTES,
        wire::device_namespace::Request {
            kind: 0,
            mode: 0o600,
            uid: 999,
            gid: 888,
            name: b"device",
        },
    )
    .unwrap();
    let stat = service
        .stat_at(
            wire::Header::default(),
            b"/managed/device",
            PathAnchors::default(),
            root_credentials(),
        )
        .unwrap();
    let updated = wire::decode_node_status(&stat.payload).unwrap();
    assert_eq!(
        (updated.mode, updated.uid, updated.gid),
        (0o020600, 999, 888)
    );
    assert_eq!(updated.special_device, status.special_device);
    configure_received_device(
        &mut service,
        parent,
        wire::OP_DEVICE_NODE_REMOVE,
        wire::device_namespace::Request {
            kind: 0,
            mode: 0,
            uid: 0,
            gid: 0,
            name: b"device",
        },
    )
    .unwrap();
    assert_eq!(calls.lock().unwrap().dropped, 1);
    let mut a = attachments();
    let new = register(&mut service, parent, header, &bytes, &mut a, &calls).unwrap();
    assert_ne!(
        wire::decode_node_status(&new.payload).unwrap().node_id,
        status.node_id
    );
    drop(service);
    assert_eq!(calls.lock().unwrap().dropped, 2);
}

#[test]
fn malformed_or_unprivileged_registration_never_identifies_a_parent_or_adopts_capabilities() {
    let fixture = Fixture::new();
    let (mut service, _) = service(&fixture, "external-registration-denied");
    let (header, bytes) = packet(b"bad");
    let mut cases = Vec::new();
    for flags in [0, 1, 3, u32::MAX] {
        let mut a = attachments();
        a.delivery_flags = flags;
        cases.push((header, bytes.clone(), a));
    }
    for count in [0, 1, 2, 4, u32::MAX] {
        let mut a = attachments();
        a.count = count;
        cases.push((header, bytes.clone(), a));
    }
    for index in 0..3 {
        let mut a = attachments();
        a.handles[index].handle = 0;
        cases.push((header, bytes.clone(), a));
        let mut a = attachments();
        a.handles[index].reserved = 1;
        cases.push((header, bytes.clone(), a));
        let mut a = attachments();
        a.handles[index].rights = 0;
        cases.push((header, bytes.clone(), a));
    }
    for (index, rights) in [
        (0, T),
        (0, C),
        (1, S | T),
        (1, C),
        (2, D),
        (2, T | C),
        (2, T | S),
    ] {
        let mut a = attachments();
        a.handles[index].rights = rights;
        cases.push((header, bytes.clone(), a));
    }
    for (first, second) in [(0, 1), (0, 2), (1, 2)] {
        let mut a = attachments();
        a.handles[second].handle = a.handles[first].handle;
        cases.push((header, bytes.clone(), a));
    }
    for bad in [
        wire::Header {
            mount_id: 1,
            ..header
        },
        wire::Header {
            node_id: 1,
            ..header
        },
        wire::Header {
            open_id: 1,
            ..header
        },
        wire::Header {
            offset: 1,
            ..header
        },
        wire::Header { flags: 1, ..header },
        wire::Header {
            status: 1,
            ..header
        },
        wire::Header { mode: 1, ..header },
        wire::Header {
            length: 0,
            ..header
        },
        wire::Header {
            opcode: wire::OP_DEVICE_NODE_CREATE,
            ..header
        },
    ] {
        cases.push((bad, bytes.clone(), attachments()));
    }
    let mut uid_root = bytes.clone();
    uid_root[8..12].copy_from_slice(&0u32.to_le_bytes());
    let mut a = attachments();
    a.handles[0].rights = T;
    cases.push((header, uid_root, a));
    for at in [0, 2, 26] {
        let mut bad = bytes.clone();
        bad[at] ^= 0x80;
        cases.push((header, bad, attachments()));
    }
    cases.push((header, bytes[..bytes.len() - 1].to_vec(), attachments()));
    for (header, bytes, mut a) in cases {
        let original = a;
        assert!(
            handle(
                &mut service,
                header,
                &bytes,
                &mut a,
                |_| panic!("invalid registration"),
                |_, _| panic!("invalid registration")
            )
            .is_err()
        );
        assert_eq!(a, original);
    }
    assert!(matches!(
        service.stat_at(
            wire::Header::default(),
            b"/managed/bad",
            PathAnchors::default(),
            root_credentials()
        ),
        Err(2)
    ));
}

#[test]
fn identify_adoption_and_namespace_failures_have_unambiguous_reference_ownership() {
    let fixture = Fixture::new();
    let (mut service, parent) = service(&fixture, "external-registration-failure");
    let (header, bytes) = packet(b"device");
    let mut a = attachments();
    let original = a;
    assert!(matches!(
        handle(
            &mut service,
            header,
            &bytes,
            &mut a,
            |_| Err(9),
            |_, _| panic!("foreign parent")
        ),
        Err(9)
    ));
    assert_eq!(a, original);
    let mut a = attachments();
    let adopted = std::cell::Cell::new(false);
    assert!(matches!(
        handle(
            &mut service,
            header,
            &bytes,
            &mut a,
            |_| Ok(parent),
            |endpoint, factory| {
                assert_eq!((endpoint.handle, factory.handle), (31, 33));
                adopted.set(true);
                Err(12)
            }
        ),
        Err(12)
    ));
    assert!(adopted.get());
    assert_eq!(
        (
            a.handles[0].handle,
            a.handles[1].handle,
            a.handles[2].handle
        ),
        (29, 0, 0)
    );
    assert!(matches!(
        service.stat_at(
            wire::Header::default(),
            b"/managed/device",
            PathAnchors::default(),
            root_credentials()
        ),
        Err(2)
    ));
    let calls = Arc::new(Mutex::new(Calls::default()));
    let mut a = attachments();
    assert!(matches!(
        register(&mut service, u64::MAX, header, &bytes, &mut a, &calls),
        Err(9)
    ));
    assert_eq!(calls.lock().unwrap().dropped, 1);
    let disk = device_open(
        &mut service,
        b"/",
        wire::OPEN_AT_READ | wire::OPEN_AT_DIRECTORY,
        PathAnchors::default(),
    )
    .unwrap();
    let mut a = attachments();
    assert!(matches!(
        register(&mut service, disk, header, &bytes, &mut a, &calls),
        Err(95)
    ));
    assert_eq!(calls.lock().unwrap().dropped, 2);
    let null = device_open(
        &mut service,
        b"/managed/null",
        wire::OPEN_AT_READ,
        PathAnchors::default(),
    )
    .unwrap();
    let mut a = attachments();
    assert!(matches!(
        register(&mut service, null, header, &bytes, &mut a, &calls),
        Err(20)
    ));
    assert_eq!(calls.lock().unwrap().dropped, 3);
    configure_received_device(
        &mut service,
        parent,
        wire::OP_DEVICE_NODE_CREATE,
        wire::device_namespace::Request {
            kind: wire::device_namespace::KIND_DIRECTORY,
            mode: 0o755,
            uid: 0,
            gid: 0,
            name: b"covered",
        },
    )
    .unwrap();
    service
        .mount_devices(
            b"/managed/covered",
            filesystem_service::devfs::DeviceFilesystem::default(),
        )
        .unwrap();
    let (covered_header, covered_bytes) = packet(b"covered");
    let mut a = attachments();
    assert!(matches!(
        register(
            &mut service,
            parent,
            covered_header,
            &covered_bytes,
            &mut a,
            &calls
        ),
        Err(17)
    ));
    assert_eq!(calls.lock().unwrap().dropped, 4);
    configure_received_device(
        &mut service,
        parent,
        wire::OP_DEVICE_NODE_CREATE,
        wire::device_namespace::Request {
            kind: wire::device_namespace::KIND_DIRECTORY,
            mode: 0o755,
            uid: 0,
            gid: 0,
            name: b"removed",
        },
    )
    .unwrap();
    let removed = device_open(
        &mut service,
        b"/managed/removed",
        wire::OPEN_AT_READ | wire::OPEN_AT_DIRECTORY,
        PathAnchors::default(),
    )
    .unwrap();
    configure_received_device(
        &mut service,
        parent,
        wire::OP_DEVICE_NODE_REMOVE,
        wire::device_namespace::Request {
            kind: 0,
            mode: 0,
            uid: 0,
            gid: 0,
            name: b"removed",
        },
    )
    .unwrap();
    let mut a = attachments();
    assert!(matches!(
        register(&mut service, removed, header, &bytes, &mut a, &calls),
        Err(2)
    ));
    assert_eq!(calls.lock().unwrap().dropped, 5);
}
