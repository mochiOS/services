use filesystem_service::{
    devfs::{Attributes, DeviceFilesystem, NodeKind},
    path_walk::{self, Backend, Credentials, Resolution},
};
use mnu_abi::{HANDLE_RIGHT_READ as R, HANDLE_RIGHT_WRITE as W};
use mochios_filesystem_protocol as wire;
use std::sync::{Arc, Mutex};
#[path = "support/external_factory.rs"]
mod factory;
use factory::{Calls, definition, metadata};
fn attrs(mode: u16) -> Attributes {
    Attributes {
        mode,
        uid: 1000,
        gid: 20,
    }
}
fn owner() -> Credentials<'static> {
    Credentials {
        uid: 1000,
        gid: 20,
        groups: &[],
    }
}

#[test]
fn external_nodes_use_normal_traversal_and_full_width_device_metadata_without_factory_io() {
    let calls = Arc::new(Mutex::new(Calls::default()));
    let mut fs = DeviceFilesystem::default();
    let root = fs.root();
    let directory = fs
        .register(&root, b"sessions", NodeKind::Directory, attrs(0o750))
        .unwrap();
    let node = fs
        .register_external(
            &directory,
            b"0",
            attrs(0o620),
            definition(&calls, 0x1234_5678_9abc_def0),
        )
        .unwrap();
    assert_eq!(node.kind(), NodeKind::External);
    let found = match path_walk::resolve(
        &fs,
        root.clone(),
        root.clone(),
        b"/sessions/0",
        true,
        owner(),
    )
    .unwrap()
    {
        Resolution::Found { inode, .. } => inode,
        _ => panic!("registered device missing"),
    };
    assert_eq!(found.id(), node.id());
    let status = fs.status(&node, 7).unwrap();
    assert_eq!(
        (
            status.kind,
            status.mode,
            status.uid,
            status.gid,
            status.link_count
        ),
        (wire::NODE_TYPE_SPECIAL, 0o020620, 1000, 20, 1)
    );
    assert_eq!(status.special_device, 0x1234_5678_9abc_def0);
    assert_eq!(status.device, 7);
    assert_eq!(fs.children(&directory).unwrap()[0].1.id(), node.id());
    assert!(!fs.is_directory(&node));
    assert!(calls.lock().unwrap().requests.is_empty());
    assert!(matches!(
        fs.open_null(&node, owner(), true, false, 0),
        Err(21)
    ));
}

#[test]
fn permissions_are_checked_before_factory_calls_and_open_access_cannot_expand() {
    let calls = Arc::new(Mutex::new(Calls::default()));
    let mut fs = DeviceFilesystem::default();
    let root = fs.root();
    let node = fs
        .register_external(&root, b"object", attrs(0o640), definition(&calls, 9))
        .unwrap();
    let outsider = Credentials {
        uid: 2000,
        gid: 2000,
        groups: &[],
    };
    let group = Credentials {
        groups: &[20],
        ..outsider
    };
    assert!(matches!(
        fs.open_external(&node, outsider, true, false, 0),
        Err(13)
    ));
    assert!(matches!(
        fs.open_external(&node, group, false, true, 0),
        Err(13)
    ));
    assert!(matches!(
        fs.open_external(&node, owner(), false, false, 0),
        Err(22)
    ));
    assert!(matches!(
        fs.open_external(&node, owner(), true, false, u32::MAX),
        Err(22)
    ));
    assert!(calls.lock().unwrap().requests.is_empty());
    let reader = fs
        .open_external(&node, group, true, false, wire::OPEN_STATUS_NONBLOCK)
        .unwrap();
    let writer = fs
        .open_external(&node, owner(), false, true, wire::OPEN_STATUS_APPEND)
        .unwrap();
    fs.set_attributes(&node, attrs(0)).unwrap();
    assert!(matches!(
        fs.open_external(&node, owner(), true, false, 0),
        Err(13)
    ));
    let read = reader.publish(metadata()).unwrap();
    let write = writer.publish(metadata()).unwrap();
    assert_ne!(read.handle, write.handle);
    assert_eq!(read.rights & R, R);
    assert_eq!(read.rights & W, 0);
    assert_eq!(write.rights & W, W);
    assert_eq!(write.rights & R, 0);
    let calls = calls.lock().unwrap();
    assert_eq!(calls.requests[0].0, metadata());
    assert_eq!(
        calls.requests[0].1.options,
        mnu_abi::HANDLE_OPTION_NONBLOCKING
    );
    assert_eq!(calls.requests[1].1.options, 0);
}

#[test]
fn unpublication_and_recreation_never_retarget_an_admitted_open_or_release_its_factory_early() {
    let old = Arc::new(Mutex::new(Calls::default()));
    let new = Arc::new(Mutex::new(Calls::default()));
    let mut fs = DeviceFilesystem::default();
    let root = fs.root();
    let node = fs
        .register_external(&root, b"object", attrs(0o600), definition(&old, 10))
        .unwrap();
    let admitted = fs.open_external(&node, owner(), true, false, 0).unwrap();
    let removed = fs.unregister(&root, b"object").unwrap();
    let replacement = fs
        .register_external(&root, b"object", attrs(0o600), definition(&new, 11))
        .unwrap();
    assert_ne!(replacement.id(), admitted.node().id());
    assert_eq!(fs.status(admitted.node(), 0).unwrap().link_count, 0);
    assert_eq!(fs.status(admitted.node(), 0).unwrap().special_device, 10);
    drop(node);
    drop(removed);
    assert_eq!(old.lock().unwrap().dropped, 0);
    admitted.publish(metadata()).unwrap();
    assert_eq!(old.lock().unwrap().requests.len(), 1);
    assert!(new.lock().unwrap().requests.is_empty());
    drop(admitted);
    assert_eq!(old.lock().unwrap().dropped, 1);
    assert_eq!(new.lock().unwrap().dropped, 0);
    drop(replacement);
    drop(root);
    drop(fs);
    assert_eq!(new.lock().unwrap().dropped, 1);
}

#[test]
fn foreign_node_authority_is_rejected_even_for_root_and_rejected_registrations_drop_factory() {
    let calls = Arc::new(Mutex::new(Calls::default()));
    let mut fs = DeviceFilesystem::default();
    let root = fs.root();
    let foreign = DeviceFilesystem::default();
    let foreign_node = foreign.root();
    assert!(matches!(
        fs.register_external(&foreign_node, b"new", attrs(0o600), definition(&calls, 1)),
        Err(13)
    ));
    assert_eq!(calls.lock().unwrap().dropped, 1);
    let node = fs
        .register_external(&root, b"new", attrs(0o600), definition(&calls, 1))
        .unwrap();
    assert!(matches!(
        foreign.open_external(
            &node,
            Credentials {
                uid: 0,
                gid: 0,
                groups: &[]
            },
            true,
            false,
            0
        ),
        Err(13)
    ));
    assert!(matches!(
        fs.register_external(&root, b"new", attrs(0o600), definition(&calls, 2)),
        Err(17)
    ));
    assert_eq!(calls.lock().unwrap().dropped, 2);
    assert!(matches!(
        fs.register(&root, b"unbacked", NodeKind::External, attrs(0o600)),
        Err(22)
    ));
    let directory = fs
        .register(&root, b"directory", NodeKind::Directory, attrs(0o700))
        .unwrap();
    let removed = fs.unregister(&root, b"directory").unwrap();
    assert!(matches!(
        fs.register_external(&directory, b"orphan", attrs(0o600), definition(&calls, 3)),
        Err(2)
    ));
    assert_eq!(calls.lock().unwrap().dropped, 3);
    assert!(matches!(
        fs.open_external(&removed, owner(), true, false, 0),
        Err(95)
    ));
}
