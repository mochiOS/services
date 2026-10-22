use super::{Fixture, Namespace, credentials, walk};
use filesystem_service::devfs::{Attributes, DeviceFilesystem, NodeKind};
use filesystem_service::path_walk::{Credentials, Resolution};
use std::sync::{Arc, Mutex};
#[path = "external_factory.rs"]
pub(super) mod factory;
use factory::{Calls, definition, metadata};
fn attrs() -> Attributes {
    Attributes {
        mode: 0o600,
        uid: 501,
        gid: 20,
    }
}

#[test]
fn external_registration_uses_actual_mount_nodes_and_retains_removed_device_identity() {
    let fixture = Fixture::new();
    let mut namespace = Namespace::new(fixture.volume("external-mounted-devices")).unwrap();
    let root = namespace.root();
    let devices = namespace
        .mount_named_devices(root.clone(), b"devices", DeviceFilesystem::default())
        .unwrap();
    let group = namespace
        .register_device_node(
            &devices,
            b"session",
            NodeKind::Directory,
            Attributes {
                mode: 0o700,
                ..attrs()
            },
        )
        .unwrap();
    let calls = Arc::new(Mutex::new(Calls::default()));
    let leaf = namespace
        .register_external_device(&group, b"0", attrs(), definition(&calls, 0x123456789))
        .unwrap();
    assert_eq!(
        walk(&namespace, root.clone(), b"/devices/session/0").id(),
        leaf.id()
    );
    assert_eq!(
        namespace.device_status(&leaf).unwrap().special_device,
        0x123456789
    );
    let admitted = namespace
        .open_external_device(&leaf, credentials(), true, false, 0)
        .unwrap();
    assert!(matches!(
        namespace.resolve(
            root.clone(),
            root.clone(),
            b"/devices/session/0",
            true,
            Credentials {
                uid: 999,
                gid: 999,
                groups: &[]
            }
        ),
        Err(13)
    ));
    assert!(matches!(
        namespace.open_external_device(
            &leaf,
            Credentials {
                uid: 999,
                gid: 999,
                groups: &[]
            },
            true,
            false,
            0
        ),
        Err(13)
    ));
    let removed = namespace.unregister_device_node(&group, b"0").unwrap();
    assert_eq!(namespace.device_status(&removed).unwrap().link_count, 0);
    assert!(matches!(
        namespace.resolve(
            root.clone(),
            root,
            b"/devices/session/0",
            true,
            credentials()
        ),
        Ok(Resolution::Missing { .. })
    ));
    let replacement = namespace
        .register_external_device(
            &group,
            b"0",
            attrs(),
            definition(&Arc::new(Mutex::new(Calls::default())), 7),
        )
        .unwrap();
    assert_ne!(replacement.id(), leaf.id());
    admitted.publish(metadata()).unwrap();
    assert_eq!(calls.lock().unwrap().requests.len(), 1);
    drop(leaf);
    drop(removed);
    assert_eq!(calls.lock().unwrap().dropped, 0);
    drop(admitted);
    assert_eq!(calls.lock().unwrap().dropped, 1);
}

#[test]
fn external_registration_and_open_cannot_cross_named_mount_or_namespace_authority() {
    let fixture = Fixture::new();
    let mut namespace = Namespace::new(fixture.volume("external-registration-authority")).unwrap();
    let devices = namespace
        .mount_named_devices(namespace.root(), b"devices", DeviceFilesystem::default())
        .unwrap();
    namespace
        .mount_named_devices(devices.clone(), b"covered", DeviceFilesystem::default())
        .unwrap();
    let calls = Arc::new(Mutex::new(Calls::default()));
    assert!(matches!(
        namespace.register_external_device(&devices, b"covered", attrs(), definition(&calls, 1)),
        Err(17)
    ));
    assert!(matches!(
        namespace.register_external_device(
            &namespace.root(),
            b"disk",
            attrs(),
            definition(&calls, 1)
        ),
        Err(95)
    ));
    let mut foreign = Namespace::new(fixture.volume("external-foreign-namespace")).unwrap();
    let foreign_devices = foreign
        .mount_named_devices(foreign.root(), b"devices", DeviceFilesystem::default())
        .unwrap();
    let foreign_leaf = foreign
        .register_external_device(&foreign_devices, b"0", attrs(), definition(&calls, 1))
        .unwrap();
    assert!(matches!(
        namespace.register_external_device(
            &foreign_devices,
            b"bad",
            attrs(),
            definition(&calls, 1)
        ),
        Err(13)
    ));
    assert!(matches!(
        namespace.open_external_device(
            &foreign_leaf,
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
    assert!(calls.lock().unwrap().requests.is_empty());
    assert_eq!(calls.lock().unwrap().dropped, 3);
}
