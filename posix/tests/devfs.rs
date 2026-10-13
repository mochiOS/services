use filesystem_service::devfs::{DeviceFilesystem, NodeKind};
use filesystem_service::path_walk::{self, Backend, Credentials, Resolution};
use mochios_filesystem_protocol as protocol;

fn user() -> Credentials<'static> {
    Credentials {
        uid: 1000,
        gid: 1000,
        groups: &[],
    }
}

#[test]
fn shared_path_walker_resolves_device_identity_and_clamps_parent_traversal() {
    let fs = DeviceFilesystem::default();
    for path in [b"/null".as_slice(), b"null", b"../../null", b"./null"] {
        let node = match path_walk::resolve(&fs, fs.root(), fs.root(), path, true, user()).unwrap()
        {
            Resolution::Found { inode, .. } => inode,
            Resolution::Missing { .. } => panic!("device missing"),
        };
        assert_eq!(node.kind(), NodeKind::Null);
        assert_eq!(node.id(), 2);
        let status = fs.status(&node, 17).unwrap();
        assert_eq!(
            (status.device, status.node_id, status.mode),
            (17, 2, 0o020666)
        );
        assert_eq!(status.kind, protocol::NODE_TYPE_SPECIAL);
        assert_eq!(status.special_device, 259);
    }
}

#[test]
fn device_nodes_are_not_directories_and_missing_nodes_are_not_created() {
    let fs = DeviceFilesystem::default();
    assert!(matches!(
        path_walk::resolve(&fs, fs.root(), fs.root(), b"/absent", true, user()).unwrap(),
        Resolution::Missing { .. }
    ));
    for path in [b"/null/".as_slice(), b"/null/../null", b"/null/child"] {
        assert!(matches!(
            path_walk::resolve(&fs, fs.root(), fs.root(), path, true, user()),
            Err(20)
        ));
    }
    let entries = fs.children(&fs.root()).unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].0, b"null");
    assert!(matches!(fs.children(&entries[0].1), Err(20)));
}

#[test]
fn foreign_nodes_with_identical_numeric_ids_cannot_cross_filesystem_authority() {
    let fs = DeviceFilesystem::default();
    let other = DeviceFilesystem::default();
    let foreign = other.child(&other.root(), b"null").unwrap();
    let owned = fs.child(&fs.root(), b"null").unwrap();
    assert_eq!(foreign.id(), owned.id());
    assert!(matches!(fs.status(&foreign, 0), Err(13)));
    assert!(matches!(
        fs.open_null(&foreign, user(), true, true, 0),
        Err(13)
    ));
    assert!(matches!(fs.ancestry(&fs.root(), other.root()), Err(13)));
    assert!(matches!(fs.child(&other.root(), b"null"), Err(13)));
    assert!(matches!(fs.search(&other.root(), user()), Err(13)));
}

#[test]
fn open_device_checks_access_and_returns_distinct_descriptions() {
    let fs = DeviceFilesystem::default();
    let node = fs.child(&fs.root(), b"null").unwrap();
    let mut reader = fs.open_null(&node, user(), true, false, 0).unwrap();
    let writer = fs.open_null(&node, user(), false, true, 0).unwrap();
    assert_eq!(reader.read_into(&mut [1; 16]), Ok(0));
    assert_eq!(reader.write(b"x"), Err(13));
    assert_eq!(writer.write(b"discard"), Ok(7));
    assert_eq!(writer.read_into(&mut [0]), Err(13));
    reader.set_flags(protocol::OPEN_STATUS_NONBLOCK).unwrap();
    assert_eq!(writer.flags(), 0);
    assert!(matches!(
        fs.open_null(&node, user(), false, false, 0),
        Err(22)
    ));
    assert!(matches!(
        fs.open_null(&node, user(), true, true, u32::MAX),
        Err(22)
    ));
    assert!(matches!(
        fs.open_null(&fs.root(), user(), true, false, 0),
        Err(21)
    ));
}

#[test]
fn directory_metadata_and_device_metadata_are_independent_of_open_lifetime() {
    let fs = DeviceFilesystem::default();
    let root = fs.status(&fs.root(), 9).unwrap();
    assert_eq!((root.mode, root.link_count, root.node_id), (0o040555, 2, 1));
    let node = fs.child(&fs.root(), b"null").unwrap();
    let before = fs.status(&node, 9).unwrap();
    {
        let writer = fs.open_null(&node, user(), false, true, 0).unwrap();
        assert_eq!(writer.write_at(&[42; 4096], u64::MAX), Ok(4096));
        assert_eq!(writer.memory_object(), Err(95));
    }
    assert_eq!(fs.status(&node, 9).unwrap(), before);
    assert_eq!((before.size, before.blocks), (0, 0));
}
