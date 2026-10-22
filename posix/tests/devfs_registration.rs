use filesystem_service::devfs::{Attributes, DeviceFilesystem, Node, NodeKind};
use filesystem_service::path_walk::{self, Backend, Credentials, Resolution};

fn attributes(mode: u16) -> Attributes {
    Attributes {
        mode,
        uid: 1000,
        gid: 20,
    }
}
fn user() -> Credentials<'static> {
    Credentials {
        uid: 1000,
        gid: 20,
        groups: &[],
    }
}
fn found(fs: &DeviceFilesystem, root: Node, base: Node, path: &[u8]) -> Node {
    match path_walk::resolve(fs, root, base, path, true, user()).unwrap() {
        Resolution::Found { inode, .. } => inode,
        Resolution::Missing { .. } => panic!("registered node missing"),
    }
}

#[test]
fn dynamic_directories_use_normal_lookup_and_root_clamped_ancestry() {
    let mut fs = DeviceFilesystem::default();
    let root = fs.root();
    let first = fs
        .register(&root, b"session", NodeKind::Directory, attributes(0o750))
        .unwrap();
    let nested = fs
        .register(&first, b"nested", NodeKind::Directory, attributes(0o750))
        .unwrap();
    let leaf = fs
        .register(&nested, b"device", NodeKind::Null, attributes(0o600))
        .unwrap();
    assert_eq!(
        found(&fs, root.clone(), root.clone(), b"/session/nested/device").id(),
        leaf.id()
    );
    assert_eq!(
        found(&fs, root.clone(), nested.clone(), b"../nested/device").id(),
        leaf.id()
    );
    assert_eq!(
        found(&fs, first.clone(), nested.clone(), b"../../nested/device").id(),
        leaf.id()
    );
    assert!(matches!(
        path_walk::resolve(&fs, first.clone(), root.clone(), b"nested", true, user()),
        Err(13)
    ));
    let ids: Vec<_> = fs
        .ancestry(&root, nested.clone())
        .unwrap()
        .iter()
        .map(Node::id)
        .collect();
    assert_eq!(ids, [root.id(), first.id(), nested.id()]);
    assert_eq!(fs.status(&root, 1).unwrap().link_count, 3);
    assert_eq!(fs.status(&first, 1).unwrap().link_count, 3);
    assert_eq!(fs.status(&nested, 1).unwrap().link_count, 2);
    assert_eq!(fs.children(&nested).unwrap()[0].0, b"device");
}

#[test]
fn registration_rejects_invalid_names_types_and_duplicates_without_mutating_links() {
    let mut fs = DeviceFilesystem::default();
    let root = fs.root();
    for name in [b"".as_slice(), b".", b"..", b"a/b", b"a\0b"] {
        assert!(matches!(
            fs.register(&root, name, NodeKind::Directory, attributes(0o755)),
            Err(22)
        ));
    }
    assert!(matches!(
        fs.register(&root, &vec![b'a'; 256], NodeKind::Null, attributes(0o600)),
        Err(36)
    ));
    assert!(matches!(
        fs.register(&root, b"bad", NodeKind::Null, attributes(0o100600)),
        Err(22)
    ));
    assert!(matches!(
        fs.register(&root, b"null", NodeKind::Directory, attributes(0o755)),
        Err(17)
    ));
    let null = fs.child(&root, b"null").unwrap();
    assert!(matches!(
        fs.register(&null, b"child", NodeKind::Null, attributes(0o600)),
        Err(20)
    ));
    assert_eq!(fs.status(&root, 1).unwrap().link_count, 2);
    assert_eq!(fs.children(&root).unwrap().len(), 1);
    let long = vec![0xff; 255];
    let node = fs
        .register(&root, &long, NodeKind::Null, attributes(0o600))
        .unwrap();
    assert_eq!(fs.child(&root, &long).unwrap().id(), node.id());
}

#[test]
fn ownership_permissions_and_supplementary_groups_apply_to_actual_nodes() {
    let mut fs = DeviceFilesystem::default();
    let root = fs.root();
    let directory = fs
        .register(&root, b"private", NodeKind::Directory, attributes(0o710))
        .unwrap();
    let node = fs
        .register(&directory, b"object", NodeKind::Null, attributes(0o660))
        .unwrap();
    let outsider = Credentials {
        uid: 2000,
        gid: 2000,
        groups: &[],
    };
    let group = Credentials {
        uid: 2000,
        gid: 2000,
        groups: &[20],
    };
    assert!(matches!(
        path_walk::resolve(
            &fs,
            root.clone(),
            root.clone(),
            b"private/object",
            true,
            outsider
        ),
        Err(13)
    ));
    assert!(path_walk::resolve(&fs, root.clone(), root, b"private/object", true, group).is_ok());
    assert!(matches!(
        fs.open_null(&node, outsider, true, false, 0),
        Err(13)
    ));
    let retained = fs.open_null(&node, group, false, true, 0).unwrap();
    fs.set_attributes(
        &node,
        Attributes {
            mode: 0o600,
            uid: 3000,
            gid: 3000,
        },
    )
    .unwrap();
    assert!(matches!(
        fs.open_null(&node, group, false, true, 0),
        Err(13)
    ));
    assert_eq!(retained.write(b"already granted"), Ok(15));
    let status = fs.status(&node, 7).unwrap();
    assert_eq!(
        (status.mode, status.uid, status.gid),
        (0o020600, 3000, 3000)
    );
}

#[test]
fn unpublication_keeps_open_objects_and_never_reuses_retained_inode_identity() {
    let mut fs = DeviceFilesystem::default();
    let root = fs.root();
    let node = fs
        .register(&root, b"object", NodeKind::Null, attributes(0o600))
        .unwrap();
    let reader = fs.open_null(&node, user(), true, false, 0).unwrap();
    let removed = fs.unregister(&root, b"object").unwrap();
    assert_eq!(removed.id(), node.id());
    assert_eq!(fs.status(&node, 7).unwrap().link_count, 0);
    assert!(matches!(fs.child(&root, b"object"), Err(2)));
    assert_eq!(reader.read_into(&mut [0xcc; 8]), Ok(0));
    let replacement = fs
        .register(&root, b"object", NodeKind::Null, attributes(0o000))
        .unwrap();
    assert_ne!(replacement.id(), node.id());
    assert_eq!(fs.status(&replacement, 7).unwrap().link_count, 1);
    assert_eq!(fs.status(&node, 7).unwrap().mode, 0o020600);
    assert!(matches!(
        fs.open_null(&replacement, user(), true, false, 0),
        Err(13)
    ));
}

#[test]
fn removed_directories_cannot_publish_new_children_and_nonempty_removal_is_atomic() {
    let mut fs = DeviceFilesystem::default();
    let root = fs.root();
    let directory = fs
        .register(&root, b"directory", NodeKind::Directory, attributes(0o700))
        .unwrap();
    let leaf = fs
        .register(&directory, b"child", NodeKind::Null, attributes(0o600))
        .unwrap();
    assert!(matches!(fs.unregister(&root, b"directory"), Err(39)));
    assert_eq!(fs.status(&root, 0).unwrap().link_count, 3);
    assert_eq!(fs.child(&directory, b"child").unwrap().id(), leaf.id());
    fs.unregister(&directory, b"child").unwrap();
    fs.unregister(&root, b"directory").unwrap();
    assert_eq!(fs.status(&root, 0).unwrap().link_count, 2);
    assert_eq!(fs.status(&directory, 0).unwrap().link_count, 0);
    assert!(matches!(
        fs.register(&directory, b"new", NodeKind::Null, attributes(0o600)),
        Err(2)
    ));
    assert_eq!(fs.parent(&directory).unwrap().id(), root.id());
}

#[test]
fn foreign_nodes_cannot_register_remove_update_or_reconstruct_ancestry() {
    let mut fs = DeviceFilesystem::default();
    let other = DeviceFilesystem::default();
    let foreign = other.root();
    assert_eq!(foreign.id(), fs.root().id());
    assert!(matches!(
        fs.register(&foreign, b"new", NodeKind::Null, attributes(0o600)),
        Err(13)
    ));
    assert!(matches!(fs.unregister(&foreign, b"null"), Err(13)));
    assert_eq!(fs.set_attributes(&foreign, attributes(0o777)), Err(13));
    assert!(matches!(fs.parent(&foreign), Err(13)));
    assert!(matches!(fs.ancestry(&fs.root(), foreign), Err(13)));
    assert_eq!(fs.status(&fs.root(), 0).unwrap().mode, 0o040555);
}
