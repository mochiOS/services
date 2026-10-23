use super::trailing_lookup::status;
use super::*;

fn create(fs: &mut FilesystemService, path: &[u8], mode: u32) -> Result<protocol::NodeStatus, i32> {
    let response = fs.create_fifo_at(
        protocol::Header {
            mode,
            ..Default::default()
        },
        path,
        PathAnchors::default(),
        root_credentials(),
    )?;
    assert_eq!(response.header.open_id, 0);
    Ok(protocol::decode_node_status(&response.payload).unwrap())
}

fn retain(fs: &mut FilesystemService, path: &[u8], flags: u32) -> Result<u64, i32> {
    fs.open_fifo_at_retained(
        protocol::Header {
            flags,
            ..Default::default()
        },
        path,
        PathAnchors::default(),
        root_credentials(),
    )
    .map(|response| response.header.open_id)
}

fn retained_status(fs: &FilesystemService, id: u64) -> protocol::NodeStatus {
    protocol::decode_node_status(
        &fs.stat_handle(protocol::Header::default(), id)
            .unwrap()
            .payload,
    )
    .unwrap()
}

#[test]
fn fifo_inode_is_persistent_and_has_no_regular_file_data() {
    let (mut fs, image) = test_filesystem_with_storage(None);
    let created = create(&mut fs, b"/fifo", 0o10640).unwrap();
    assert_eq!(created.kind, protocol::NODE_TYPE_FIFO);
    assert_eq!(created.mode, 0o640);
    assert_eq!(
        (created.size, created.blocks, created.link_count),
        (0, 0, 1)
    );
    let converted = posix_service::filesystem_metadata::translate(created).unwrap();
    assert_eq!(converted.mode, 0o010640);
    let owner = retain(&mut fs, b"/fifo", protocol::OPEN_AT_READ).unwrap();
    assert_eq!(fs.provider_memory_object(owner), Ok(0));
    assert_eq!(fs.provider_read(owner, 1), Err(95));
    assert!(fs.provider_write(owner, b"not disk data").is_err());
    assert_eq!(fs.provider_seek(owner, 0, HANDLE_SEEK_START), Err(95));
    for flags in [
        protocol::OPEN_AT_READ,
        protocol::OPEN_AT_WRITE,
        protocol::OPEN_AT_READ | protocol::OPEN_AT_WRITE | protocol::OPEN_AT_TRUNCATE,
    ] {
        assert_eq!(
            fs.open_at(
                protocol::Header {
                    flags,
                    ..Default::default()
                },
                b"/fifo",
                PathAnchors::default(),
                root_credentials()
            )
            .err(),
            Some(95)
        );
    }
    let before = status(&mut fs, b"/fifo");
    assert!(
        fs.truncate_at(
            protocol::Header {
                offset: 100,
                ..Default::default()
            },
            b"/fifo",
            PathAnchors::default(),
            root_credentials()
        )
        .is_err()
    );
    let after = status(&mut fs, b"/fifo");
    assert_eq!(after, before);
    fs.provider_close(owner).unwrap();
    drop(fs);
    let disk = Ext4::load_with_writer(Box::new(image.clone()), Some(Box::new(image))).unwrap();
    let mut fs = FilesystemService::new(disk);
    let reopened = status(&mut fs, b"/fifo");
    assert_eq!(
        (reopened.node_id, reopened.kind, reopened.mode),
        (created.node_id, created.kind, created.mode)
    );
    assert_eq!((reopened.size, reopened.blocks), (0, 0));
}

#[test]
fn fifo_create_is_exclusive_and_preserves_existing_entries_with_slashes() {
    let mut fs = super::trailing_lookup::prepared(0o700);
    create(&mut fs, b"/fifo", 0o600).unwrap();
    for path in [
        b"/fifo".as_slice(),
        b"/target-file",
        b"/target-dir",
        b"/missing-link",
    ] {
        let original = status(&mut fs, path);
        for suffix in [b"".as_slice(), b"///"] {
            assert_eq!(
                create(&mut fs, &[path, suffix].concat(), 0o777).err(),
                Some(17)
            );
        }
        let after = status(&mut fs, path);
        assert_eq!(
            (after.node_id, after.mode, after.link_count),
            (original.node_id, original.mode, original.link_count)
        );
    }
    assert_eq!(create(&mut fs, b"/absent/", 0o600).err(), Some(2));
    assert_eq!(
        fs.stat_at(
            protocol::Header::default(),
            b"/absent",
            PathAnchors::default(),
            root_credentials()
        )
        .err(),
        Some(2)
    );
    let long = vec![b'/'; protocol::MAX_PATH_LEN + 1];
    assert_eq!(create(&mut fs, &long, 0o600).err(), Some(36));
}

#[test]
fn fifo_retention_checks_direction_credentials_and_parent_search() {
    let mut fs = test_filesystem();
    create(&mut fs, b"/fifo", 0o004).unwrap();
    let unprivileged = credentials(501, 501, &[]);
    let root = fs
        .open_at(
            protocol::Header {
                flags: protocol::OPEN_AT_READ | protocol::OPEN_AT_DIRECTORY,
                ..Default::default()
            },
            b"/",
            PathAnchors::default(),
            root_credentials(),
        )
        .unwrap()
        .header
        .open_id;
    fs.chmod_at(
        protocol::Header {
            mode: 0o755,
            ..Default::default()
        },
        b"/",
        PathAnchors::default(),
        root_credentials(),
    )
    .unwrap();
    let open = |fs: &mut FilesystemService, flags| {
        fs.open_fifo_at_retained(
            protocol::Header {
                flags,
                ..Default::default()
            },
            b"/fifo",
            PathAnchors::default(),
            unprivileged,
        )
    };
    let reader = open(&mut fs, protocol::OPEN_AT_READ)
        .unwrap()
        .header
        .open_id;
    assert_eq!(open(&mut fs, protocol::OPEN_AT_WRITE).err(), Some(13));
    fs.provider_close(reader).unwrap();
    // Search on the actual parent remains mandatory even for a readable FIFO.
    fs.chmod_handle(
        protocol::Header {
            mode: 0o600,
            ..Default::default()
        },
        root,
        root_credentials(),
    )
    .unwrap();
    assert_eq!(open(&mut fs, protocol::OPEN_AT_READ).err(), Some(13));
    fs.provider_close(root).unwrap();
}

#[test]
fn fifo_creation_inherits_parent_group_and_validates_anchors_before_mutation() {
    let mut fs = test_filesystem();
    fs.chmod_at(
        protocol::Header {
            mode: 0o755,
            ..Default::default()
        },
        b"/",
        PathAnchors::default(),
        root_credentials(),
    )
    .unwrap();
    fs.chown_at(
        protocol::Header {
            node_id: 777 << 32,
            ..Default::default()
        },
        b"/create-base",
        PathAnchors::default(),
        root_credentials(),
    )
    .unwrap();
    fs.chmod_at(
        protocol::Header {
            mode: 0o2777,
            ..Default::default()
        },
        b"/create-base",
        PathAnchors::default(),
        root_credentials(),
    )
    .unwrap();
    let response = fs
        .create_fifo_at(
            protocol::Header {
                mode: 0o2660,
                ..Default::default()
            },
            b"/create-base/fifo",
            PathAnchors::default(),
            credentials(501, 501, &[]),
        )
        .unwrap();
    let created = protocol::decode_node_status(&response.payload).unwrap();
    assert_eq!((created.uid, created.gid, created.mode), (501, 777, 0o660));
    for flags in [
        protocol::MKDIR_AT_BASE_ATTACHED,
        protocol::MKDIR_AT_ROOT_ATTACHED,
        1 << 20,
    ] {
        assert_eq!(
            fs.create_fifo_at(
                protocol::Header {
                    flags,
                    mode: 0o600,
                    ..Default::default()
                },
                b"/not-created",
                PathAnchors::default(),
                root_credentials()
            )
            .err(),
            Some(22)
        );
    }
    assert_eq!(
        fs.stat_at(
            protocol::Header::default(),
            b"/not-created",
            PathAnchors::default(),
            root_credentials()
        )
        .err(),
        Some(2)
    );
    assert_eq!(
        fs.create_fifo_at(
            protocol::Header {
                mode: 0o600,
                ..Default::default()
            },
            b"/forbidden",
            PathAnchors::default(),
            credentials(501, 501, &[])
        )
        .err(),
        Some(13)
    );
}

#[test]
fn fifo_metadata_reference_survives_unlink_and_never_follows_a_replacement_name() {
    let mut fs = test_filesystem();
    let original = create(&mut fs, b"/fifo", 0o600).unwrap();
    let a = retain(&mut fs, b"/fifo", protocol::OPEN_AT_READ).unwrap();
    let b = retain(&mut fs, b"/fifo", protocol::OPEN_AT_WRITE).unwrap();
    fs.unlink_at(
        protocol::Header::default(),
        b"/fifo",
        PathAnchors::default(),
        root_credentials(),
    )
    .unwrap();
    let replacement = create(&mut fs, b"/fifo", 0o660).unwrap();
    assert_ne!(replacement.node_id, original.node_id);
    for id in [a, b] {
        let retained = retained_status(&fs, id);
        assert_eq!(
            (retained.node_id, retained.kind, retained.link_count),
            (original.node_id, protocol::NODE_TYPE_FIFO, 0)
        );
    }
    fs.chmod_handle(
        protocol::Header {
            mode: 0o400,
            ..Default::default()
        },
        a,
        root_credentials(),
    )
    .unwrap();
    assert_eq!(retained_status(&fs, b).mode, 0o400);
    assert_eq!(status(&mut fs, b"/fifo").mode, replacement.mode);
    fs.provider_close(a).unwrap();
    assert_eq!(retained_status(&fs, b).link_count, 0);
    fs.provider_close(b).unwrap();
    assert_eq!(
        fs.stat_handle(protocol::Header::default(), b).err(),
        Some(9)
    );
    assert_eq!(status(&mut fs, b"/fifo").node_id, replacement.node_id);
}

#[test]
fn fifo_retention_rejects_wrong_types_flags_and_final_symlink_without_consuming_an_id() {
    let mut fs = test_filesystem();
    create(&mut fs, b"/fifo", 0o600).unwrap();
    let first = retain(&mut fs, b"/fifo", protocol::OPEN_AT_READ).unwrap();
    let target = b"fifo";
    fs.symlink_at(
        protocol::Header {
            mode: target.len() as u32,
            ..Default::default()
        },
        &[target.as_slice(), b"/fifo-link"].concat(),
        PathAnchors::default(),
        root_credentials(),
    )
    .unwrap();
    assert_eq!(
        retain(
            &mut fs,
            b"/fifo-link",
            protocol::OPEN_AT_READ | protocol::OPEN_AT_NOFOLLOW
        ),
        Err(40)
    );
    assert_eq!(retain(&mut fs, b"/fifo/", protocol::OPEN_AT_READ), Err(20));
    assert_eq!(retain(&mut fs, b"/missing", protocol::OPEN_AT_READ), Err(2));
    assert_eq!(retain(&mut fs, b"/", protocol::OPEN_AT_READ), Err(22));
    for flags in [
        0,
        protocol::OPEN_AT_READ | protocol::OPEN_AT_WRITE,
        protocol::OPEN_AT_READ | protocol::OPEN_AT_TRUNCATE,
        protocol::OPEN_AT_READ | protocol::OPEN_AT_ROOT_ATTACHED,
    ] {
        assert_eq!(retain(&mut fs, b"/fifo", flags), Err(22));
    }
    let linked = retain(&mut fs, b"/fifo-link", protocol::OPEN_AT_WRITE).unwrap();
    assert_eq!(linked, first + 1);
    assert_eq!(
        retained_status(&fs, first).node_id,
        retained_status(&fs, linked).node_id
    );
    fs.provider_close(first).unwrap();
    fs.provider_close(linked).unwrap();
}

#[test]
fn mounted_fifo_keeps_volume_identity_and_root_scope_for_raw_byte_names() {
    let mut fs = test_filesystem();
    let (other, image) = test_filesystem_with_storage(None);
    drop(other);
    let volume = Ext4::load_with_writer(Box::new(image.clone()), Some(Box::new(image))).unwrap();
    fs.mount_volume(b"/jail", volume).unwrap();
    let jail = fs
        .open_at(
            protocol::Header {
                flags: protocol::OPEN_AT_READ | protocol::OPEN_AT_DIRECTORY,
                ..Default::default()
            },
            b"/jail",
            PathAnchors::default(),
            root_credentials(),
        )
        .unwrap()
        .header
        .open_id;
    let created = fs
        .create_fifo_at(
            protocol::Header {
                flags: protocol::MKDIR_AT_ROOT_ATTACHED,
                mode: 0o600,
                ..Default::default()
            },
            b"/pipe\xff",
            PathAnchors {
                root_open_id: Some(jail),
                base_open_id: None,
            },
            root_credentials(),
        )
        .unwrap();
    let created = protocol::decode_node_status(&created.payload).unwrap();
    assert_ne!(created.device, 0);
    assert_eq!(created.device, created.node_id >> 32);
    let retained = fs
        .open_fifo_at_retained(
            protocol::Header {
                flags: protocol::OPEN_AT_ROOT_ATTACHED | protocol::OPEN_AT_READ,
                ..Default::default()
            },
            b"/../pipe\xff",
            PathAnchors {
                root_open_id: Some(jail),
                base_open_id: None,
            },
            root_credentials(),
        )
        .unwrap()
        .header
        .open_id;
    assert_eq!(retained_status(&fs, retained).node_id, created.node_id);
    assert_eq!(status(&mut fs, b"/jail/pipe\xff").node_id, created.node_id);
    assert_eq!(
        fs.stat_at(
            protocol::Header::default(),
            b"/pipe\xff",
            PathAnchors::default(),
            root_credentials()
        )
        .err(),
        Some(2)
    );
    fs.provider_close(jail).unwrap();
    assert_eq!(
        retained_status(&fs, retained).kind,
        protocol::NODE_TYPE_FIFO
    );
    fs.provider_close(retained).unwrap();
}

#[test]
fn read_only_volume_cannot_publish_a_fifo_entry() {
    let (fs, image) = test_filesystem_with_storage(None);
    drop(fs);
    let volume = Ext4::load_with_writer(Box::new(image), None).unwrap();
    let mut fs = FilesystemService::new(volume);
    assert_eq!(create(&mut fs, b"/fifo", 0o600).err(), Some(30));
    assert_eq!(
        fs.stat_at(
            protocol::Header::default(),
            b"/fifo",
            PathAnchors::default(),
            root_credentials()
        )
        .err(),
        Some(2)
    );
}
