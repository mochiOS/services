use super::*;
use ext4plus::inode::InodeCreationOptions;
use ext4plus::{DirEntryName, FileType};

fn create(
    service: &mut FilesystemService,
    directory: u64,
    kind: u8,
    name: &[u8],
) -> Result<(), i32> {
    let anchors = PathAnchors {
        root_open_id: None,
        base_open_id: Some(directory),
    };
    let credentials = credentials(1001, 77, &[]);
    match kind {
        0 => service.open_at(
            mode_request(
                wire::OP_OPEN_AT,
                wire::OPEN_AT_BASE_ATTACHED
                    | wire::OPEN_AT_CREATE
                    | wire::OPEN_AT_EXCLUSIVE
                    | wire::OPEN_AT_WRITE,
                0o600,
            ),
            name,
            anchors,
            credentials,
        ),
        1 => service.mkdir_at(
            mode_request(wire::OP_MKDIR_AT, wire::MKDIR_AT_BASE_ATTACHED, 0o700),
            name,
            anchors,
            credentials,
        ),
        2 | 4 => {
            let mut payload = if kind == 2 {
                b"target".to_vec()
            } else {
                vec![b'a'; 100]
            };
            let length = payload.len() as u32;
            payload.extend_from_slice(name);
            service.symlink_at(
                wire::Header {
                    mode: length,
                    ..request(wire::OP_SYMLINK_AT, wire::SYMLINK_AT_BASE_ATTACHED)
                },
                &payload,
                anchors,
                credentials,
            )
        }
        3 => service.create_socket_at_retained(
            mode_request(
                wire::OP_CREATE_SOCKET_AT,
                wire::SOCKET_AT_BASE_ATTACHED,
                0o600,
            ),
            name,
            anchors,
            credentials,
        ),
        _ => unreachable!(),
    }
    .map(|_| ())
}

#[test]
fn all_creation_paths_stamp_child_and_parent_once_using_retained_anchors() {
    let (_fixture, disk, mut service) = metadata_fixture();
    let directory = open(&mut service, b"/work", true);
    let mut parent = disk
        .path_to_inode("/work".try_into().unwrap(), FollowSymlinks::All)
        .unwrap();
    parent
        .set_signed_timestamps(Some(time(-1, 12)), Some(time(2, 13)), Some(time(3, 14)))
        .unwrap();
    parent.write(&disk).unwrap();
    for kind in 0..5 {
        let name = format!("created-{kind}");
        let now = time(2_147_483_648 + i64::from(kind), 123_456_789);
        set_clock(Ok(now));
        create(&mut service, directory, kind, name.as_bytes()).unwrap();
        assert_eq!(calls(), 1);
        let child = disk
            .path_to_inode(
                format!("/work/{name}").as_str().try_into().unwrap(),
                FollowSymlinks::ExcludeFinalComponent,
            )
            .unwrap();
        assert_eq!(times(&child), [(now.seconds, now.nanoseconds); 3]);
        assert_eq!(
            inode_time::decode(child.crtime().unwrap()),
            Some((now.seconds, now.nanoseconds))
        );
        assert_eq!(child.uid(), 1001);
        assert_eq!(child.gid(), 77);
        assert_eq!(
            status_times(status(&mut service, directory)),
            [
                (-1, 12),
                (now.seconds, now.nanoseconds),
                (now.seconds, now.nanoseconds)
            ]
        );
        let parent = disk
            .path_to_inode("/work".try_into().unwrap(), FollowSymlinks::All)
            .unwrap();
        assert_eq!(parent.links_count(), if kind == 0 { 2 } else { 3 });
    }
    set_clock(Err(5));
    for kind in 0..5 {
        let name = format!("created-{kind}");
        assert_eq!(
            create(&mut service, directory, kind, name.as_bytes()),
            Err(17)
        );
        assert_eq!(calls(), 0);
    }
}

#[test]
fn clock_and_range_errors_leave_namespace_bitmaps_and_parent_metadata_unchanged() {
    let (fixture, disk, mut service) = metadata_fixture();
    let directory = open(&mut service, b"/work", true);
    let before = fixture.image.0.lock().unwrap().clone();
    for kind in 0..5 {
        for (clock, expected) in [
            (Err(11), 11),
            (Err(13), 13),
            (Err(5), 5),
            (Ok(time(i64::MAX, 0)), 75),
            (Ok(time(0, 1_000_000_000)), 22),
        ] {
            set_clock(clock);
            assert_eq!(create(&mut service, directory, kind, b"new"), Err(expected));
            assert_eq!(calls(), 1);
            assert_eq!(*fixture.image.0.lock().unwrap(), before);
            assert!(
                disk.path_to_inode(
                    "/work/new".try_into().unwrap(),
                    FollowSymlinks::ExcludeFinalComponent
                )
                .is_err()
            );
        }
    }
    // Permission checks must use current anchor metadata, not its open snapshot.
    let mut parent = disk
        .path_to_inode("/work".try_into().unwrap(), FollowSymlinks::All)
        .unwrap();
    parent
        .set_mode(InodeMode::S_IFDIR | InodeMode::from_bits_retain(0o500))
        .unwrap();
    parent.write(&disk).unwrap();
    set_clock(Err(5));
    for kind in 0..5 {
        assert_eq!(create(&mut service, directory, kind, b"new"), Err(13));
    }
    assert_eq!(calls(), 0);
}

#[test]
fn mounted_creation_updates_only_the_resolved_volume() {
    let (root, _disk, mut service) = metadata_fixture();
    let (_fixture, mounted, _) = metadata_fixture();
    service.mount_volume(b"/system", mounted.clone()).unwrap();
    let directory = open(&mut service, b"/system/work", true);
    let before = root.image.0.lock().unwrap().clone();
    for kind in 0..5 {
        set_clock(Ok(time(30 + i64::from(kind), 40)));
        create(
            &mut service,
            directory,
            kind,
            format!("new-{kind}").as_bytes(),
        )
        .unwrap();
        assert_eq!(*root.image.0.lock().unwrap(), before);
        let child = mounted
            .path_to_inode(
                format!("/work/new-{kind}").as_str().try_into().unwrap(),
                FollowSymlinks::ExcludeFinalComponent,
            )
            .unwrap();
        assert_eq!(times(&child), [(30 + i64::from(kind), 40); 3]);
    }
}

#[test]
fn readonly_and_immutable_parents_reject_creation_before_clock_or_allocation() {
    let (fixture, disk, mut service) = metadata_fixture();
    let directory = open(&mut service, b"/work", true);
    let mut parent = disk
        .path_to_inode("/work".try_into().unwrap(), FollowSymlinks::All)
        .unwrap();
    parent.set_flags(parent.flags() | InodeFlags::IMMUTABLE);
    parent.write(&disk).unwrap();
    let before = fixture.image.0.lock().unwrap().clone();
    set_clock(Err(5));
    for kind in 0..5 {
        assert_eq!(create(&mut service, directory, kind, b"new"), Err(1));
    }
    assert_eq!(calls(), 0);
    assert_eq!(*fixture.image.0.lock().unwrap(), before);
    let readonly = Ext4::load(Box::new(fixture.image.clone())).unwrap();
    let mut service = FilesystemService::new_with_clock(readonly, clock);
    let directory = open(&mut service, b"/work", true);
    for kind in 0..5 {
        assert_eq!(create(&mut service, directory, kind, b"new"), Err(30));
    }
    assert_eq!(calls(), 0);
    assert_eq!(*fixture.image.0.lock().unwrap(), before);
}

#[test]
fn legacy_creation_requests_share_checked_times_and_parent_inode_persistence() {
    let (_fixture, disk, mut service) = metadata_fixture();
    for (kind, path) in [
        (wire::NODE_TYPE_REGULAR, b"/work/legacy-file".as_slice()),
        (wire::NODE_TYPE_DIRECTORY, b"/work/legacy-dir".as_slice()),
    ] {
        set_clock(Ok(time(-1, 123)));
        let reply = service.handle(
            wire::Header {
                mode: 0o700,
                offset: 1001 | (77u64 << 32),
                ..request(wire::OP_CREATE, kind)
            },
            path,
        );
        assert_eq!(reply.header.status, 0);
        assert_eq!(calls(), 1);
        let inode = disk
            .path_to_inode(
                std::str::from_utf8(path).unwrap().try_into().unwrap(),
                FollowSymlinks::All,
            )
            .unwrap();
        assert_eq!(times(&inode), [(-1, 123); 3]);
        assert_eq!(
            times(
                &disk
                    .path_to_inode("/work".try_into().unwrap(), FollowSymlinks::All)
                    .unwrap()
            )[1..],
            [(-1, 123); 2]
        );
    }
    set_clock(Ok(time(-1, 124)));
    let reply = service.handle(
        wire::Header {
            offset: 6,
            node_id: 1001,
            open_id: 77,
            ..request(wire::OP_SYMLINK, 0)
        },
        b"target/work/legacy-link",
    );
    assert_eq!(reply.header.status, 0);
    assert_eq!(calls(), 1);
    let inode = disk
        .path_to_inode(
            "/work/legacy-link".try_into().unwrap(),
            FollowSymlinks::ExcludeFinalComponent,
        )
        .unwrap();
    assert_eq!(times(&inode), [(-1, 124); 3]);
    assert_eq!(
        times(
            &disk
                .path_to_inode("/work".try_into().unwrap(), FollowSymlinks::All)
                .unwrap()
        )[1..],
        [(-1, 124); 2]
    );
}

fn options() -> InodeCreationOptions {
    InodeCreationOptions {
        file_type: FileType::Regular,
        mode: InodeMode::S_IFREG | InodeMode::from_bits_retain(0o600),
        uid: 1001,
        gid: 77,
        time: std::time::Duration::default(),
        flags: InodeFlags::empty(),
    }
}

#[test]
fn signed_creation_checks_new_inode_layout_before_allocation_and_preserves_epoch_bits() {
    for size in [128, 256] {
        let fixture = Fixture::create(size, None, true);
        let disk = fixture.load();
        for (index, seconds) in [-1, 0, 2_147_483_647, 2_147_483_648, 15_032_385_535]
            .into_iter()
            .enumerate()
        {
            let before = fixture.image.0.lock().unwrap().clone();
            let now = time(seconds, 123_456_789);
            let result = disk.create_inode_with_timestamps(options(), now);
            if size == 128 && seconds > i64::from(i32::MAX) {
                assert!(matches!(
                    result,
                    Err(ext4plus::error::Ext4Error::Timestamp(
                        ext4plus::inode::TimestampError::OutOfRange
                    ))
                ));
                assert_eq!(*fixture.image.0.lock().unwrap(), before);
                continue;
            }
            let mut inode = result.unwrap();
            let mut parent =
                ext4plus::dir::Dir::open_inode(&disk, disk.read_root_inode().unwrap()).unwrap();
            parent
                .link(
                    DirEntryName::try_from(format!("new-{index}").as_str()).unwrap(),
                    &mut inode,
                )
                .unwrap();
            let persisted = Inode::read(&disk, inode.index).unwrap();
            let expected = (seconds, if size == 128 { 0 } else { now.nanoseconds });
            assert_eq!(times(&persisted), [expected; 3]);
            if size == 256 {
                assert_eq!(
                    inode_time::decode(persisted.crtime().unwrap()),
                    Some(expected)
                );
            }
        }
        for now in [time(i64::MAX, 0), time(0, 1_000_000_000)] {
            let before = fixture.image.0.lock().unwrap().clone();
            assert!(matches!(
                disk.create_inode_with_timestamps(options(), now),
                Err(ext4plus::error::Ext4Error::Timestamp(_))
            ));
            assert_eq!(*fixture.image.0.lock().unwrap(), before);
        }
    }
}
