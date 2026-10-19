use super::*;

fn link(
    service: &mut FilesystemService,
    old: &[u8],
    new: &[u8],
    flags: u32,
    anchors: RenameAnchors,
) -> Result<(), i32> {
    let mut payload = old.to_vec();
    payload.extend_from_slice(new);
    service
        .link_at(
            wire::Header {
                mode: old.len() as u32,
                ..request(wire::OP_LINK_AT, flags)
            },
            &payload,
            anchors,
            credentials(1001, 77, &[]),
        )
        .map(|_| ())
}

#[test]
fn link_stages_target_ctime_and_only_destination_directory_times_with_one_clock_read() {
    let (_fixture, disk, mut service) = metadata_fixture();
    let file = open(&mut service, b"/work/target", false);
    let source_parent = open(&mut service, b"/work", true);
    let destination = open(&mut service, b"/hidden", true);
    let source_before = status(&mut service, source_parent);
    let parent_before = status(&mut service, destination);
    let before = status(&mut service, file);
    set_clock(Ok(time(2_147_483_649, 123_456_789)));
    link(
        &mut service,
        b"target",
        b"new",
        wire::LINK_AT_OLD_BASE_ATTACHED | wire::LINK_AT_NEW_BASE_ATTACHED,
        RenameAnchors {
            root_open_id: None,
            old_base_open_id: Some(source_parent),
            new_base_open_id: Some(destination),
        },
    )
    .unwrap();
    assert_eq!(calls(), 1);
    let after = status(&mut service, file);
    assert_eq!(
        status_times(after),
        [(-1, 11), (2_147_483_648, 22), (2_147_483_649, 123_456_789)]
    );
    assert_eq!(after.link_count, before.link_count + 1);
    assert_eq!(status(&mut service, source_parent), source_before);
    assert_eq!(
        status_times(status(&mut service, destination)),
        [
            status_times(parent_before)[0],
            (2_147_483_649, 123_456_789),
            (2_147_483_649, 123_456_789)
        ]
    );
    let inode = disk
        .path_to_inode("/hidden/new".try_into().unwrap(), FollowSymlinks::All)
        .unwrap();
    let source = disk
        .path_to_inode("/work/target".try_into().unwrap(), FollowSymlinks::All)
        .unwrap();
    assert_eq!(inode.index, source.index);
    assert_eq!(times(&inode), status_times(after));
}

#[test]
fn link_clock_and_range_errors_leave_names_link_counts_and_all_image_bytes_unchanged() {
    let (fixture, _disk, mut service) = metadata_fixture();
    let file = open(&mut service, b"/work/target", false);
    let before = status(&mut service, file);
    let bytes = fixture.image.0.lock().unwrap().clone();
    for (clock, expected) in [
        (Err(11), 11),
        (Err(13), 13),
        (Err(5), 5),
        (Ok(time(i64::MAX, 0)), 75),
        (Ok(time(0, 1_000_000_000)), 22),
    ] {
        set_clock(clock);
        assert_eq!(
            link(
                &mut service,
                b"/work/target",
                b"/work/new",
                0,
                RenameAnchors::default()
            ),
            Err(expected)
        );
        assert_eq!(calls(), 1);
        assert_eq!(status(&mut service, file), before);
        assert_eq!(*fixture.image.0.lock().unwrap(), bytes);
    }
}

#[test]
fn existing_names_directory_targets_permissions_and_link_limits_fail_before_clock_access() {
    let (fixture, disk, mut service) = metadata_fixture();
    let mut target = disk
        .path_to_inode("/work/target".try_into().unwrap(), FollowSymlinks::All)
        .unwrap();
    set_clock(Err(5));
    assert_eq!(
        link(
            &mut service,
            b"/work/target",
            b"/work/link",
            0,
            RenameAnchors::default()
        ),
        Err(17)
    );
    assert_eq!(
        link(
            &mut service,
            b"/work",
            b"/work/new",
            0,
            RenameAnchors::default()
        ),
        Err(1)
    );
    assert_eq!(calls(), 0);
    target.set_flags(target.flags() | InodeFlags::IMMUTABLE);
    target.write(&disk).unwrap();
    let bytes = fixture.image.0.lock().unwrap().clone();
    assert_eq!(
        link(
            &mut service,
            b"/work/target",
            b"/work/new",
            0,
            RenameAnchors::default()
        ),
        Err(1)
    );
    assert_eq!(*fixture.image.0.lock().unwrap(), bytes);
    target.set_flags(target.flags().difference(InodeFlags::IMMUTABLE));
    target.set_links_count(u16::MAX);
    target.write(&disk).unwrap();
    let bytes = fixture.image.0.lock().unwrap().clone();
    assert_eq!(
        link(
            &mut service,
            b"/work/target",
            b"/work/new",
            0,
            RenameAnchors::default()
        ),
        Err(31)
    );
    assert_eq!(*fixture.image.0.lock().unwrap(), bytes);
    assert_eq!(calls(), 0);
    let mut parent = disk
        .path_to_inode("/work".try_into().unwrap(), FollowSymlinks::All)
        .unwrap();
    parent
        .set_mode(InodeMode::S_IFDIR | InodeMode::from_bits_retain(0o500))
        .unwrap();
    parent.write(&disk).unwrap();
    assert_eq!(
        link(
            &mut service,
            b"/work/target",
            b"/work/new",
            0,
            RenameAnchors::default()
        ),
        Err(13)
    );
    assert_eq!(calls(), 0);
}

#[test]
fn readonly_volumes_and_immutable_parent_directories_deny_links_before_clock_access() {
    let (fixture, disk, mut service) = metadata_fixture();
    let mut parent = disk
        .path_to_inode("/work".try_into().unwrap(), FollowSymlinks::All)
        .unwrap();
    parent.set_flags(parent.flags() | InodeFlags::IMMUTABLE);
    parent.write(&disk).unwrap();
    let before = fixture.image.0.lock().unwrap().clone();
    set_clock(Err(5));
    assert_eq!(
        link(
            &mut service,
            b"/work/target",
            b"/work/new",
            0,
            RenameAnchors::default()
        ),
        Err(1)
    );
    assert_eq!(calls(), 0);
    assert_eq!(*fixture.image.0.lock().unwrap(), before);
    parent.set_flags(parent.flags().difference(InodeFlags::IMMUTABLE));
    parent.write(&disk).unwrap();
    let before = fixture.image.0.lock().unwrap().clone();
    let readonly = Ext4::load(Box::new(fixture.image.clone())).unwrap();
    let mut service = FilesystemService::new_with_clock(readonly, clock);
    assert_eq!(
        link(
            &mut service,
            b"/work/target",
            b"/work/new",
            0,
            RenameAnchors::default()
        ),
        Err(30)
    );
    assert_eq!(calls(), 0);
    assert_eq!(*fixture.image.0.lock().unwrap(), before);
}

#[test]
fn symlink_follow_flag_updates_only_the_inode_that_receives_the_new_hard_link() {
    let (_fixture, disk, mut service) = metadata_fixture();
    let original = disk
        .path_to_inode(
            "/work/link".try_into().unwrap(),
            FollowSymlinks::ExcludeFinalComponent,
        )
        .unwrap();
    let original_times = times(&original);
    let file = open(&mut service, b"/work/target", false);
    let before = status(&mut service, file);
    set_clock(Ok(time(100, 200)));
    link(
        &mut service,
        b"/work/link",
        b"/work/link-copy",
        0,
        RenameAnchors::default(),
    )
    .unwrap();
    let linked = disk
        .path_to_inode(
            "/work/link-copy".try_into().unwrap(),
            FollowSymlinks::ExcludeFinalComponent,
        )
        .unwrap();
    assert_eq!(linked.index, original.index);
    assert_eq!(
        times(&linked),
        [original_times[0], original_times[1], (100, 200)]
    );
    assert_eq!(status(&mut service, file), before);
    set_clock(Ok(time(101, 201)));
    link(
        &mut service,
        b"/work/link",
        b"/work/target-copy",
        wire::LINK_AT_FOLLOW_SOURCE,
        RenameAnchors::default(),
    )
    .unwrap();
    assert_eq!(
        status_times(status(&mut service, file)),
        [(-1, 11), (2_147_483_648, 22), (101, 201)]
    );
    assert_eq!(
        times(
            &disk
                .path_to_inode(
                    "/work/link".try_into().unwrap(),
                    FollowSymlinks::ExcludeFinalComponent
                )
                .unwrap()
        )[2],
        (100, 200)
    );
}

#[test]
fn mounted_links_stay_on_their_volume_and_cross_volume_links_cannot_read_the_clock() {
    let (root, _disk, mut service) = metadata_fixture();
    let (_fixture, mounted, _) = metadata_fixture();
    service.mount_volume(b"/system", mounted.clone()).unwrap();
    let bytes = root.image.0.lock().unwrap().clone();
    set_clock(Ok(time(300, 400)));
    link(
        &mut service,
        b"/system/work/target",
        b"/system/work/new",
        0,
        RenameAnchors::default(),
    )
    .unwrap();
    assert_eq!(calls(), 1);
    assert_eq!(*root.image.0.lock().unwrap(), bytes);
    let inode = mounted
        .path_to_inode("/work/new".try_into().unwrap(), FollowSymlinks::All)
        .unwrap();
    assert_eq!(times(&inode), [(-1, 11), (2_147_483_648, 22), (300, 400)]);
    set_clock(Err(5));
    assert_eq!(
        link(
            &mut service,
            b"/system/work/target",
            b"/work/cross",
            0,
            RenameAnchors::default()
        ),
        Err(18)
    );
    assert_eq!(calls(), 0);
}
