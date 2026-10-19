use super::*;
use std::cell::RefCell;

#[path = "truncate_timestamps.rs"]
mod truncate;

#[path = "write_timestamps.rs"]
mod write;

#[path = "creation_timestamps.rs"]
mod creation;

#[path = "read_timestamps.rs"]
mod read;

#[path = "link_timestamps.rs"]
mod link;

#[path = "unlink_timestamps.rs"]
mod unlink;

#[path = "rename_timestamps.rs"]
mod rename;

#[path = "sticky_permissions.rs"]
mod sticky;

thread_local! {
    static CLOCK: RefCell<(Result<Time, i32>, usize)> = const {
        RefCell::new((Ok(Time { seconds: 10, nanoseconds: 20 }), 0))
    };
}

fn clock() -> Result<Time, i32> {
    CLOCK.with_borrow_mut(|state| {
        state.1 += 1;
        state.0
    })
}
fn set_clock(value: Result<Time, i32>) {
    CLOCK.with_borrow_mut(|state| *state = (value, 0));
}
fn calls() -> usize {
    CLOCK.with_borrow(|state| state.1)
}

fn metadata_fixture() -> (Fixture, Ext4, FilesystemService) {
    let (fixture, disk, _) = fixture();
    let mut inode = disk
        .path_to_inode("/work/target".try_into().unwrap(), FollowSymlinks::All)
        .unwrap();
    inode
        .set_signed_timestamps(
            Some(time(-1, 11)),
            Some(time(2_147_483_648, 22)),
            Some(time(3, 33)),
        )
        .unwrap();
    inode.write(&disk).unwrap();
    let mut service = FilesystemService::new_with_clock(disk.clone(), clock);
    service
        .configure_memory_updates(Box::new(unmapped_updates::UnmappedUpdates))
        .unwrap();
    set_clock(Ok(time(10, 20)));
    (fixture, disk, service)
}

fn mode_request(opcode: u16, flags: u32, mode: u32) -> wire::Header {
    wire::Header {
        mode,
        ..request(opcode, flags)
    }
}
fn owner_request(opcode: u16, flags: u32, uid: u32, gid: u32) -> wire::Header {
    wire::Header {
        node_id: u64::from(uid) | (u64::from(gid) << 32),
        ..request(opcode, flags)
    }
}

#[test]
fn chmod_and_chown_commit_ctime_with_metadata_and_refresh_all_descriptions() {
    let (_fixture, disk, mut service) = metadata_fixture();
    let first = open(&mut service, b"/work/target", false);
    let second = open(&mut service, b"/work/target", false);
    let directory = open(&mut service, b"/work", true);
    service
        .chmod_handle(
            mode_request(wire::OP_CHMOD_HANDLE, 0, 0o2640),
            first,
            credentials(1001, 77, &[]),
        )
        .unwrap();
    assert_eq!(calls(), 1);
    assert_eq!(
        status_times(status(&mut service, first)),
        [(-1, 11), (2_147_483_648, 22), (10, 20)]
    );
    assert_eq!(status(&mut service, first), status(&mut service, second));
    assert_eq!(status(&mut service, first).mode & 0o7777, 0o2640);
    set_clock(Ok(time(11, 21)));
    service
        .chown_handle(
            owner_request(wire::OP_CHOWN_HANDLE, 0, 1002, 88),
            first,
            credentials(0, 0, &[]),
        )
        .unwrap();
    let updated = status(&mut service, second);
    assert_eq!((updated.uid, updated.gid), (1002, 88));
    assert_eq!(updated.mode & 0o6000, 0);
    assert_eq!(
        status_times(updated),
        [(-1, 11), (2_147_483_648, 22), (11, 21)]
    );
    assert_eq!(calls(), 1);
    set_clock(Ok(time(12, 22)));
    service
        .chmod_at(
            mode_request(wire::OP_CHMOD_AT, wire::CHMOD_AT_BASE_ATTACHED, 0o600),
            b"target",
            PathAnchors {
                root_open_id: None,
                base_open_id: Some(directory),
            },
            credentials(1002, 88, &[]),
        )
        .unwrap();
    assert_eq!(status_times(status(&mut service, first))[2], (12, 22));
    set_clock(Ok(time(13, 23)));
    service
        .chown_at(
            owner_request(wire::OP_CHOWN_AT, wire::CHOWN_AT_BASE_ATTACHED, 1001, 77),
            b"target",
            PathAnchors {
                root_open_id: None,
                base_open_id: Some(directory),
            },
            credentials(0, 0, &[]),
        )
        .unwrap();
    assert_eq!(
        status_times(status(&mut service, second)),
        [(-1, 11), (2_147_483_648, 22), (13, 23)]
    );
    let persisted = disk
        .path_to_inode("/work/target".try_into().unwrap(), FollowSymlinks::All)
        .unwrap();
    assert_eq!(times(&persisted), [(-1, 11), (2_147_483_648, 22), (13, 23)]);
}

#[test]
fn failed_clock_or_unrepresentable_time_cannot_partially_change_mode_or_ownership() {
    let (fixture, _disk, mut service) = metadata_fixture();
    let file = open(&mut service, b"/work/target", false);
    let before = status(&mut service, file);
    let bytes = fixture.image.0.lock().unwrap().clone();
    for (time, expected) in [
        (Err(11), 11),
        (Err(13), 13),
        (Err(5), 5),
        (Ok(time(i64::MAX, 0)), 75),
        (Ok(time(1, 1_000_000_000)), 22),
    ] {
        set_clock(time);
        assert_eq!(
            service
                .chmod_handle(
                    mode_request(wire::OP_CHMOD_HANDLE, 0, 0o777),
                    file,
                    credentials(1001, 77, &[])
                )
                .err(),
            Some(expected)
        );
        assert_eq!(calls(), 1);
        assert_eq!(status(&mut service, file), before);
        set_clock(time);
        assert_eq!(
            service
                .chown_handle(
                    owner_request(wire::OP_CHOWN_HANDLE, 0, 1002, 88),
                    file,
                    credentials(0, 0, &[])
                )
                .err(),
            Some(expected)
        );
        assert_eq!(calls(), 1);
        assert_eq!(status(&mut service, file), before);
        assert_eq!(*fixture.image.0.lock().unwrap(), bytes);
    }
}

#[test]
fn denied_permissions_readonly_and_immutable_inodes_do_not_read_the_clock() {
    let (fixture, disk, mut service) = metadata_fixture();
    let file = open(&mut service, b"/work/target", false);
    set_clock(Err(5));
    assert_eq!(
        service
            .chmod_handle(
                mode_request(wire::OP_CHMOD_HANDLE, 0, 0o777),
                file,
                credentials(2002, 0, &[])
            )
            .err(),
        Some(1)
    );
    assert_eq!(
        service
            .chown_handle(
                owner_request(wire::OP_CHOWN_HANDLE, 0, 1002, 88),
                file,
                credentials(2002, 0, &[])
            )
            .err(),
        Some(1)
    );
    assert_eq!(calls(), 0);
    let mut inode = disk
        .path_to_inode("/work/target".try_into().unwrap(), FollowSymlinks::All)
        .unwrap();
    inode.set_flags(inode.flags() | InodeFlags::IMMUTABLE);
    inode.write(&disk).unwrap();
    assert_eq!(
        service
            .chmod_handle(
                mode_request(wire::OP_CHMOD_HANDLE, 0, 0o777),
                file,
                credentials(0, 0, &[])
            )
            .err(),
        Some(1)
    );
    assert_eq!(
        service
            .chown_handle(
                owner_request(wire::OP_CHOWN_HANDLE, 0, 1002, 88),
                file,
                credentials(0, 0, &[])
            )
            .err(),
        Some(1)
    );
    assert_eq!(calls(), 0);
    let readonly = Ext4::load(Box::new(fixture.image.clone())).unwrap();
    let mut service = FilesystemService::new_with_clock(readonly, clock);
    let file = open(&mut service, b"/work/target", false);
    assert_eq!(
        service
            .chmod_handle(
                mode_request(wire::OP_CHMOD_HANDLE, 0, 0o777),
                file,
                credentials(0, 0, &[])
            )
            .err(),
        Some(30)
    );
    assert_eq!(
        service
            .chown_handle(
                owner_request(wire::OP_CHOWN_HANDLE, 0, 1002, 88),
                file,
                credentials(0, 0, &[])
            )
            .err(),
        Some(30)
    );
    assert_eq!(calls(), 0);
}

#[test]
fn retained_unlinked_handles_and_nofollow_symlinks_update_the_selected_inode_only() {
    let (_fixture, disk, mut service) = metadata_fixture();
    let file = open(&mut service, b"/work/target", false);
    let link_before = disk
        .path_to_inode(
            "/work/link".try_into().unwrap(),
            FollowSymlinks::ExcludeFinalComponent,
        )
        .unwrap();
    let original_times = times(&link_before);
    set_clock(Ok(time(44, 55)));
    service
        .chown_at(
            owner_request(wire::OP_CHOWN_AT, wire::CHOWN_AT_NOFOLLOW, 1002, 88),
            b"/work/link",
            PathAnchors::default(),
            credentials(0, 0, &[]),
        )
        .unwrap();
    let link_after = disk
        .path_to_inode(
            "/work/link".try_into().unwrap(),
            FollowSymlinks::ExcludeFinalComponent,
        )
        .unwrap();
    assert_eq!(
        times(&link_after),
        [original_times[0], original_times[1], (44, 55)]
    );
    assert_eq!(status_times(status(&mut service, file))[2], (3, 33));
    service
        .unlink_at(
            request(wire::OP_UNLINK_AT, 0),
            b"/work/target",
            PathAnchors::default(),
            credentials(1001, 77, &[]),
        )
        .unwrap();
    set_clock(Ok(time(45, 56)));
    service
        .chmod_handle(
            mode_request(wire::OP_CHMOD_HANDLE, 0, 0o600),
            file,
            credentials(1001, 77, &[]),
        )
        .unwrap();
    assert_eq!(
        status_times(status(&mut service, file)),
        [(-1, 11), (2_147_483_648, 22), (45, 56)]
    );
}

#[test]
fn metadata_writes_use_the_mounted_volume_and_do_not_touch_the_root_image() {
    let (fixture, _root_disk, mut service) = metadata_fixture();
    let (_mounted, mounted, _) = metadata_fixture();
    service.mount_volume(b"/system", mounted.clone()).unwrap();
    let file = open(&mut service, b"/system/work/target", false);
    let root_before = fixture.image.0.lock().unwrap().clone();
    set_clock(Ok(time(77, 88)));
    service
        .chmod_at(
            mode_request(wire::OP_CHMOD_AT, 0, 0o640),
            b"/system/work/target",
            PathAnchors::default(),
            credentials(1001, 77, &[]),
        )
        .unwrap();
    assert_eq!(status_times(status(&mut service, file))[2], (77, 88));
    let inode = mounted
        .path_to_inode("/work/target".try_into().unwrap(), FollowSymlinks::All)
        .unwrap();
    assert_eq!(times(&inode)[2], (77, 88));
    assert_eq!(*fixture.image.0.lock().unwrap(), root_before);
}
