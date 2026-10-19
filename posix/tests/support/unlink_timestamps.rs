use super::*;

#[derive(Clone)]
struct FailParentWrite {
    image: Image,
    offset: u64,
}
impl Ext4Read for FailParentWrite {
    fn read(&self, offset: u64, output: &mut [u8]) -> Result<(), Box<dyn Error + Send + Sync>> {
        self.image.read(offset, output)
    }
}
impl Ext4Write for FailParentWrite {
    fn flush(&self) -> Result<(), Box<dyn Error + Send + Sync>> {
        Ok(())
    }
    fn write(&self, offset: u64, bytes: &[u8]) -> Result<(), Box<dyn Error + Send + Sync>> {
        if offset == self.offset {
            Err("injected public-parent inode write failure".into())
        } else {
            self.image.write(offset, bytes)
        }
    }
}

#[test]
fn late_parent_write_failure_does_not_lose_retention_ownership_after_name_removal() {
    let (fixture, disk, _) = metadata_fixture();
    let parent = disk
        .path_to_inode("/work".try_into().unwrap(), FollowSymlinks::All)
        .unwrap();
    let table = {
        let bytes = fixture.image.0.lock().unwrap();
        u32::from_le_bytes(bytes[2056..2060].try_into().unwrap()) as u64 * 1024
    };
    let adapter = FailParentWrite {
        image: fixture.image.clone(),
        offset: table + (u64::from(parent.index.get()) - 1) * fixture.inode_size as u64,
    };
    let backing =
        Ext4::load_with_writer(Box::new(adapter.clone()), Some(Box::new(adapter))).unwrap();
    let mut service = FilesystemService::new_with_clock(backing, clock);
    let file = open(&mut service, b"/work/target", false);
    set_clock(Ok(time(100, 200)));
    assert_eq!(unlink(&mut service, b"/work/target", false), Err(5));
    assert!(
        disk.path_to_inode("/work/target".try_into().unwrap(), FollowSymlinks::All)
            .is_err()
    );
    assert_eq!(status(&mut service, file).link_count, 0);
    assert_eq!(status_times(status(&mut service, file))[2], (100, 200));
    assert_eq!(service.provider_read(file, 4).unwrap(), b"data");
    service.provider_close(file).unwrap();
    let root = ext4plus::dir::Dir::open_inode(&disk, disk.read_root_inode().unwrap()).unwrap();
    for entry in root.read_dir().unwrap() {
        assert!(
            !entry
                .unwrap()
                .file_name()
                .as_ref()
                .starts_with(b".mochios-orphan-")
        );
    }
}

fn unlink(service: &mut FilesystemService, path: &[u8], directory: bool) -> Result<(), i32> {
    service
        .unlink_at(
            request(
                wire::OP_UNLINK_AT,
                if directory {
                    wire::UNLINK_AT_REMOVE_DIRECTORY
                } else {
                    0
                },
            ),
            path,
            PathAnchors::default(),
            credentials(1001, 77, &[]),
        )
        .map(|_| ())
}
fn mkdir(service: &mut FilesystemService, path: &[u8]) {
    service
        .mkdir_at(
            mode_request(wire::OP_MKDIR_AT, 0, 0o700),
            path,
            PathAnchors::default(),
            credentials(1001, 77, &[]),
        )
        .unwrap();
}
fn create(service: &mut FilesystemService, path: &[u8]) -> u64 {
    service
        .open_at(
            mode_request(
                wire::OP_OPEN_AT,
                wire::OPEN_AT_READ
                    | wire::OPEN_AT_WRITE
                    | wire::OPEN_AT_CREATE
                    | wire::OPEN_AT_EXCLUSIVE,
                0o600,
            ),
            path,
            PathAnchors::default(),
            credentials(1001, 77, &[]),
        )
        .unwrap()
        .header
        .open_id
}

#[test]
fn removing_last_public_name_stamps_retained_file_and_parent_without_touching_the_retention_root() {
    let (_fixture, disk, mut service) = metadata_fixture();
    let file = open(&mut service, b"/work/target", false);
    let parent = open(&mut service, b"/work", true);
    let root_before = disk.read_root_inode().unwrap();
    let parent_before = status(&mut service, parent);
    set_clock(Ok(time(2_147_483_649, 123_456_789)));
    unlink(&mut service, b"/work/target", false).unwrap();
    assert_eq!(calls(), 1);
    assert_eq!(status(&mut service, file).link_count, 0);
    assert_eq!(
        status_times(status(&mut service, file)),
        [(-1, 11), (2_147_483_648, 22), (2_147_483_649, 123_456_789)]
    );
    assert_eq!(
        status_times(status(&mut service, parent)),
        [
            status_times(parent_before)[0],
            (2_147_483_649, 123_456_789),
            (2_147_483_649, 123_456_789)
        ]
    );
    assert_eq!(times(&disk.read_root_inode().unwrap()), times(&root_before));
    assert!(
        disk.path_to_inode("/work/target".try_into().unwrap(), FollowSymlinks::All)
            .is_err()
    );
    set_clock(Ok(time(2_147_483_650, 123)));
    assert_eq!(service.provider_read(file, 4).unwrap(), b"data");
    assert_eq!(
        status_times(status(&mut service, file))[2],
        (2_147_483_649, 123_456_789)
    );
}

#[test]
fn unlink_with_another_hard_link_keeps_that_inode_and_updates_only_change_time() {
    let (_fixture, disk, mut service) = metadata_fixture();
    let file = open(&mut service, b"/work/target", false);
    service
        .link_at(
            wire::Header {
                mode: 12,
                ..request(wire::OP_LINK_AT, 0)
            },
            b"/work/target/work/other",
            RenameAnchors::default(),
            credentials(1001, 77, &[]),
        )
        .unwrap();
    set_clock(Ok(time(100, 200)));
    unlink(&mut service, b"/work/target", false).unwrap();
    assert_eq!(calls(), 1);
    assert_eq!(status(&mut service, file).link_count, 1);
    assert_eq!(
        status_times(status(&mut service, file)),
        [(-1, 11), (2_147_483_648, 22), (100, 200)]
    );
    let other = disk
        .path_to_inode("/work/other".try_into().unwrap(), FollowSymlinks::All)
        .unwrap();
    assert_eq!(times(&other)[2], (100, 200));
}

#[test]
fn rmdir_updates_retained_directory_ctime_and_parent_times_and_link_count() {
    let (_fixture, _disk, mut service) = metadata_fixture();
    mkdir(&mut service, b"/work/empty");
    let directory = open(&mut service, b"/work/empty", true);
    let parent = open(&mut service, b"/work", true);
    let child_before = status(&mut service, directory);
    let parent_before = status(&mut service, parent);
    set_clock(Ok(time(300, 400)));
    unlink(&mut service, b"/work/empty", true).unwrap();
    assert_eq!(calls(), 1);
    let child = status(&mut service, directory);
    assert_eq!(child.link_count, 0);
    assert_eq!(
        status_times(child),
        [
            status_times(child_before)[0],
            status_times(child_before)[1],
            (300, 400)
        ]
    );
    let parent_after = status(&mut service, parent);
    assert_eq!(parent_after.link_count + 1, parent_before.link_count);
    assert_eq!(
        status_times(parent_after),
        [status_times(parent_before)[0], (300, 400), (300, 400)]
    );
}

#[test]
fn clock_and_range_errors_preserve_names_references_and_all_storage_bytes() {
    let (fixture, _disk, mut service) = metadata_fixture();
    let file = open(&mut service, b"/work/target", false);
    mkdir(&mut service, b"/work/empty");
    let directory = open(&mut service, b"/work/empty", true);
    let bytes = fixture.image.0.lock().unwrap().clone();
    let file_before = status(&mut service, file);
    let directory_before = status(&mut service, directory);
    for (clock, expected) in [
        (Err(11), 11),
        (Err(13), 13),
        (Err(5), 5),
        (Ok(time(i64::MAX, 0)), 75),
        (Ok(time(0, 1_000_000_000)), 22),
    ] {
        for (path, is_dir) in [
            (b"/work/target".as_slice(), false),
            (b"/work/empty".as_slice(), true),
        ] {
            set_clock(clock);
            assert_eq!(unlink(&mut service, path, is_dir), Err(expected));
            assert_eq!(calls(), 1);
            assert_eq!(status(&mut service, file), file_before);
            assert_eq!(status(&mut service, directory), directory_before);
            assert_eq!(*fixture.image.0.lock().unwrap(), bytes);
        }
    }
}

#[test]
fn known_type_nonempty_immutable_and_readonly_errors_do_not_read_the_clock() {
    let (fixture, disk, mut service) = metadata_fixture();
    mkdir(&mut service, b"/work/nonempty");
    let child = create(&mut service, b"/work/nonempty/file");
    set_clock(Err(5));
    assert_eq!(unlink(&mut service, b"/work/nonempty", false), Err(21));
    assert_eq!(unlink(&mut service, b"/work/nonempty", true), Err(39));
    assert_eq!(unlink(&mut service, b"/work/target", true), Err(20));
    assert_eq!(calls(), 0);
    let mut target = disk
        .path_to_inode("/work/target".try_into().unwrap(), FollowSymlinks::All)
        .unwrap();
    target.set_flags(target.flags() | InodeFlags::IMMUTABLE);
    target.write(&disk).unwrap();
    let bytes = fixture.image.0.lock().unwrap().clone();
    assert_eq!(unlink(&mut service, b"/work/target", false), Err(1));
    assert_eq!(*fixture.image.0.lock().unwrap(), bytes);
    assert_eq!(calls(), 0);
    let readonly = Ext4::load(Box::new(fixture.image.clone())).unwrap();
    let mut readonly = FilesystemService::new_with_clock(readonly, clock);
    assert_eq!(
        unlink(&mut readonly, b"/work/nonempty/file", false),
        Err(30)
    );
    assert_eq!(calls(), 0);
    assert_eq!(status(&mut service, child).link_count, 1);
}

#[test]
fn failed_rmdir_clock_cannot_evacuate_private_rename_retention_links() {
    let (fixture, disk, mut service) = metadata_fixture();
    mkdir(&mut service, b"/work/box");
    let old_target = create(&mut service, b"/work/box/target");
    let source = create(&mut service, b"/work/source");
    service
        .rename_at(
            wire::Header {
                request_id: 100,
                mode: 12,
                ..request(wire::OP_RENAME_AT, 0)
            },
            b"/work/source/work/box/target",
            RenameAnchors::default(),
            credentials(1001, 77, &[]),
        )
        .unwrap();
    unlink(&mut service, b"/work/box/target", false).unwrap();
    let directory = open(&mut service, b"/work/box", true);
    let bytes = fixture.image.0.lock().unwrap().clone();
    let old_times = status_times(status(&mut service, old_target));
    set_clock(Err(5));
    assert_eq!(unlink(&mut service, b"/work/box", true), Err(5));
    assert_eq!(calls(), 1);
    assert_eq!(*fixture.image.0.lock().unwrap(), bytes);
    set_clock(Ok(time(500, 600)));
    unlink(&mut service, b"/work/box", true).unwrap();
    assert_eq!(calls(), 1);
    assert_eq!(status_times(status(&mut service, directory))[2], (500, 600));
    assert_eq!(status_times(status(&mut service, old_target)), old_times);
    assert_eq!(status(&mut service, source).link_count, 0);
    assert!(
        disk.path_to_inode("/work/box".try_into().unwrap(), FollowSymlinks::All)
            .is_err()
    );
}
