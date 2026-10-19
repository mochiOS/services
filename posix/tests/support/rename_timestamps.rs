use super::*;

fn rename(
    service: &mut FilesystemService,
    old: &[u8],
    new: &[u8],
    legacy: bool,
) -> Result<(), i32> {
    let mut payload = old.to_vec();
    payload.extend_from_slice(new);
    if legacy {
        let reply = service.handle(
            wire::Header {
                offset: old.len() as u64,
                request_id: 81,
                ..request(wire::OP_RENAME, 0)
            },
            &payload,
        );
        if reply.header.status == 0 {
            Ok(())
        } else {
            Err(-reply.header.status)
        }
    } else {
        service
            .rename_at(
                wire::Header {
                    mode: old.len() as u32,
                    request_id: 82,
                    ..request(wire::OP_RENAME_AT, 0)
                },
                &payload,
                RenameAnchors::default(),
                credentials(1001, 77, &[]),
            )
            .map(|_| ())
    }
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
fn file_rename_updates_both_parents_once_preserves_data_times_and_retains_replaced_descriptions() {
    for legacy in [false, true] {
        for replacing in [false, true] {
            let (_fixture, disk, mut service) = metadata_fixture();
            let source = open(&mut service, b"/work/target", false);
            let destination = if replacing {
                Some(open(&mut service, b"/hidden/target", false))
            } else {
                None
            };
            let old_parent = open(&mut service, b"/work", true);
            let new_parent = open(&mut service, b"/hidden", true);
            let old_time = status_times(status(&mut service, old_parent));
            let new_time = status_times(status(&mut service, new_parent));
            let destination_time = destination.map(|id| status_times(status(&mut service, id)));
            let new = if replacing {
                b"/hidden/target".as_slice()
            } else {
                b"/hidden/renamed".as_slice()
            };
            set_clock(Ok(time(2_147_483_649, 123_456_789)));
            rename(&mut service, b"/work/target", new, legacy).unwrap();
            assert_eq!(calls(), 1);
            assert_eq!(
                status_times(status(&mut service, source)),
                [(-1, 11), (2_147_483_648, 22), (2_147_483_649, 123_456_789)]
            );
            assert_eq!(
                status_times(status(&mut service, old_parent)),
                [
                    old_time[0],
                    (2_147_483_649, 123_456_789),
                    (2_147_483_649, 123_456_789)
                ]
            );
            assert_eq!(
                status_times(status(&mut service, new_parent)),
                [
                    new_time[0],
                    (2_147_483_649, 123_456_789),
                    (2_147_483_649, 123_456_789)
                ]
            );
            if let (Some(id), Some(old)) = (destination, destination_time) {
                assert_eq!(
                    status_times(status(&mut service, id)),
                    [old[0], old[1], (2_147_483_649, 123_456_789)]
                );
                assert_eq!(status(&mut service, id).link_count, 0);
                assert_eq!(service.provider_read(id, 7).unwrap(), b"private");
            }
            assert!(
                disk.path_to_inode("/work/target".try_into().unwrap(), FollowSymlinks::All)
                    .is_err()
            );
            assert_eq!(service.provider_read(source, 4).unwrap(), b"data");
        }
    }
}

#[test]
fn same_parent_directory_rename_preserves_latest_extent_map_link_counts_and_times() {
    for legacy in [false, true] {
        let (_fixture, disk, mut service) = metadata_fixture();
        mkdir(&mut service, b"/work/dir");
        let source = open(&mut service, b"/work/dir", true);
        let parent = open(&mut service, b"/work", true);
        let links = status(&mut service, parent).link_count;
        // Leave insufficient slack for the long destination; rename grows the
        // parent, then must not persist an older extent map while removing old.
        for i in 0..3 {
            let path = format!("/work/{i}{}", "f".repeat(239));
            let file = create(&mut service, path.as_bytes());
            service.provider_close(file).unwrap();
        }
        let original_size = status(&mut service, parent).size;
        let new = format!("/work/{}", "n".repeat(255));
        set_clock(Ok(time(100, 200)));
        rename(&mut service, b"/work/dir", new.as_bytes(), legacy).unwrap();
        assert_eq!(calls(), 1);
        assert!(status(&mut service, parent).size > original_size);
        assert_eq!(status(&mut service, parent).link_count, links);
        assert_eq!(
            status_times(status(&mut service, parent))[1..],
            [(100, 200); 2]
        );
        assert_eq!(status_times(status(&mut service, source))[2], (100, 200));
        let destination = disk
            .path_to_inode(new.as_str().try_into().unwrap(), FollowSymlinks::All)
            .unwrap();
        assert_eq!(
            destination.index.get(),
            status(&mut service, source).node_id as u32
        );
    }
}

#[test]
fn clock_range_and_immutable_errors_precede_every_public_and_private_namespace_write() {
    let (fixture, disk, mut service) = metadata_fixture();
    let source = open(&mut service, b"/work/target", false);
    let _held_destination = open(&mut service, b"/hidden/target", false);
    let before = fixture.image.0.lock().unwrap().clone();
    for legacy in [false, true] {
        for (clock, expected) in [
            (Err(11), 11),
            (Err(13), 13),
            (Err(5), 5),
            (Ok(time(i64::MAX, 0)), 75),
            (Ok(time(0, 1_000_000_000)), 22),
        ] {
            set_clock(clock);
            assert_eq!(
                rename(&mut service, b"/work/target", b"/hidden/target", legacy),
                Err(expected)
            );
            assert_eq!(calls(), 1);
            assert_eq!(*fixture.image.0.lock().unwrap(), before);
        }
    }
    let mut inode = disk
        .path_to_inode("/work/target".try_into().unwrap(), FollowSymlinks::All)
        .unwrap();
    inode.set_flags(inode.flags() | InodeFlags::IMMUTABLE);
    inode.write(&disk).unwrap();
    set_clock(Err(5));
    assert_eq!(
        rename(&mut service, b"/work/target", b"/work/new", false),
        Err(1)
    );
    assert_eq!(calls(), 0);
    assert_eq!(status(&mut service, source).link_count, 1);
}

#[test]
fn same_path_or_same_inode_is_a_timestamp_free_noop_and_missing_source_still_fails() {
    for legacy in [false, true] {
        let (fixture, _, mut service) = metadata_fixture();
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
        let before = fixture.image.0.lock().unwrap().clone();
        set_clock(Err(5));
        rename(&mut service, b"/work/target", b"/work/target", legacy).unwrap();
        rename(&mut service, b"/work/target", b"/work/other", legacy).unwrap();
        assert_eq!(
            rename(&mut service, b"/work/missing", b"/work/missing", legacy),
            Err(2)
        );
        assert_eq!(calls(), 0);
        assert_eq!(*fixture.image.0.lock().unwrap(), before);
    }
}

#[test]
fn directory_replacement_validates_clock_before_evacuating_held_file_pins() {
    for legacy in [false, true] {
        let (fixture, _, mut service) = metadata_fixture();
        mkdir(&mut service, b"/work/box");
        let held = create(&mut service, b"/work/box/target");
        let _file = create(&mut service, b"/work/source");
        rename(&mut service, b"/work/source", b"/work/box/target", legacy).unwrap();
        service
            .unlink_at(
                request(wire::OP_UNLINK_AT, 0),
                b"/work/box/target",
                PathAnchors::default(),
                credentials(1001, 77, &[]),
            )
            .unwrap();
        mkdir(&mut service, b"/work/source-dir");
        let source = open(&mut service, b"/work/source-dir", true);
        let replaced = open(&mut service, b"/work/box", true);
        let before = fixture.image.0.lock().unwrap().clone();
        let held_times = status_times(status(&mut service, held));
        set_clock(Err(5));
        assert_eq!(
            rename(&mut service, b"/work/source-dir", b"/work/box", legacy),
            Err(5)
        );
        assert_eq!(*fixture.image.0.lock().unwrap(), before);
        set_clock(Ok(time(300, 400)));
        rename(&mut service, b"/work/source-dir", b"/work/box", legacy).unwrap();
        assert_eq!(calls(), 1);
        assert_eq!(status_times(status(&mut service, source))[2], (300, 400));
        assert_eq!(status_times(status(&mut service, replaced))[2], (300, 400));
        assert_eq!(status(&mut service, replaced).link_count, 0);
        assert_eq!(status_times(status(&mut service, held)), held_times);
    }
}

#[test]
fn readonly_cross_volume_nonempty_and_cycle_failures_precede_clock_access() {
    let (fixture, _, mut service) = metadata_fixture();
    mkdir(&mut service, b"/work/dir");
    mkdir(&mut service, b"/work/dir/sub");
    mkdir(&mut service, b"/work/box");
    let _file = create(&mut service, b"/work/box/file");
    let before = fixture.image.0.lock().unwrap().clone();
    set_clock(Err(5));
    assert_eq!(
        rename(&mut service, b"/work/dir", b"/work/box", false),
        Err(39)
    );
    assert_eq!(
        rename(&mut service, b"/work/dir", b"/work/dir/sub/new", false),
        Err(22)
    );
    assert_eq!(calls(), 0);
    assert_eq!(*fixture.image.0.lock().unwrap(), before);
    let readonly = Ext4::load(Box::new(fixture.image.clone())).unwrap();
    let mut readonly = FilesystemService::new_with_clock(readonly, clock);
    assert_eq!(
        rename(&mut readonly, b"/work/target", b"/work/new", false),
        Err(30)
    );
    assert_eq!(calls(), 0);
    let (_mount, mounted, _) = metadata_fixture();
    service.mount_volume(b"/system", mounted).unwrap();
    set_clock(Err(5));
    assert_eq!(
        rename(&mut service, b"/work/target", b"/system/work/new", false),
        Err(18)
    );
    assert_eq!(calls(), 0);
}

#[derive(Clone)]
struct FailFinalParent {
    image: Image,
    offset: u64,
    writes: Arc<Mutex<usize>>,
}
impl Ext4Read for FailFinalParent {
    fn read(&self, offset: u64, output: &mut [u8]) -> Result<(), Box<dyn Error + Send + Sync>> {
        self.image.read(offset, output)
    }
}
impl Ext4Write for FailFinalParent {
    fn flush(&self) -> Result<(), Box<dyn Error + Send + Sync>> {
        Ok(())
    }
    fn write(&self, offset: u64, bytes: &[u8]) -> Result<(), Box<dyn Error + Send + Sync>> {
        if offset == self.offset {
            let mut count = self.writes.lock().unwrap();
            *count += 1;
            // Backup link and public source link have already saved the parent.
            if *count == 3 {
                return Err("injected final rename timestamp failure".into());
            }
        }
        self.image.write(offset, bytes)
    }
}

#[test]
fn final_timestamp_failure_keeps_replaced_inode_pinned_and_reclaimable() {
    let (fixture, disk, mut setup) = metadata_fixture();
    let _target = create(&mut setup, b"/work/destination");
    drop(setup);
    let parent = disk
        .path_to_inode("/work".try_into().unwrap(), FollowSymlinks::All)
        .unwrap();
    let table = {
        let bytes = fixture.image.0.lock().unwrap();
        u32::from_le_bytes(bytes[2056..2060].try_into().unwrap()) as u64 * 1024
    };
    let writes = Arc::new(Mutex::new(0));
    let adapter = FailFinalParent {
        image: fixture.image.clone(),
        offset: table + (u64::from(parent.index.get()) - 1) * fixture.inode_size as u64,
        writes: writes.clone(),
    };
    let backing =
        Ext4::load_with_writer(Box::new(adapter.clone()), Some(Box::new(adapter))).unwrap();
    let mut service = FilesystemService::new_with_clock(backing, clock);
    let source = open(&mut service, b"/work/target", false);
    let replaced = open(&mut service, b"/work/destination", false);
    set_clock(Ok(time(100, 200)));
    assert_eq!(
        rename(&mut service, b"/work/target", b"/work/destination", false),
        Err(5)
    );
    assert_eq!(*writes.lock().unwrap(), 3);
    assert_eq!(status(&mut service, replaced).link_count, 0);
    assert_eq!(status(&mut service, source).link_count, 1);
    assert_eq!(service.provider_read(source, 4).unwrap(), b"data");
    service.provider_close(replaced).unwrap();
    let directory =
        ext4plus::dir::Dir::open_inode(&disk, Inode::read(&disk, parent.index).unwrap()).unwrap();
    for entry in directory.read_dir().unwrap() {
        assert!(
            !entry
                .unwrap()
                .file_name()
                .as_ref()
                .starts_with(b".mochios-orphan-rename-")
        );
    }
}
