use super::*;

fn resize(service: &mut FilesystemService, file: u64, length: u64) -> Result<(), i32> {
    service
        .truncate_handle(
            wire::Header {
                offset: length,
                ..request(wire::OP_TRUNCATE_HANDLE, 0)
            },
            file,
        )
        .map(|_| ())
}

#[test]
fn resize_commits_times_with_size_and_preserves_access_time_and_description_offsets() {
    let (_fixture, disk, mut service) = metadata_fixture();
    let first = open(&mut service, b"/work/target", false);
    let second = open(&mut service, b"/work/target", false);
    service
        .provider_seek(first, 19, mnu_abi::HANDLE_SEEK_START)
        .unwrap();
    service
        .provider_seek(second, 23, mnu_abi::HANDLE_SEEK_START)
        .unwrap();
    for (step, length) in [2, 3072, 3072, 0, 1].into_iter().enumerate() {
        let now = time(2_147_483_649 + step as i64, 123_456_789);
        set_clock(Ok(now));
        resize(&mut service, first, length).unwrap();
        assert_eq!(calls(), 1);
        let expected = [
            (-1, 11),
            (now.seconds, now.nanoseconds),
            (now.seconds, now.nanoseconds),
        ];
        let actual = status(&mut service, second);
        assert_eq!(actual.size, length);
        assert_eq!(status_times(actual), expected);
        assert_eq!(status(&mut service, first), actual);
        assert_eq!(
            service
                .provider_seek(first, 0, mnu_abi::HANDLE_SEEK_CURRENT)
                .unwrap(),
            19
        );
        assert_eq!(
            service
                .provider_seek(second, 0, mnu_abi::HANDLE_SEEK_CURRENT)
                .unwrap(),
            23
        );
        let inode = disk
            .path_to_inode("/work/target".try_into().unwrap(), FollowSymlinks::All)
            .unwrap();
        assert_eq!(inode.metadata().len(), length);
        assert_eq!(times(&inode), expected);
    }
    assert_eq!(service.provider_read_at(first, 0, 8).unwrap(), b"\0");
}

#[test]
fn legacy_block_map_truncation_commits_times_without_extended_inode_words() {
    let fixture = Fixture::create(128, None, true);
    let disk = fixture.load();
    let mut inode = disk
        .path_to_inode("/work/target".try_into().unwrap(), FollowSymlinks::All)
        .unwrap();
    inode
        .set_signed_timestamps(Some(time(-1, 0)), Some(time(2, 0)), Some(time(3, 0)))
        .unwrap();
    inode.write(&disk).unwrap();
    let mut service = FilesystemService::new_with_clock(disk.clone(), clock);
    service
        .configure_memory_updates(Box::new(unmapped_updates::UnmappedUpdates))
        .unwrap();
    let file = open(&mut service, b"/work/target", false);
    for (step, length) in [2, 6000, 6000, 0].into_iter().enumerate() {
        let now = time(2_147_483_644 + step as i64, 999_999_999);
        set_clock(Ok(now));
        resize(&mut service, file, length).unwrap();
        assert_eq!(calls(), 1);
        let inode = disk
            .path_to_inode("/work/target".try_into().unwrap(), FollowSymlinks::All)
            .unwrap();
        assert_eq!(inode.metadata().len(), length);
        assert_eq!(times(&inode), [(-1, 0), (now.seconds, 0), (now.seconds, 0)]);
        assert_eq!(status_times(status(&mut service, file)), times(&inode));
    }
    let bytes = fixture.image.0.lock().unwrap().clone();
    set_clock(Ok(time(2_147_483_648, 0)));
    assert_eq!(resize(&mut service, file, 2), Err(75));
    assert_eq!(*fixture.image.0.lock().unwrap(), bytes);
}

#[test]
fn pathname_and_open_truncate_use_the_same_timestamp_commit() {
    let (_fixture, _disk, mut service) = metadata_fixture();
    let file = open(&mut service, b"/work/target", false);
    let directory = open(&mut service, b"/work", true);
    set_clock(Ok(time(30, 40)));
    service
        .truncate_at(
            wire::Header {
                open_id: 3,
                ..request(wire::OP_TRUNCATE_AT, wire::TRUNCATE_AT_BASE_ATTACHED)
            },
            b"link",
            PathAnchors {
                root_open_id: None,
                base_open_id: Some(directory),
            },
            credentials(1001, 77, &[]),
        )
        .unwrap();
    assert_eq!(calls(), 1);
    assert_eq!(
        status_times(status(&mut service, file)),
        [(-1, 11), (30, 40), (30, 40)]
    );
    set_clock(Ok(time(31, 41)));
    let opened = service
        .open_at(
            request(
                wire::OP_OPEN_AT,
                wire::OPEN_AT_WRITE | wire::OPEN_AT_TRUNCATE,
            ),
            b"/work/target",
            PathAnchors::default(),
            credentials(1001, 77, &[]),
        )
        .unwrap()
        .header
        .open_id;
    assert_eq!(calls(), 1);
    assert_eq!(status(&mut service, file).size, 0);
    assert_eq!(status(&mut service, file), status(&mut service, opened));
    assert_eq!(
        status_times(status(&mut service, file)),
        [(-1, 11), (31, 41), (31, 41)]
    );
}

struct Updates {
    events: Arc<Mutex<Vec<&'static str>>>,
    fail: &'static str,
}
struct Update {
    events: Arc<Mutex<Vec<&'static str>>>,
    fail: &'static str,
}
impl filesystem_service::memory_updates::MemoryUpdates for Updates {
    fn prepare(
        &self,
        _: u64,
        _: u64,
        _: u64,
    ) -> Result<Box<dyn filesystem_service::memory_updates::Update>, i32> {
        self.events.lock().unwrap().push("prepare");
        if self.fail == "prepare" {
            return Err(5);
        }
        Ok(Box::new(Update {
            events: self.events.clone(),
            fail: self.fail,
        }))
    }
}
impl filesystem_service::memory_updates::Update for Update {
    fn begin(&mut self) -> Result<(), i32> {
        self.events.lock().unwrap().push("begin");
        if self.fail == "begin" { Err(5) } else { Ok(()) }
    }
    fn publish(&mut self) -> Result<(), i32> {
        self.events.lock().unwrap().push("publish");
        if self.fail == "publish" {
            Err(5)
        } else {
            Ok(())
        }
    }
}

#[test]
fn clock_and_timestamp_validation_fail_before_pager_admission_and_all_storage_writes() {
    let (fixture, _disk, mut service) = metadata_fixture();
    let events = Arc::new(Mutex::new(Vec::new()));
    service
        .configure_memory_updates(Box::new(Updates {
            events: events.clone(),
            fail: "",
        }))
        .unwrap();
    let file = open(&mut service, b"/work/target", false);
    let before = status(&mut service, file);
    let bytes = fixture.image.0.lock().unwrap().clone();
    for length in [0, 4, 8192] {
        for (clock, error) in [
            (Err(11), 11),
            (Err(13), 13),
            (Err(5), 5),
            (Ok(time(i64::MAX, 0)), 75),
            (Ok(time(0, 1_000_000_000)), 22),
        ] {
            set_clock(clock);
            assert_eq!(resize(&mut service, file, length), Err(error));
            assert_eq!(calls(), 1);
            assert!(events.lock().unwrap().is_empty());
            assert_eq!(status(&mut service, file), before);
            assert_eq!(*fixture.image.0.lock().unwrap(), bytes);
        }
    }
}

#[test]
fn permission_size_limit_and_immutable_rejections_do_not_read_clock_or_change_times() {
    let (fixture, disk, mut service) = metadata_fixture();
    let file = open(&mut service, b"/work/target", false);
    let before = status(&mut service, file);
    let bytes = fixture.image.0.lock().unwrap().clone();
    set_clock(Err(5));
    assert_eq!(
        service
            .truncate_handle(
                wire::Header {
                    offset: 8192,
                    node_id: 4096,
                    ..request(wire::OP_TRUNCATE_HANDLE, wire::TRUNCATE_GROWTH_BOUNDED)
                },
                file
            )
            .err(),
        Some(wire::ERROR_GROWTH_LIMIT)
    );
    assert_eq!(
        service
            .truncate_at(
                wire::Header {
                    open_id: 0,
                    ..request(wire::OP_TRUNCATE_AT, 0)
                },
                b"/work/target",
                PathAnchors::default(),
                credentials(2002, 88, &[])
            )
            .err(),
        Some(13)
    );
    assert_eq!(calls(), 0);
    assert_eq!(status(&mut service, file), before);
    assert_eq!(*fixture.image.0.lock().unwrap(), bytes);
    let mut inode = disk
        .path_to_inode("/work/target".try_into().unwrap(), FollowSymlinks::All)
        .unwrap();
    inode.set_flags(inode.flags() | InodeFlags::IMMUTABLE);
    inode.write(&disk).unwrap();
    assert_eq!(resize(&mut service, file, 0), Err(1));
    assert_eq!(calls(), 0);
    let readonly = Ext4::load(Box::new(fixture.image.clone())).unwrap();
    let mut service = FilesystemService::new_with_clock(readonly, clock);
    let file = open(&mut service, b"/work/target", false);
    assert_eq!(resize(&mut service, file, 0), Err(30));
    assert_eq!(calls(), 0);
}

#[test]
fn preparation_failure_does_not_persist_staged_times_and_publication_failure_is_not_replayed() {
    for fail in ["prepare", "begin", "publish"] {
        let (fixture, _disk, mut service) = metadata_fixture();
        let events = Arc::new(Mutex::new(Vec::new()));
        service
            .configure_memory_updates(Box::new(Updates {
                events: events.clone(),
                fail,
            }))
            .unwrap();
        let file = open(&mut service, b"/work/target", false);
        let before = status(&mut service, file);
        let bytes = fixture.image.0.lock().unwrap().clone();
        set_clock(Ok(time(50, 60)));
        assert_eq!(resize(&mut service, file, 2), Err(5));
        assert_eq!(calls(), 1);
        match fail {
            "prepare" => assert_eq!(*events.lock().unwrap(), ["prepare"]),
            "begin" => assert_eq!(*events.lock().unwrap(), ["prepare", "begin"]),
            _ => assert_eq!(*events.lock().unwrap(), ["prepare", "begin", "publish"]),
        }
        if fail == "publish" {
            let updated = status(&mut service, file);
            assert_eq!(updated.size, 2);
            assert_eq!(status_times(updated), [(-1, 11), (50, 60), (50, 60)]);
        } else {
            assert_eq!(status(&mut service, file), before);
            assert_eq!(*fixture.image.0.lock().unwrap(), bytes);
        }
    }
}

#[test]
fn mounted_and_retained_unlinked_files_keep_their_own_resize_timestamps() {
    let (root, _disk, mut service) = metadata_fixture();
    let (_fixture, mounted, _) = metadata_fixture();
    service.mount_volume(b"/system", mounted.clone()).unwrap();
    let file = open(&mut service, b"/system/work/target", false);
    let root_bytes = root.image.0.lock().unwrap().clone();
    set_clock(Ok(time(70, 80)));
    resize(&mut service, file, 2).unwrap();
    let inode = mounted
        .path_to_inode("/work/target".try_into().unwrap(), FollowSymlinks::All)
        .unwrap();
    assert_eq!(times(&inode), [(-1, 11), (70, 80), (70, 80)]);
    assert_eq!(*root.image.0.lock().unwrap(), root_bytes);
    service
        .unlink_at(
            request(wire::OP_UNLINK_AT, 0),
            b"/system/work/target",
            PathAnchors::default(),
            credentials(1001, 77, &[]),
        )
        .unwrap();
    set_clock(Ok(time(71, 81)));
    resize(&mut service, file, 8).unwrap();
    assert_eq!(
        status_times(status(&mut service, file)),
        [(-1, 11), (71, 81), (71, 81)]
    );
    assert_eq!(status(&mut service, file).size, 8);
}
