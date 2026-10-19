use super::*;

#[derive(Clone)]
struct RejectWrites(Image);
impl Ext4Read for RejectWrites {
    fn read(&self, offset: u64, output: &mut [u8]) -> Result<(), Box<dyn Error + Send + Sync>> {
        self.0.read(offset, output)
    }
}
impl Ext4Write for RejectWrites {
    fn flush(&self) -> Result<(), Box<dyn Error + Send + Sync>> {
        Ok(())
    }
    fn write(&self, _: u64, _: &[u8]) -> Result<(), Box<dyn Error + Send + Sync>> {
        Err("injected access-time write failure".into())
    }
}

#[test]
fn failed_access_time_storage_does_not_publish_a_success_or_advance_shared_offsets() {
    let (fixture, _, _) = metadata_fixture();
    let adapter = RejectWrites(fixture.image.clone());
    let disk = Ext4::load_with_writer(Box::new(adapter.clone()), Some(Box::new(adapter))).unwrap();
    let mut service = FilesystemService::new_with_clock(disk, clock);
    let file = open(&mut service, b"/work/target", false);
    let directory = open(&mut service, b"/work", true);
    let before = fixture.image.0.lock().unwrap().clone();
    set_clock(Ok(time(10, 20)));
    assert_eq!(service.provider_read(file, 2), Err(5));
    assert_eq!(
        service.provider_seek(file, 0, mnu_abi::HANDLE_SEEK_CURRENT),
        Ok(0)
    );
    let mut output = [0; 2];
    assert_eq!(service.provider_read_into(file, &mut output), Err(5));
    assert_eq!(
        service.provider_seek(file, 0, mnu_abi::HANDLE_SEEK_CURRENT),
        Ok(0)
    );
    assert_eq!(service.provider_read(directory, 4096), Err(5));
    assert_eq!(
        service.provider_seek(directory, 0, mnu_abi::HANDLE_SEEK_CURRENT),
        Ok(0)
    );
    assert_eq!(*fixture.image.0.lock().unwrap(), before);
}

#[test]
fn sequential_positioned_shared_and_legacy_reads_update_only_access_time() {
    let (_fixture, _disk, mut service) = metadata_fixture();
    let file = open(&mut service, b"/work/target", false);
    let other = open(&mut service, b"/work/target", false);
    set_clock(Ok(time(100, 200)));
    assert_eq!(
        service.provider_read_with_offset(file, 1).unwrap(),
        (b"d".to_vec(), 0)
    );
    assert_eq!(calls(), 1);
    assert_eq!(
        status_times(status(&mut service, other)),
        [(100, 200), (2_147_483_648, 22), (3, 33)]
    );
    set_clock(Ok(time(101, 201)));
    assert_eq!(service.provider_read_at(file, 2, 1).unwrap(), b"t");
    assert_eq!(calls(), 1);
    assert_eq!(
        service.provider_seek(file, 0, mnu_abi::HANDLE_SEEK_CURRENT),
        Ok(1)
    );
    let mut output = [0; 2];
    set_clock(Ok(time(102, 202)));
    assert_eq!(service.provider_read_into(file, &mut output), Ok((2, 1)));
    assert_eq!(&output, b"at");
    assert_eq!(calls(), 1);
    set_clock(Ok(time(-1, 999_999_999)));
    let reply = service.handle(
        wire::Header {
            open_id: file,
            offset: 0,
            ..request(wire::OP_READ, 4)
        },
        &[],
    );
    assert_eq!(reply.header.status, 0);
    assert_eq!(reply.payload, b"data");
    assert_eq!(calls(), 1);
    assert_eq!(
        service.provider_seek(file, 0, mnu_abi::HANDLE_SEEK_CURRENT),
        Ok(3)
    );
    assert_eq!(
        status_times(status(&mut service, other)),
        [(-1, 999_999_999), (2_147_483_648, 22), (3, 33)]
    );
}

#[test]
fn positive_requests_update_at_eof_but_empty_requests_have_no_timestamp_or_cursor_effect() {
    let (fixture, _disk, mut service) = metadata_fixture();
    let file = open(&mut service, b"/work/target", false);
    service
        .provider_seek(file, 19, mnu_abi::HANDLE_SEEK_START)
        .unwrap();
    set_clock(Ok(time(200, 300)));
    assert!(service.provider_read(file, 8).unwrap().is_empty());
    assert_eq!(calls(), 1);
    assert_eq!(
        status_times(status(&mut service, file)),
        [(200, 300), (2_147_483_648, 22), (3, 33)]
    );
    assert_eq!(
        service.provider_seek(file, 0, mnu_abi::HANDLE_SEEK_CURRENT),
        Ok(19)
    );
    let bytes = fixture.image.0.lock().unwrap().clone();
    set_clock(Err(5));
    assert!(service.provider_read(file, 0).unwrap().is_empty());
    assert!(
        service
            .provider_read_at(file, u64::MAX, 0)
            .unwrap()
            .is_empty()
    );
    assert_eq!(calls(), 0);
    assert_eq!(*fixture.image.0.lock().unwrap(), bytes);
    set_clock(Ok(time(201, 301)));
    assert!(service.provider_read_at(file, 20, 8).unwrap().is_empty());
    assert_eq!(calls(), 1);
    assert_eq!(status_times(status(&mut service, file))[0], (201, 301));
}

#[test]
fn invalid_clock_and_range_failures_do_not_consume_data_or_mutate_any_timestamp() {
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
        assert_eq!(service.provider_read(file, 1), Err(expected));
        assert_eq!(calls(), 1);
        set_clock(clock);
        let mut output = [0x55; 4];
        assert_eq!(service.provider_read_into(file, &mut output), Err(expected));
        assert_eq!(output, [0x55; 4]);
        assert_eq!(calls(), 1);
        assert_eq!(
            service.provider_seek(file, 0, mnu_abi::HANDLE_SEEK_CURRENT),
            Ok(0)
        );
        assert_eq!(status(&mut service, file), before);
        assert_eq!(*fixture.image.0.lock().unwrap(), bytes);
    }
    set_clock(Err(5));
    assert_eq!(service.provider_read_at(file, u64::MAX, 2), Err(27));
    assert_eq!(calls(), 0);
}

#[test]
fn immutable_and_readonly_reads_need_neither_clock_nor_metadata_write_authority() {
    let (fixture, disk, mut service) = metadata_fixture();
    let mut inode = disk
        .path_to_inode("/work/target".try_into().unwrap(), FollowSymlinks::All)
        .unwrap();
    inode.set_flags(inode.flags() | InodeFlags::IMMUTABLE);
    inode.write(&disk).unwrap();
    let bytes = fixture.image.0.lock().unwrap().clone();
    let file = open(&mut service, b"/work/target", false);
    set_clock(Err(13));
    assert_eq!(service.provider_read(file, 8).unwrap(), b"data");
    assert_eq!(calls(), 0);
    assert_eq!(*fixture.image.0.lock().unwrap(), bytes);
    inode.set_flags(inode.flags().difference(InodeFlags::IMMUTABLE));
    inode.write(&disk).unwrap();
    let bytes = fixture.image.0.lock().unwrap().clone();
    let readonly = Ext4::load(Box::new(fixture.image.clone())).unwrap();
    let mut service = FilesystemService::new_with_clock(readonly, clock);
    let file = open(&mut service, b"/work/target", false);
    let directory = open(&mut service, b"/work", true);
    assert_eq!(service.provider_read_at(file, 0, 8).unwrap(), b"data");
    assert!(!service.provider_read(directory, 4096).unwrap().is_empty());
    assert_eq!(calls(), 0);
    assert_eq!(*fixture.image.0.lock().unwrap(), bytes);
}

#[test]
fn old_inode_access_time_floors_subseconds_and_rejects_unrepresentable_dates_before_read() {
    let fixture = Fixture::create(128, None, true);
    let disk = fixture.load();
    let mut inode = disk
        .path_to_inode("/work/target".try_into().unwrap(), FollowSymlinks::All)
        .unwrap();
    inode
        .set_signed_timestamps(Some(time(-1, 0)), Some(time(2, 0)), Some(time(3, 0)))
        .unwrap();
    inode.write(&disk).unwrap();
    let mut service = FilesystemService::new_with_clock(disk, clock);
    let file = open(&mut service, b"/work/target", false);
    set_clock(Ok(time(2_147_483_647, 999_999_999)));
    assert_eq!(service.provider_read(file, 1).unwrap(), b"d");
    assert_eq!(
        status_times(status(&mut service, file)),
        [(2_147_483_647, 0), (2, 0), (3, 0)]
    );
    let bytes = fixture.image.0.lock().unwrap().clone();
    set_clock(Ok(time(2_147_483_648, 0)));
    assert_eq!(service.provider_read(file, 1), Err(75));
    assert_eq!(
        service.provider_seek(file, 0, mnu_abi::HANDLE_SEEK_CURRENT),
        Ok(1)
    );
    assert_eq!(*fixture.image.0.lock().unwrap(), bytes);
}

#[test]
fn directory_and_symlink_reads_stamp_only_the_actual_selected_inode() {
    let (_fixture, disk, mut service) = metadata_fixture();
    let directory = open(&mut service, b"/work", true);
    let mut inode = disk
        .path_to_inode("/work".try_into().unwrap(), FollowSymlinks::All)
        .unwrap();
    inode
        .set_signed_timestamps(Some(time(-1, 11)), Some(time(2, 22)), Some(time(3, 33)))
        .unwrap();
    inode.write(&disk).unwrap();
    set_clock(Ok(time(400, 500)));
    assert!(!service.provider_read(directory, 4096).unwrap().is_empty());
    assert_eq!(calls(), 1);
    assert_eq!(
        status_times(status(&mut service, directory)),
        [(400, 500), (2, 22), (3, 33)]
    );
    set_clock(Err(5));
    let before = status(&mut service, directory);
    assert!(service.provider_read(directory, 0).unwrap().is_empty());
    assert_eq!(status(&mut service, directory), before);
    assert_eq!(calls(), 0);
    let link_before = disk
        .path_to_inode(
            "/work/link".try_into().unwrap(),
            FollowSymlinks::ExcludeFinalComponent,
        )
        .unwrap();
    let link_times = times(&link_before);
    set_clock(Ok(time(401, 501)));
    let reply = service
        .readlink_at(
            request(wire::OP_READLINK_AT, 0),
            b"/work/link",
            PathAnchors::default(),
            credentials(1001, 77, &[]),
        )
        .unwrap();
    assert_eq!(reply.payload, b"target");
    assert_eq!(calls(), 1);
    let link_after = disk
        .path_to_inode(
            "/work/link".try_into().unwrap(),
            FollowSymlinks::ExcludeFinalComponent,
        )
        .unwrap();
    assert_eq!(
        times(&link_after),
        [(401, 501), link_times[1], link_times[2]]
    );
    assert_eq!(
        times(
            &disk
                .path_to_inode("/work/target".try_into().unwrap(), FollowSymlinks::All)
                .unwrap()
        )[0],
        (-1, 11)
    );
}

#[test]
fn mounted_and_unlinked_descriptions_update_the_retained_inode_not_its_former_path() {
    let (root, _disk, mut service) = metadata_fixture();
    let (_fixture, mounted, _) = metadata_fixture();
    service.mount_volume(b"/system", mounted.clone()).unwrap();
    let file = open(&mut service, b"/system/work/target", false);
    let bytes = root.image.0.lock().unwrap().clone();
    set_clock(Ok(time(599, 699)));
    service
        .unlink_at(
            request(wire::OP_UNLINK_AT, 0),
            b"/system/work/target",
            PathAnchors::default(),
            credentials(1001, 77, &[]),
        )
        .unwrap();
    set_clock(Ok(time(600, 700)));
    assert_eq!(service.provider_read(file, 4).unwrap(), b"data");
    assert_eq!(calls(), 1);
    assert_eq!(
        status_times(status(&mut service, file)),
        [(600, 700), (2_147_483_648, 22), (599, 699)]
    );
    assert_eq!(*root.image.0.lock().unwrap(), bytes);
}
