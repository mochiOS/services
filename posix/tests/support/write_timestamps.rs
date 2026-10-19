use super::*;
use ext4plus::file::File;

#[test]
fn sequential_positioned_append_and_bounded_writes_commit_times_without_changing_atime() {
    let (_fixture, _disk, mut service) = metadata_fixture();
    let file = open(&mut service, b"/work/target", false);
    let other = open(&mut service, b"/work/target", false);
    for (step, positioned) in [false, true, false].into_iter().enumerate() {
        set_clock(Ok(time(60 + step as i64, 70)));
        if positioned {
            assert_eq!(service.provider_write_at(file, 1, b"x"), Ok(1));
            assert_eq!(
                service.provider_seek(file, 0, mnu_abi::HANDLE_SEEK_CURRENT),
                Ok(1)
            );
        } else {
            assert_eq!(service.provider_write(file, b"y"), Ok(1));
        }
        assert_eq!(calls(), 1);
        assert_eq!(
            status_times(status(&mut service, other)),
            [(-1, 11), (60 + step as i64, 70), (60 + step as i64, 70)]
        );
    }
    let append = service
        .open_at(
            request(wire::OP_OPEN_AT, wire::OPEN_AT_WRITE | wire::OPEN_AT_APPEND),
            b"/work/target",
            PathAnchors::default(),
            credentials(1001, 77, &[]),
        )
        .unwrap()
        .header
        .open_id;
    set_clock(Ok(time(63, 71)));
    assert_eq!(
        service.provider_write_bounded(append, b"1234", 6),
        Ok((2, 4))
    );
    assert_eq!(status(&mut service, other).size, 6);
    assert_eq!(
        status_times(status(&mut service, other)),
        [(-1, 11), (63, 71), (63, 71)]
    );
    set_clock(Err(5));
    assert!(service.provider_write_bounded(append, b"z", 6).is_err());
    assert_eq!(calls(), 0);
    assert_eq!(service.provider_write(file, b""), Ok(0));
    assert_eq!(service.provider_write_at(file, u64::MAX, b""), Ok(0));
    assert_eq!(calls(), 0);
}

#[test]
fn invalid_clock_range_permissions_and_empty_writes_do_not_mutate_backing() {
    let (fixture, disk, mut service) = metadata_fixture();
    let file = open(&mut service, b"/work/target", false);
    let bytes = fixture.image.0.lock().unwrap().clone();
    let before = status(&mut service, file);
    for (clock, expected) in [
        (Err(11), 11),
        (Err(13), 13),
        (Err(5), 5),
        (Ok(time(i64::MAX, 0)), 75),
        (Ok(time(1, 1_000_000_000)), 22),
    ] {
        set_clock(clock);
        assert_eq!(service.provider_write(file, b"x"), Err(expected));
        assert_eq!(calls(), 1);
        set_clock(clock);
        assert_eq!(service.provider_write_at(file, 0, b"x"), Err(expected));
        assert_eq!(calls(), 1);
        assert_eq!(status(&mut service, file), before);
        assert_eq!(*fixture.image.0.lock().unwrap(), bytes);
    }
    set_clock(Err(5));
    assert_eq!(service.provider_write_at(file, u64::MAX, b"xx"), Err(27));
    assert_eq!(calls(), 0);
    let mut inode = disk
        .path_to_inode("/work/target".try_into().unwrap(), FollowSymlinks::All)
        .unwrap();
    inode.set_flags(inode.flags() | InodeFlags::IMMUTABLE);
    inode.write(&disk).unwrap();
    assert_eq!(service.provider_write(file, b"x"), Err(1));
    assert_eq!(calls(), 0);
    let readonly = Ext4::load(Box::new(fixture.image.clone())).unwrap();
    let mut service = FilesystemService::new_with_clock(readonly, clock);
    let file = open(&mut service, b"/work/target", false);
    assert_eq!(service.provider_write_at(file, 0, b"x"), Err(30));
    assert_eq!(calls(), 0);
}

#[derive(Clone)]
struct Fault {
    image: Image,
    fail: Arc<Mutex<Option<u64>>>,
    attempts: Arc<Mutex<Vec<u64>>>,
}
impl Ext4Read for Fault {
    fn read(&self, offset: u64, output: &mut [u8]) -> Result<(), Box<dyn Error + Send + Sync>> {
        self.image.read(offset, output)
    }
}
impl Ext4Write for Fault {
    fn flush(&self) -> Result<(), Box<dyn Error + Send + Sync>> {
        Ok(())
    }
    fn write(&self, offset: u64, bytes: &[u8]) -> Result<(), Box<dyn Error + Send + Sync>> {
        self.attempts.lock().unwrap().push(offset);
        if *self.fail.lock().unwrap() == Some(offset) {
            return Err("injected backing failure".into());
        }
        self.image.write(offset, bytes)
    }
}

fn populated(inode_size: usize) -> (Fixture, Fault, FilesystemService, Vec<u64>) {
    let fixture = Fixture::create(inode_size, None, true);
    let disk = fixture.load();
    let inode = disk
        .path_to_inode("/work/target".try_into().unwrap(), FollowSymlinks::All)
        .unwrap();
    let mut file = File::open_inode(&disk, inode).unwrap();
    let data = [0x11; 4096];
    let mut done = 0;
    while done < data.len() {
        done += file.write_bytes_at(&data[done..], done as u64).unwrap();
    }
    file.inode_mut()
        .set_signed_timestamps(Some(time(-1, 0)), Some(time(2, 0)), Some(time(3, 0)))
        .unwrap();
    file.inode_mut().write(&disk).unwrap();
    let output = Command::new("debugfs")
        .args(["-R", "blocks /work/target"])
        .arg(fixture.save())
        .output()
        .unwrap();
    assert!(output.status.success());
    let blocks: Vec<u64> = String::from_utf8(output.stdout)
        .unwrap()
        .split_whitespace()
        .map(|block| block.parse::<u64>().unwrap() * 1024)
        .collect();
    assert_eq!(blocks.len(), 4);
    let fault = Fault {
        image: fixture.image.clone(),
        fail: Arc::new(Mutex::new(None)),
        attempts: Arc::new(Mutex::new(Vec::new())),
    };
    let disk =
        Ext4::load_with_writer(Box::new(fault.clone()), Some(Box::new(fault.clone()))).unwrap();
    let mut service = FilesystemService::new_with_clock(disk, clock);
    service
        .configure_memory_updates(Box::new(unmapped_updates::UnmappedUpdates))
        .unwrap();
    (fixture, fault, service, blocks)
}

#[test]
fn actual_extent_and_block_map_failures_preserve_reported_prefix_cursor_and_committed_times() {
    for size in [128, 256] {
        for mode in 0..3 {
            let (_fixture, fault, mut service, blocks) = populated(size);
            let file = open(&mut service, b"/work/target", false);
            service
                .provider_seek(file, 17, mnu_abi::HANDLE_SEEK_START)
                .unwrap();
            *fault.fail.lock().unwrap() = Some(blocks[1]);
            set_clock(Ok(time(100, 0)));
            let payload = [0x22; 3072];
            let result = match mode {
                0 => service.provider_write(file, &payload),
                1 => service.provider_write_at(file, 17, &payload),
                _ => {
                    let reply = service.handle(
                        wire::Header {
                            open_id: file,
                            offset: 17,
                            ..request(wire::OP_WRITE, 0)
                        },
                        &payload,
                    );
                    assert_eq!(reply.header.status, 0);
                    Ok(reply.header.offset as usize)
                }
            };
            assert_eq!(result, Ok(1007));
            assert_eq!(calls(), 1);
            assert_eq!(
                service.provider_seek(file, 0, mnu_abi::HANDLE_SEEK_CURRENT),
                Ok(if mode == 0 { 1024 } else { 17 })
            );
            assert_eq!(
                status_times(status(&mut service, file)),
                [(-1, 0), (100, 0), (100, 0)]
            );
            let data = service.provider_read_at(file, 0, 4096).unwrap();
            assert_eq!(&data[..17], &[0x11; 17]);
            assert_eq!(&data[17..1024], &[0x22; 1007]);
            assert_eq!(&data[1024..], &[0x11; 3072]);
            let attempts = fault.attempts.lock().unwrap();
            assert_eq!(
                attempts
                    .iter()
                    .filter(|&&offset| offset == blocks[1])
                    .count(),
                1
            );
            assert!(!attempts.contains(&blocks[2]));
        }
    }
}

#[test]
fn block_map_overwrite_and_legacy_large_write_persist_times_without_advancing_positioned_cursor() {
    for size in [128, 256] {
        let (_fixture, _fault, mut service, _) = populated(size);
        let file = open(&mut service, b"/work/target", false);
        set_clock(Ok(time(101, 123)));
        assert_eq!(service.provider_write_at(file, 0, b"x"), Ok(1));
        let nanos = if size == 128 { 0 } else { 123 };
        assert_eq!(
            status_times(status(&mut service, file)),
            [(-1, 0), (101, nanos), (101, nanos)]
        );
        set_clock(Ok(time(102, 124)));
        let reply = service.handle(
            wire::Header {
                open_id: file,
                offset: 0,
                ..request(wire::OP_WRITE, 0)
            },
            &[0x33; 8192],
        );
        assert_eq!(reply.header.status, 0);
        assert_eq!(reply.header.offset, 8192);
        assert_eq!(calls(), 1);
        let nanos = if size == 128 { 0 } else { 124 };
        assert_eq!(
            status_times(status(&mut service, file)),
            [(-1, 0), (102, nanos), (102, nanos)]
        );
        assert_eq!(
            service.provider_seek(file, 0, mnu_abi::HANDLE_SEEK_CURRENT),
            Ok(0)
        );
    }
}
