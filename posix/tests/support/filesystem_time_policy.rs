use super::*;
use ext4plus::FollowSymlinks;
use ext4plus::inode::{InodeFlags, InodeMode};
use filesystem_service::service::{FilesystemService, PathAnchors, RenameAnchors};
use mochios_filesystem_protocol::{
    self as wire, FileTimeUpdate as Update, TimestampUpdate as Field,
};

#[path = "unmapped_updates.rs"]
mod unmapped_updates;

fn credentials(uid: u32, gid: u32, groups: &[u32]) -> wire::Credentials {
    let mut bytes = [0; wire::CREDENTIALS_MAX_LEN];
    let length = wire::encode_credentials_payload(uid, gid, groups, &[], &mut bytes).unwrap();
    wire::decode_credentials_payload(&bytes[..length])
        .unwrap()
        .0
}

fn request(opcode: u16, flags: u32) -> wire::Header {
    wire::Header {
        opcode,
        flags,
        ..Default::default()
    }
}
fn update(access: Field, modification: Field) -> Update {
    Update {
        access,
        modification,
    }
}
fn explicit() -> Update {
    update(
        Field::Set {
            seconds: -1,
            nanoseconds: 123_456_789,
        },
        Field::Set {
            seconds: 2_147_483_648,
            nanoseconds: 987_654_321,
        },
    )
}
fn current() -> Update {
    update(Field::Now, Field::Now)
}
fn omit() -> Update {
    update(Field::Omit, Field::Omit)
}
fn now() -> Result<Time, i32> {
    Ok(time(1_234_567_890, 456_789_123))
}
fn never() -> Result<Time, i32> {
    panic!("clock must not be used")
}

fn fixture() -> (Fixture, Ext4, FilesystemService) {
    let fixture = Fixture::create(256, None, true);
    let disk = fixture.load();
    for (path, uid, mode) in [
        ("/", 0, 0o755),
        ("/work", 1001, 0o777),
        ("/work/target", 1001, 0o660),
        ("/hidden", 1001, 0o700),
    ] {
        let mut inode = disk
            .path_to_inode(path.try_into().unwrap(), FollowSymlinks::All)
            .unwrap();
        inode.set_uid(uid);
        inode.set_gid(77);
        inode
            .set_mode(InodeMode::from_bits_retain(
                (inode.mode().bits() & 0xf000) | mode,
            ))
            .unwrap();
        inode.write(&disk).unwrap();
    }
    let mut service = FilesystemService::new(disk.clone());
    service
        .configure_memory_updates(Box::new(unmapped_updates::UnmappedUpdates))
        .unwrap();
    (fixture, disk, service)
}

fn open(service: &mut FilesystemService, path: &[u8], directory: bool) -> u64 {
    service
        .open_at(
            request(
                wire::OP_OPEN_AT,
                wire::OPEN_AT_READ
                    | if directory {
                        wire::OPEN_AT_DIRECTORY
                    } else {
                        0
                    },
            ),
            path,
            PathAnchors::default(),
            credentials(0, 0, &[]),
        )
        .unwrap()
        .header
        .open_id
}

fn status(service: &mut FilesystemService, id: u64) -> wire::NodeStatus {
    let reply = service
        .stat_handle(request(wire::OP_STAT_HANDLE, 0), id)
        .unwrap();
    wire::decode_node_status(&reply.payload).unwrap()
}

fn status_times(status: wire::NodeStatus) -> [(i64, u32); 3] {
    [
        (status.access_time_seconds, status.access_time_nanoseconds),
        (
            status.modification_time_seconds,
            status.modification_time_nanoseconds,
        ),
        (status.change_time_seconds, status.change_time_nanoseconds),
    ]
}

#[test]
fn time_update_wire_is_explicit_bounded_canonical_and_pointer_free() {
    for access in [
        Field::Now,
        Field::Omit,
        Field::Set {
            seconds: i64::MIN,
            nanoseconds: 0,
        },
        Field::Set {
            seconds: i64::MAX,
            nanoseconds: 999_999_999,
        },
    ] {
        for modification in [
            Field::Now,
            Field::Omit,
            Field::Set {
                seconds: -1,
                nanoseconds: 1,
            },
        ] {
            let value = update(access, modification);
            let mut bytes = [0xaa; wire::TIME_UPDATE_LEN + 4];
            assert_eq!(wire::encode_time_update(value, &mut bytes).unwrap(), 32);
            bytes[32..].copy_from_slice(b"path");
            let (decoded, path) = wire::decode_time_update(&bytes).unwrap();
            assert_eq!(decoded, value);
            assert_eq!(path, b"path");
            for length in 0..32 {
                assert!(wire::decode_time_update(&bytes[..length]).is_err());
                let mut short = [0xcc; 32];
                assert!(wire::encode_time_update(value, &mut short[..length]).is_err());
                assert_eq!(short, [0xcc; 32]);
            }
        }
    }
    let mut bytes = [0xcc; 32];
    assert!(
        wire::encode_time_update(
            update(
                Field::Now,
                Field::Set {
                    seconds: 0,
                    nanoseconds: 1_000_000_000
                }
            ),
            &mut bytes
        )
        .is_err()
    );
    assert_eq!(bytes, [0xcc; 32]);
    wire::encode_time_update(current(), &mut bytes).unwrap();
    for field in [0, 16] {
        for tag in [3u32, u32::MAX] {
            let mut bad = bytes;
            bad[field..field + 4].copy_from_slice(&tag.to_le_bytes());
            assert!(wire::decode_time_update(&bad).is_err());
        }
        for offset in field + 4..field + 16 {
            let mut bad = bytes;
            bad[offset] = 1;
            assert!(wire::decode_time_update(&bad).is_err());
        }
    }
}

#[test]
fn permissions_distinguish_both_now_from_explicit_and_mixed_updates() {
    let (_fixture, _disk, mut service) = fixture();
    let id = open(&mut service, b"/work/target", false);
    // Different primary gid, but the owning supplementary group may write.
    service
        .set_times_handle(
            request(wire::OP_SET_TIMES_HANDLE, 0),
            id,
            credentials(2002, 88, &[77]),
            current(),
            now,
        )
        .unwrap();
    let current_time = now().unwrap();
    assert_eq!(
        status_times(status(&mut service, id)),
        [(current_time.seconds, current_time.nanoseconds); 3]
    );
    for denied in [
        explicit(),
        update(Field::Now, Field::Omit),
        update(Field::Omit, Field::Now),
    ] {
        let before = status(&mut service, id);
        assert_eq!(
            service
                .set_times_handle(
                    request(wire::OP_SET_TIMES_HANDLE, 0),
                    id,
                    credentials(2002, 88, &[77]),
                    denied,
                    never
                )
                .err(),
            Some(1)
        );
        assert_eq!(status(&mut service, id), before);
    }
    assert_eq!(
        service
            .set_times_handle(
                request(wire::OP_SET_TIMES_HANDLE, 0),
                id,
                credentials(2002, 88, &[]),
                current(),
                never
            )
            .err(),
        Some(13)
    );
    // An owner needs no write mode or writable OFD to set explicit dates.
    service
        .chmod_handle(
            wire::Header {
                mode: 0o400,
                ..request(wire::OP_CHMOD_HANDLE, 0)
            },
            id,
            credentials(1001, 88, &[]),
        )
        .unwrap();
    service
        .set_times_handle(
            request(wire::OP_SET_TIMES_HANDLE, 0),
            id,
            credentials(1001, 88, &[]),
            explicit(),
            now,
        )
        .unwrap();
    assert_eq!(
        status_times(status(&mut service, id)),
        [
            (-1, 123_456_789),
            (2_147_483_648, 987_654_321),
            (current_time.seconds, current_time.nanoseconds)
        ]
    );
}

#[test]
fn omit_preserves_ctime_and_needs_no_file_permission_but_still_checks_path_and_object() {
    let (_fixture, _disk, mut service) = fixture();
    let id = open(&mut service, b"/work/target", false);
    let before = status(&mut service, id);
    service
        .set_times_handle(
            request(wire::OP_SET_TIMES_HANDLE, 0),
            id,
            credentials(2002, 88, &[]),
            omit(),
            never,
        )
        .unwrap();
    assert_eq!(status(&mut service, id), before);
    service
        .set_times_at(
            request(wire::OP_SET_TIMES_AT, 0),
            b"/work/target",
            PathAnchors::default(),
            credentials(2002, 88, &[]),
            omit(),
            never,
        )
        .unwrap();
    assert_eq!(
        service
            .set_times_at(
                request(wire::OP_SET_TIMES_AT, 0),
                b"/hidden/target",
                PathAnchors::default(),
                credentials(2002, 88, &[]),
                omit(),
                never
            )
            .err(),
        Some(13)
    );
    assert_eq!(
        service
            .set_times_at(
                request(wire::OP_SET_TIMES_AT, 0),
                b"/missing",
                PathAnchors::default(),
                credentials(0, 0, &[]),
                omit(),
                never
            )
            .err(),
        Some(2)
    );
    assert_eq!(
        service
            .set_times_handle(
                request(wire::OP_SET_TIMES_HANDLE, 0),
                u64::MAX,
                credentials(0, 0, &[]),
                omit(),
                never
            )
            .err(),
        Some(9)
    );
}

#[test]
fn authority_and_validation_failures_do_not_read_time_or_mutate_storage() {
    let (fixture, _disk, mut service) = fixture();
    let id = open(&mut service, b"/work/target", false);
    let before = fixture.image.0.lock().unwrap().clone();
    let invalid = update(
        Field::Set {
            seconds: 0,
            nanoseconds: u32::MAX,
        },
        Field::Omit,
    );
    assert_eq!(
        service
            .set_times_handle(
                request(wire::OP_SET_TIMES_HANDLE, 1),
                id,
                credentials(0, 0, &[]),
                current(),
                never
            )
            .err(),
        Some(22)
    );
    assert_eq!(
        service
            .set_times_handle(
                request(wire::OP_SET_TIMES_HANDLE, 0),
                id,
                credentials(0, 0, &[]),
                invalid,
                never
            )
            .err(),
        Some(22)
    );
    for flags in [
        1 << 29,
        wire::SET_TIMES_AT_ROOT_ATTACHED,
        wire::SET_TIMES_AT_BASE_ATTACHED,
    ] {
        assert_eq!(
            service
                .set_times_at(
                    request(wire::OP_SET_TIMES_AT, flags),
                    b"/work/target",
                    PathAnchors::default(),
                    credentials(0, 0, &[]),
                    current(),
                    never
                )
                .err(),
            Some(22)
        );
    }
    for opcode in [wire::OP_SET_TIMES_AT, wire::OP_SET_TIMES_HANDLE] {
        // Neither a self-reported uid nor an inline open_id is an IPC Handle.
        let reply = service.handle(
            wire::Header {
                open_id: id,
                ..request(opcode, 0)
            },
            b"",
        );
        assert_eq!(reply.header.status, -22);
    }
    for rights in [
        0,
        mnu_abi::HANDLE_RIGHT_READ,
        mnu_abi::HANDLE_RIGHT_TRANSFER,
        mnu_abi::HANDLE_RIGHT_CONTROL,
        mnu_abi::HANDLE_RIGHT_WRITE | mnu_abi::HANDLE_RIGHT_TRANSFER,
    ] {
        assert_eq!(
            filesystem_service::handle_access::authorize(wire::OP_SET_TIMES_HANDLE, rights),
            Err(13)
        );
    }
    assert_eq!(
        filesystem_service::handle_access::authorize(
            wire::OP_SET_TIMES_HANDLE,
            mnu_abi::HANDLE_RIGHT_CONTROL | mnu_abi::HANDLE_RIGHT_TRANSFER
        ),
        Ok(())
    );
    assert_eq!(*fixture.image.0.lock().unwrap(), before);
}

#[test]
fn clock_and_range_errors_preserve_all_three_times_and_omit_preserves_one_field() {
    let (fixture, _disk, mut service) = fixture();
    let id = open(&mut service, b"/work/target", false);
    service
        .set_times_handle(
            request(wire::OP_SET_TIMES_HANDLE, 0),
            id,
            credentials(1001, 0, &[]),
            explicit(),
            now,
        )
        .unwrap();
    let before = status(&mut service, id);
    let disk_before = fixture.image.0.lock().unwrap().clone();
    assert_eq!(
        service
            .set_times_handle(
                request(wire::OP_SET_TIMES_HANDLE, 0),
                id,
                credentials(1001, 0, &[]),
                current(),
                || Err(5)
            )
            .err(),
        Some(5)
    );
    assert_eq!(
        service
            .set_times_handle(
                request(wire::OP_SET_TIMES_HANDLE, 0),
                id,
                credentials(1001, 0, &[]),
                update(
                    Field::Now,
                    Field::Set {
                        seconds: i64::MAX,
                        nanoseconds: 0
                    }
                ),
                now
            )
            .err(),
        Some(75)
    );
    assert_eq!(status(&mut service, id), before);
    assert_eq!(*fixture.image.0.lock().unwrap(), disk_before);
    let called = std::cell::Cell::new(0);
    service
        .set_times_handle(
            request(wire::OP_SET_TIMES_HANDLE, 0),
            id,
            credentials(1001, 0, &[]),
            update(Field::Omit, Field::Now),
            || {
                called.set(called.get() + 1);
                Ok(time(4, 5))
            },
        )
        .unwrap();
    assert_eq!(called.get(), 1);
    assert_eq!(
        status_times(status(&mut service, id)),
        [(-1, 123_456_789), (4, 5), (4, 5)]
    );
}

#[test]
fn permission_checks_reload_inode_instead_of_trusting_an_open_snapshot() {
    let (_fixture, disk, mut service) = fixture();
    let id = open(&mut service, b"/work/target", false);
    let mut inode = disk
        .path_to_inode("/work/target".try_into().unwrap(), FollowSymlinks::All)
        .unwrap();
    inode.set_uid(3003);
    inode
        .set_mode(InodeMode::from_bits_retain(0o100400))
        .unwrap();
    inode.write(&disk).unwrap();
    assert_eq!(
        service
            .set_times_handle(
                request(wire::OP_SET_TIMES_HANDLE, 0),
                id,
                credentials(1001, 77, &[]),
                explicit(),
                never
            )
            .err(),
        Some(1)
    );
    assert_eq!(
        service
            .set_times_handle(
                request(wire::OP_SET_TIMES_HANDLE, 0),
                id,
                credentials(2002, 77, &[]),
                current(),
                never
            )
            .err(),
        Some(13)
    );
    service
        .set_times_handle(
            request(wire::OP_SET_TIMES_HANDLE, 0),
            id,
            credentials(3003, 0, &[]),
            explicit(),
            now,
        )
        .unwrap();
}

#[test]
fn root_is_not_an_override_for_readonly_volumes_or_immutable_inodes() {
    let (fixture, disk, mut service) = fixture();
    let id = open(&mut service, b"/work/target", false);
    let mut inode = disk
        .path_to_inode("/work/target".try_into().unwrap(), FollowSymlinks::All)
        .unwrap();
    inode.set_flags(inode.flags() | InodeFlags::IMMUTABLE);
    inode.write(&disk).unwrap();
    assert_eq!(
        service
            .set_times_handle(
                request(wire::OP_SET_TIMES_HANDLE, 0),
                id,
                credentials(0, 0, &[]),
                explicit(),
                never
            )
            .err(),
        Some(1)
    );
    service
        .set_times_handle(
            request(wire::OP_SET_TIMES_HANDLE, 0),
            id,
            credentials(0, 0, &[]),
            omit(),
            never,
        )
        .unwrap();
    let readonly = Ext4::load(Box::new(fixture.image.clone())).unwrap();
    let mut readonly_service = FilesystemService::new(readonly);
    assert_eq!(
        readonly_service
            .set_times_at(
                request(wire::OP_SET_TIMES_AT, 0),
                b"/work/target",
                PathAnchors::default(),
                credentials(0, 0, &[]),
                explicit(),
                never
            )
            .err(),
        Some(30)
    );
    readonly_service
        .set_times_at(
            request(wire::OP_SET_TIMES_AT, 0),
            b"/work/target",
            PathAnchors::default(),
            credentials(2002, 0, &[]),
            omit(),
            never,
        )
        .unwrap();
    service.mount_devices(b"/dev", Default::default()).unwrap();
    assert_eq!(
        service
            .set_times_at(
                request(wire::OP_SET_TIMES_AT, 0),
                b"/dev/null",
                PathAnchors::default(),
                credentials(0, 0, &[]),
                current(),
                never
            )
            .err(),
        Some(30)
    );
    service
        .set_times_at(
            request(wire::OP_SET_TIMES_AT, 0),
            b"/dev/null",
            PathAnchors::default(),
            credentials(2002, 0, &[]),
            omit(),
            never,
        )
        .unwrap();
    let device = open(&mut service, b"/dev/null", false);
    service
        .set_times_handle(
            request(wire::OP_SET_TIMES_HANDLE, 0),
            device,
            credentials(2002, 0, &[]),
            omit(),
            never,
        )
        .unwrap();
}

#[test]
fn symlinks_anchors_and_unlinked_descriptions_keep_their_object_identity() {
    let (_fixture, disk, mut service) = fixture();
    let root = open(&mut service, b"/work", true);
    let first = open(&mut service, b"/work/target", false);
    let second = open(&mut service, b"/work/target", false);
    assert_eq!(service.provider_read(first, 2).unwrap(), b"da");
    service
        .set_times_at(
            request(wire::OP_SET_TIMES_AT, wire::SET_TIMES_AT_ROOT_ATTACHED),
            b"/link",
            PathAnchors {
                root_open_id: Some(root),
                base_open_id: None,
            },
            credentials(1001, 0, &[]),
            explicit(),
            now,
        )
        .unwrap();
    assert_eq!(
        status_times(status(&mut service, first))[0],
        (-1, 123_456_789)
    );
    service
        .set_times_at(
            request(
                wire::OP_SET_TIMES_AT,
                wire::SET_TIMES_AT_BASE_ATTACHED | wire::SET_TIMES_AT_NOFOLLOW,
            ),
            b"link",
            PathAnchors {
                root_open_id: None,
                base_open_id: Some(root),
            },
            credentials(0, 0, &[]),
            current(),
            || Ok(time(222, 333)),
        )
        .unwrap();
    let link = disk
        .path_to_inode(
            "/work/link".try_into().unwrap(),
            FollowSymlinks::ExcludeFinalComponent,
        )
        .unwrap();
    assert_eq!(times(&link), [(222, 333); 3]);
    assert_eq!(
        status_times(status(&mut service, second))[0],
        (-1, 123_456_789)
    );
    // An absolute path and .. remain confined to the explicitly attached root.
    assert_eq!(
        service
            .set_times_at(
                request(wire::OP_SET_TIMES_AT, wire::SET_TIMES_AT_ROOT_ATTACHED),
                b"/../hidden/target",
                PathAnchors {
                    root_open_id: Some(root),
                    base_open_id: None
                },
                credentials(0, 0, &[]),
                current(),
                never,
            )
            .err(),
        Some(2)
    );
    service
        .rename_at(
            wire::Header {
                mode: b"/work".len() as u32,
                ..request(wire::OP_RENAME_AT, 0)
            },
            b"/work/moved",
            RenameAnchors::default(),
            credentials(0, 0, &[]),
        )
        .unwrap();
    service
        .set_times_at(
            request(wire::OP_SET_TIMES_AT, wire::SET_TIMES_AT_BASE_ATTACHED),
            b"target",
            PathAnchors {
                root_open_id: None,
                base_open_id: Some(root),
            },
            credentials(1001, 0, &[]),
            current(),
            || Ok(time(444, 555)),
        )
        .unwrap();
    service
        .unlink_at(
            request(wire::OP_UNLINK_AT, wire::UNLINK_AT_BASE_ATTACHED),
            b"target",
            PathAnchors {
                root_open_id: None,
                base_open_id: Some(root),
            },
            credentials(1001, 0, &[]),
        )
        .unwrap();
    service
        .set_times_handle(
            request(wire::OP_SET_TIMES_HANDLE, 0),
            first,
            credentials(1001, 0, &[]),
            explicit(),
            now,
        )
        .unwrap();
    assert_eq!(service.provider_read(first, 2).unwrap(), b"ta");
    assert_eq!(
        status_times(status(&mut service, first)),
        status_times(status(&mut service, second))
    );
    assert_eq!(
        status_times(status(&mut service, second))[0],
        (-1, 123_456_789)
    );
    service.provider_close(first).unwrap();
    service
        .set_times_handle(
            request(wire::OP_SET_TIMES_HANDLE, 0),
            second,
            credentials(1001, 0, &[]),
            current(),
            now,
        )
        .unwrap();
}

#[test]
fn timestamp_mutations_use_the_resolved_volume_not_the_root_filesystem() {
    let (original, root_disk, mut service) = fixture();
    let (_mounted, mounted_disk, _) = fixture();
    service
        .mount_volume(b"/system", mounted_disk.clone())
        .unwrap();
    let root = open(&mut service, b"/work/target", false);
    let mounted = open(&mut service, b"/system/work/target", false);
    let before = original.image.0.lock().unwrap().clone();
    service
        .set_times_at(
            request(wire::OP_SET_TIMES_AT, 0),
            b"/system/work/target",
            PathAnchors::default(),
            credentials(1001, 0, &[]),
            explicit(),
            now,
        )
        .unwrap();
    let target = mounted_disk
        .path_to_inode("/work/target".try_into().unwrap(), FollowSymlinks::All)
        .unwrap();
    assert_eq!(times(&target)[0], (-1, 123_456_789));
    assert_eq!(*original.image.0.lock().unwrap(), before);
    let root_target = root_disk
        .path_to_inode("/work/target".try_into().unwrap(), FollowSymlinks::All)
        .unwrap();
    assert_ne!(times(&root_target)[0], times(&target)[0]);
    assert_ne!(
        status(&mut service, root).device,
        status(&mut service, mounted).device
    );
    service
        .set_times_handle(
            request(wire::OP_SET_TIMES_HANDLE, 0),
            mounted,
            credentials(1001, 0, &[]),
            current(),
            now,
        )
        .unwrap();
    assert_eq!(*original.image.0.lock().unwrap(), before);
}

#[test]
fn storage_failure_propagates_without_reporting_a_successful_metadata_update() {
    struct FailingWriter;
    impl Ext4Write for FailingWriter {
        fn flush(&self) -> Result<(), Box<dyn Error + Send + Sync>> {
            Ok(())
        }
        fn write(&self, _: u64, _: &[u8]) -> Result<(), Box<dyn Error + Send + Sync>> {
            Err(std::io::Error::other("injected timestamp write failure").into())
        }
    }
    let (fixture, _disk, _) = fixture();
    let disk = Ext4::load_with_writer(
        Box::new(fixture.image.clone()),
        Some(Box::new(FailingWriter)),
    )
    .unwrap();
    let mut service = FilesystemService::new(disk);
    let id = open(&mut service, b"/work/target", false);
    let before = status(&mut service, id);
    let bytes = fixture.image.0.lock().unwrap().clone();
    assert_eq!(
        service
            .set_times_handle(
                request(wire::OP_SET_TIMES_HANDLE, 0),
                id,
                credentials(1001, 0, &[]),
                current(),
                now
            )
            .err(),
        Some(5)
    );
    assert_eq!(status(&mut service, id), before);
    assert_eq!(*fixture.image.0.lock().unwrap(), bytes);
}
