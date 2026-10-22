use super::*;
use wire::{FileTimeUpdate as Update, TimestampUpdate as Field};

fn update(access: Field, modification: Field) -> Update {
    Update {
        access,
        modification,
    }
}
fn times(node: wire::NodeStatus) -> [(i64, u32); 3] {
    [
        (node.access_time_seconds, node.access_time_nanoseconds),
        (
            node.modification_time_seconds,
            node.modification_time_nanoseconds,
        ),
        (node.change_time_seconds, node.change_time_nanoseconds),
    ]
}
fn apply(
    service: &mut FilesystemService,
    file: u64,
    caller: wire::Credentials,
    fields: Update,
) -> Result<(), i32> {
    service
        .set_times_handle(wire::Header::default(), file, caller, fields, clock)
        .map(|_| ())
}

#[test]
fn every_now_omit_set_pair_updates_one_shared_inode_with_one_trusted_instant() {
    let f = Fixture::new();
    let (mut service, _, file) = fixture(&f);
    let alias = device_open(
        &mut service,
        b"/dev/null",
        wire::OPEN_AT_READ,
        PathAnchors::default(),
    )
    .unwrap();
    let fields = [
        Field::Now,
        Field::Omit,
        Field::Set {
            seconds: i64::MIN,
            nanoseconds: 999_999_999,
        },
        Field::Set {
            seconds: i64::MAX,
            nanoseconds: 0,
        },
    ];
    for access in fields {
        for modification in fields {
            let before = times(status(&service, file));
            CLOCK_CALLS.set(0);
            apply(
                &mut service,
                file,
                credentials(501, 20, &[]),
                update(access, modification),
            )
            .unwrap();
            let after = times(status(&service, alias));
            let expected = |field, old| match field {
                Field::Now => (-7, 321),
                Field::Omit => old,
                Field::Set {
                    seconds,
                    nanoseconds,
                } => (seconds, nanoseconds),
            };
            assert_eq!(after[0], expected(access, before[0]));
            assert_eq!(after[1], expected(modification, before[1]));
            let unchanged = update(access, modification).unchanged();
            assert_eq!(after[2], if unchanged { before[2] } else { (-7, 321) });
            assert_eq!(CLOCK_CALLS.get(), u32::from(!unchanged));
        }
    }
}

#[test]
fn only_both_now_allows_nonowners_with_fresh_write_permission() {
    let f = Fixture::new();
    let (mut service, parent, file) = fixture(&f);
    for (mode, caller, expected) in [
        (0o660, credentials(502, 20, &[]), Ok(())),
        (0o660, credentials(502, 30, &[20]), Ok(())),
        (0o660, credentials(502, 30, &[]), Err(13)),
        (0o606, credentials(502, 20, &[]), Err(13)),
        (0o606, credentials(502, 30, &[]), Ok(())),
        (0, credentials(501, 99, &[]), Ok(())),
        (0, credentials(0, 99, &[]), Ok(())),
    ] {
        configure(
            &mut service,
            parent,
            wire::OP_DEVICE_NODE_SET_ATTRIBUTES,
            mode,
            501,
            20,
        );
        CLOCK_CALLS.set(0);
        let before = status(&service, file);
        assert_eq!(
            apply(&mut service, file, caller, update(Field::Now, Field::Now)),
            expected
        );
        assert_eq!(CLOCK_CALLS.get(), u32::from(expected.is_ok()));
        if expected.is_err() {
            assert_eq!(status(&service, file), before);
        }
    }
    configure(
        &mut service,
        parent,
        wire::OP_DEVICE_NODE_SET_ATTRIBUTES,
        0o666,
        501,
        20,
    );
    for fields in [
        update(Field::Now, Field::Omit),
        update(Field::Omit, Field::Now),
        update(
            Field::Set {
                seconds: 1,
                nanoseconds: 0,
            },
            Field::Now,
        ),
    ] {
        CLOCK_CALLS.set(0);
        assert_eq!(
            apply(&mut service, file, credentials(502, 20, &[]), fields),
            Err(1)
        );
        assert_eq!(CLOCK_CALLS.get(), 0);
    }
}

#[test]
fn invalid_times_and_clock_failure_never_publish_partial_metadata() {
    let f = Fixture::new();
    let (mut service, _, file) = fixture(&f);
    let before = status(&service, file);
    let bad = update(
        Field::Set {
            seconds: 0,
            nanoseconds: 1_000_000_000,
        },
        Field::Now,
    );
    assert_eq!(
        apply(&mut service, file, credentials(501, 20, &[]), bad),
        Err(22)
    );
    assert_eq!(CLOCK_CALLS.get(), 0);
    for error in [5, -1] {
        CLOCK_ERROR.set(error);
        assert_eq!(
            apply(
                &mut service,
                file,
                credentials(501, 20, &[]),
                update(Field::Now, Field::Now)
            ),
            Err(if error == -1 { 22 } else { error })
        );
        assert_eq!(status(&service, file), before);
    }
    CLOCK_CALLS.set(0);
    apply(
        &mut service,
        file,
        credentials(999, 999, &[]),
        update(Field::Omit, Field::Omit),
    )
    .unwrap();
    assert_eq!(CLOCK_CALLS.get(), 0);
    assert_eq!(status(&service, file), before);
    service.provider_close(file).unwrap();
    assert_eq!(
        apply(
            &mut service,
            file,
            credentials(0, 0, &[]),
            update(Field::Omit, Field::Omit)
        ),
        Err(9)
    );
}

#[test]
fn retained_unpublished_timestamp_identity_is_not_the_recreated_name() {
    let f = Fixture::new();
    let (mut service, parent, file) = fixture(&f);
    configure(&mut service, parent, wire::OP_DEVICE_NODE_REMOVE, 0, 0, 0);
    configure(
        &mut service,
        parent,
        wire::OP_DEVICE_NODE_CREATE,
        0o666,
        900,
        44,
    );
    let replacement = device_open(
        &mut service,
        b"/dev/null",
        wire::OPEN_AT_READ,
        PathAnchors::default(),
    )
    .unwrap();
    let before = status(&service, replacement);
    apply(
        &mut service,
        file,
        credentials(501, 20, &[]),
        update(Field::Now, Field::Now),
    )
    .unwrap();
    assert_eq!(status(&service, replacement), before);
    assert_eq!(times(status(&service, file)), [(-7, 321); 3]);
    assert_eq!(status(&service, file).link_count, 0);
}

#[test]
fn pathname_times_share_fd_metadata_and_retained_root_confinement() {
    let f = Fixture::new();
    let (mut service, parent, file) = fixture(&f);
    let anchors = PathAnchors {
        root_open_id: Some(parent),
        base_open_id: Some(parent),
    };
    let request = wire::Header {
        flags: wire::SET_TIMES_AT_ROOT_ATTACHED | wire::SET_TIMES_AT_BASE_ATTACHED,
        ..Default::default()
    };
    service
        .set_times_at(
            request,
            b"../../null",
            anchors,
            credentials(501, 20, &[]),
            update(Field::Now, Field::Now),
            clock,
        )
        .unwrap();
    assert_eq!(times(status(&service, file)), [(-7, 321); 3]);
    assert!(matches!(
        service.set_times_at(
            request,
            b"/file",
            anchors,
            credentials(0, 0, &[]),
            update(Field::Now, Field::Now),
            clock
        ),
        Err(2)
    ));
    let before = status(&service, file);
    assert!(matches!(
        service.set_times_at(
            request,
            b"null",
            anchors,
            credentials(502, 20, &[]),
            update(Field::Now, Field::Omit),
            clock
        ),
        Err(1)
    ));
    assert_eq!(status(&service, file), before);
}

#[test]
fn followed_device_and_nofollow_disk_symlink_keep_distinct_timestamp_targets() {
    let f = Fixture::new();
    let disk = f.volume("device-time-symlink");
    let mut directory =
        ext4plus::dir::Dir::open_inode(&disk, disk.read_root_inode().unwrap()).unwrap();
    disk.symlink(
        &mut directory,
        ext4plus::DirEntryName::try_from("alias").unwrap(),
        ext4plus::path::PathBuf::try_from("/dev/null").unwrap(),
        0,
        0,
        std::time::Duration::ZERO,
    )
    .unwrap();
    let mut service = FilesystemService::new(disk);
    service.mount_devices(b"/dev", Default::default()).unwrap();
    let file = device_open(
        &mut service,
        b"/dev/null",
        wire::OPEN_AT_READ,
        PathAnchors::default(),
    )
    .unwrap();
    let before = status(&service, file);
    let explicit = update(
        Field::Set {
            seconds: -1,
            nanoseconds: 123,
        },
        Field::Set {
            seconds: 2,
            nanoseconds: 456,
        },
    );
    service
        .set_times_at(
            wire::Header {
                flags: wire::SET_TIMES_AT_NOFOLLOW,
                ..Default::default()
            },
            b"/alias",
            PathAnchors::default(),
            credentials(0, 0, &[]),
            explicit,
            clock,
        )
        .unwrap();
    assert_eq!(status(&service, file), before);
    let alias = service
        .stat_at(
            wire::Header {
                flags: wire::STAT_AT_NOFOLLOW,
                ..Default::default()
            },
            b"/alias",
            PathAnchors::default(),
            credentials(0, 0, &[]),
        )
        .unwrap()
        .payload;
    service
        .set_times_at(
            wire::Header::default(),
            b"/alias",
            PathAnchors::default(),
            credentials(0, 0, &[]),
            explicit,
            clock,
        )
        .unwrap();
    assert_eq!(
        times(status(&service, file)),
        [(-1, 123), (2, 456), (-7, 321)]
    );
    assert_eq!(
        service
            .stat_at(
                wire::Header {
                    flags: wire::STAT_AT_NOFOLLOW,
                    ..Default::default()
                },
                b"/alias",
                PathAnchors::default(),
                credentials(0, 0, &[])
            )
            .unwrap()
            .payload,
        alias
    );
}
