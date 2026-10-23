use super::*;

pub(super) fn prepared(mode: u32) -> FilesystemService {
    let mut fs = test_filesystem();
    fs.chmod_at(
        protocol::Header {
            mode: 0o755,
            ..Default::default()
        },
        b"/",
        PathAnchors::default(),
        root_credentials(),
    )
    .unwrap();
    fs.mkdir_at(
        protocol::Header {
            mode,
            ..Default::default()
        },
        b"/target-dir",
        PathAnchors::default(),
        root_credentials(),
    )
    .unwrap();
    let file = fs
        .open_at(
            protocol::Header {
                flags: protocol::OPEN_AT_READ | protocol::OPEN_AT_CREATE,
                mode: 0o600,
                ..Default::default()
            },
            b"/target-file",
            PathAnchors::default(),
            root_credentials(),
        )
        .unwrap();
    fs.provider_close(file.header.open_id).unwrap();
    for (target, name) in [
        (b"target-dir".as_slice(), b"/dir-link".as_slice()),
        (b"target-file", b"/file-link"),
        (b"absent", b"/missing-link"),
    ] {
        fs.symlink_at(
            protocol::Header {
                mode: target.len() as u32,
                ..Default::default()
            },
            &[target, name].concat(),
            PathAnchors::default(),
            root_credentials(),
        )
        .unwrap();
    }
    fs
}

pub(super) fn status(fs: &mut FilesystemService, path: &[u8]) -> protocol::NodeStatus {
    let response = fs
        .stat_at(
            protocol::Header {
                flags: protocol::STAT_AT_NOFOLLOW,
                ..Default::default()
            },
            path,
            PathAnchors::default(),
            root_credentials(),
        )
        .unwrap();
    protocol::decode_node_status(&response.payload).unwrap()
}

#[test]
fn nofollow_stat_and_readlink_distinguish_a_trailing_separator() {
    let mut fs = prepared(0o700);
    assert_eq!(
        status(&mut fs, b"/dir-link").kind,
        protocol::NODE_TYPE_SYMLINK
    );
    assert_eq!(
        status(&mut fs, b"/dir-link///").kind,
        protocol::NODE_TYPE_DIRECTORY
    );
    assert_eq!(
        status(&mut fs, b"/dir-link/").node_id,
        status(&mut fs, b"/target-dir").node_id
    );
    assert_eq!(
        fs.readlink_at(
            protocol::Header::default(),
            b"/dir-link",
            PathAnchors::default(),
            root_credentials()
        )
        .unwrap()
        .payload,
        b"target-dir"
    );
    for (path, error) in [
        (b"/dir-link/".as_slice(), 22),
        (b"/file-link/", 20),
        (b"/missing-link/", 2),
    ] {
        assert_eq!(
            fs.readlink_at(
                protocol::Header::default(),
                path,
                PathAnchors::default(),
                root_credentials()
            )
            .err(),
            Some(error)
        );
    }
    for (path, error) in [(b"/file-link/".as_slice(), 20), (b"/missing-link/", 2)] {
        assert_eq!(
            fs.stat_at(
                protocol::Header {
                    flags: protocol::STAT_AT_NOFOLLOW,
                    ..Default::default()
                },
                path,
                PathAnchors::default(),
                root_credentials()
            )
            .err(),
            Some(error)
        );
    }
}

#[test]
fn nofollow_open_can_open_a_directory_selected_by_a_trailing_separator() {
    let mut fs = prepared(0o700);
    let request = protocol::Header {
        flags: protocol::OPEN_AT_READ | protocol::OPEN_AT_NOFOLLOW,
        ..Default::default()
    };
    assert_eq!(
        fs.open_at(
            request,
            b"/dir-link",
            PathAnchors::default(),
            root_credentials()
        )
        .err(),
        Some(40)
    );
    let opened = fs
        .open_at(
            request,
            b"/dir-link/",
            PathAnchors::default(),
            root_credentials(),
        )
        .unwrap();
    fs.provider_close(opened.header.open_id).unwrap();
    for (path, error) in [(b"/file-link/".as_slice(), 20), (b"/missing-link/", 2)] {
        assert_eq!(
            fs.open_at(request, path, PathAnchors::default(), root_credentials())
                .err(),
            Some(error)
        );
    }
}

#[test]
fn trailing_directory_lookup_checks_the_target_access_without_extra_search() {
    let mut fs = prepared(0);
    let user = credentials(501, 20, &[]);
    let access = protocol::Header {
        flags: protocol::ACCESS_AT_NOFOLLOW | protocol::ACCESS_AT_READ,
        ..Default::default()
    };
    fs.access_at(
        protocol::Header {
            flags: protocol::ACCESS_AT_NOFOLLOW,
            ..Default::default()
        },
        b"/dir-link",
        PathAnchors::default(),
        user,
    )
    .unwrap();
    assert_eq!(
        fs.access_at(access, b"/dir-link/", PathAnchors::default(), user)
            .err(),
        Some(13)
    );
    fs.stat_at(
        protocol::Header {
            flags: protocol::STAT_AT_NOFOLLOW,
            ..Default::default()
        },
        b"/dir-link/",
        PathAnchors::default(),
        user,
    )
    .unwrap();
    assert_eq!(
        fs.stat_at(
            protocol::Header {
                flags: protocol::STAT_AT_NOFOLLOW,
                ..Default::default()
            },
            b"/dir-link/./",
            PathAnchors::default(),
            user
        )
        .err(),
        Some(13)
    );
}

#[test]
fn nofollow_attribute_updates_with_a_separator_modify_only_the_directory() {
    use ext4plus::inode::InodeTimestamp;
    use protocol::{FileTimeUpdate, TimestampUpdate};
    let mut fs = prepared(0o700);
    let link_before = status(&mut fs, b"/dir-link");
    fs.chown_at(
        protocol::Header {
            flags: protocol::CHOWN_AT_NOFOLLOW,
            node_id: (77u64 << 32) | 501,
            ..Default::default()
        },
        b"/dir-link/",
        PathAnchors::default(),
        root_credentials(),
    )
    .unwrap();
    let directory = status(&mut fs, b"/target-dir");
    assert_eq!((directory.uid, directory.gid), (501, 77));
    let update = FileTimeUpdate {
        access: TimestampUpdate::Set {
            seconds: 123,
            nanoseconds: 45,
        },
        modification: TimestampUpdate::Set {
            seconds: 456,
            nanoseconds: 78,
        },
    };
    fs.set_times_at(
        protocol::Header {
            flags: protocol::SET_TIMES_AT_NOFOLLOW,
            ..Default::default()
        },
        b"/dir-link/",
        PathAnchors::default(),
        root_credentials(),
        update,
        || {
            Ok(InodeTimestamp {
                seconds: 789,
                nanoseconds: 0,
            })
        },
    )
    .unwrap();
    let directory = status(&mut fs, b"/target-dir");
    assert_eq!(
        (
            directory.access_time_seconds,
            directory.modification_time_seconds
        ),
        (123, 456)
    );
    let link_after = status(&mut fs, b"/dir-link");
    assert_eq!(
        (link_after.uid, link_after.gid),
        (link_before.uid, link_before.gid)
    );
    assert_eq!(
        (
            link_after.access_time_seconds,
            link_after.modification_time_seconds
        ),
        (
            link_before.access_time_seconds,
            link_before.modification_time_seconds
        )
    );
}

#[test]
fn unlink_and_rename_never_follow_the_final_directory_link() {
    let mut fs = prepared(0o700);
    for flags in [0, protocol::UNLINK_AT_REMOVE_DIRECTORY] {
        assert_eq!(
            fs.unlink_at(
                protocol::Header {
                    flags,
                    ..Default::default()
                },
                b"/dir-link/",
                PathAnchors::default(),
                root_credentials()
            )
            .err(),
            Some(20)
        );
    }
    for (old, new) in [
        (b"/dir-link/".as_slice(), b"/moved".as_slice()),
        (b"/target-dir", b"/dir-link/"),
    ] {
        assert_eq!(
            fs.rename_at(
                protocol::Header {
                    mode: old.len() as u32,
                    ..Default::default()
                },
                &[old, new].concat(),
                RenameAnchors::default(),
                root_credentials()
            )
            .err(),
            Some(20)
        );
    }
    assert_eq!(
        status(&mut fs, b"/dir-link").kind,
        protocol::NODE_TYPE_SYMLINK
    );
    assert_eq!(
        status(&mut fs, b"/target-dir").kind,
        protocol::NODE_TYPE_DIRECTORY
    );
}
