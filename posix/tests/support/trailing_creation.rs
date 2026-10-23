use super::trailing_lookup::{prepared, status};
use super::*;

fn missing(fs: &mut FilesystemService, path: &[u8]) {
    assert_eq!(
        fs.stat_at(
            protocol::Header::default(),
            path,
            PathAnchors::default(),
            root_credentials()
        )
        .err(),
        Some(2)
    );
}

fn rename(fs: &mut FilesystemService, old: &[u8], new: &[u8]) -> Result<(), i32> {
    fs.rename_at(
        protocol::Header {
            mode: old.len() as u32,
            ..Default::default()
        },
        &[old, new].concat(),
        RenameAnchors::default(),
        root_credentials(),
    )
    .map(|_| ())
}

fn link(fs: &mut FilesystemService, old: &[u8], new: &[u8]) -> Result<(), i32> {
    fs.link_at(
        protocol::Header {
            mode: old.len() as u32,
            ..Default::default()
        },
        &[old, new].concat(),
        RenameAnchors::default(),
        root_credentials(),
    )
    .map(|_| ())
}

#[test]
fn symlink_creation_cannot_drop_a_missing_destination_separator() {
    let mut fs = prepared(0o700);
    let target = b"target-dir";
    assert_eq!(
        fs.symlink_at(
            protocol::Header {
                mode: target.len() as u32,
                ..Default::default()
            },
            &[target.as_slice(), b"/new-link///"].concat(),
            PathAnchors::default(),
            root_credentials(),
        )
        .err(),
        Some(2)
    );
    missing(&mut fs, b"/new-link");
}

#[test]
fn socket_creation_cannot_drop_a_missing_destination_separator() {
    let mut fs = prepared(0o700);
    for retained in [false, true] {
        let request = protocol::Header {
            mode: 0o600,
            ..Default::default()
        };
        let result = if retained {
            fs.create_socket_at_retained(
                request,
                b"/new-socket/",
                PathAnchors::default(),
                root_credentials(),
            )
        } else {
            fs.create_socket_at(
                request,
                b"/new-socket/",
                PathAnchors::default(),
                root_credentials(),
            )
        };
        assert_eq!(result.err(), Some(2));
        missing(&mut fs, b"/new-socket");
    }
}

#[test]
fn hard_link_failure_preserves_source_link_count_and_destination_absence() {
    let mut fs = prepared(0o700);
    let before = status(&mut fs, b"/target-file");
    assert_eq!(link(&mut fs, b"/target-file", b"/new-hard-link/"), Err(20));
    missing(&mut fs, b"/new-hard-link");
    assert_eq!(
        status(&mut fs, b"/target-file").link_count,
        before.link_count
    );
    link(&mut fs, b"/target-file", b"/new-hard-link").unwrap();
    assert_eq!(status(&mut fs, b"/new-hard-link").node_id, before.node_id);
    assert_eq!(
        status(&mut fs, b"/target-file").link_count,
        before.link_count + 1
    );
}

#[test]
fn rename_to_missing_slash_destination_never_moves_any_source_kind() {
    let mut fs = prepared(0o700);
    for (old, error) in [
        (b"/target-file".as_slice(), 20),
        (b"/target-dir", 2),
        (b"/dir-link", 20),
    ] {
        let before = status(&mut fs, old);
        assert_eq!(rename(&mut fs, old, b"/not-created/"), Err(error));
        missing(&mut fs, b"/not-created");
        assert_eq!(status(&mut fs, old).node_id, before.node_id);
        assert_eq!(status(&mut fs, old).link_count, before.link_count);
    }
}

#[test]
fn directory_creation_and_rename_to_an_existing_directory_keep_working() {
    let mut fs = prepared(0o700);
    fs.mkdir_at(
        protocol::Header {
            mode: 0o700,
            ..Default::default()
        },
        b"/destination///",
        PathAnchors::default(),
        root_credentials(),
    )
    .unwrap();
    let source = status(&mut fs, b"/target-dir");
    rename(&mut fs, b"/target-dir/", b"/destination/").unwrap();
    assert_eq!(status(&mut fs, b"/destination").node_id, source.node_id);
    missing(&mut fs, b"/target-dir");
}

#[test]
fn hard_link_source_separator_resolves_a_directory_without_linking_it() {
    let mut fs = prepared(0o700);
    for (source, error) in [
        (b"/dir-link/".as_slice(), 1),
        (b"/file-link/", 20),
        (b"/missing-link/", 2),
    ] {
        assert_eq!(link(&mut fs, source, b"/hard-result"), Err(error));
        missing(&mut fs, b"/hard-result");
    }
    let before = status(&mut fs, b"/dir-link");
    link(&mut fs, b"/dir-link", b"/hard-result").unwrap();
    assert_eq!(
        status(&mut fs, b"/hard-result").kind,
        protocol::NODE_TYPE_SYMLINK
    );
    assert_eq!(status(&mut fs, b"/hard-result").node_id, before.node_id);
}

#[test]
fn mkdir_existing_entry_with_slashes_never_follows_or_replaces_its_symlink() {
    let mut fs = prepared(0o700);
    for path in [
        b"/dir-link".as_slice(),
        b"/file-link",
        b"/missing-link",
        b"/target-file",
        b"/target-dir",
    ] {
        let before = status(&mut fs, path);
        assert_eq!(
            fs.mkdir_at(
                protocol::Header {
                    mode: 0o700,
                    ..Default::default()
                },
                &[path, b"///"].concat(),
                PathAnchors::default(),
                root_credentials()
            )
            .err(),
            Some(17),
            "{path:?}"
        );
        assert_eq!(status(&mut fs, path).node_id, before.node_id);
        assert_eq!(status(&mut fs, path).link_count, before.link_count);
    }
    missing(&mut fs, b"/absent");
}

#[test]
fn symlink_existing_destination_with_slashes_is_an_existing_entry() {
    let mut fs = prepared(0o700);
    let target = b"replacement";
    for path in [
        b"/dir-link".as_slice(),
        b"/file-link",
        b"/missing-link",
        b"/target-file",
    ] {
        let before = status(&mut fs, path);
        assert_eq!(
            fs.symlink_at(
                protocol::Header {
                    mode: target.len() as u32,
                    ..Default::default()
                },
                &[target.as_slice(), path, b"///"].concat(),
                PathAnchors::default(),
                root_credentials()
            )
            .err(),
            Some(17),
            "{path:?}"
        );
        assert_eq!(status(&mut fs, path).node_id, before.node_id);
    }
    missing(&mut fs, b"/replacement");
    missing(&mut fs, b"/absent");
}

#[test]
fn hard_link_existing_slash_destination_preserves_both_entries_and_source_links() {
    let mut fs = prepared(0o700);
    let source = status(&mut fs, b"/target-file");
    for path in [
        b"/dir-link".as_slice(),
        b"/file-link",
        b"/missing-link",
        b"/target-file",
    ] {
        let before = status(&mut fs, path);
        assert_eq!(
            link(&mut fs, b"/target-file", &[path, b"///"].concat()),
            Err(17),
            "{path:?}"
        );
        assert_eq!(status(&mut fs, path).node_id, before.node_id);
        assert_eq!(
            status(&mut fs, b"/target-file").link_count,
            source.link_count
        );
    }
    missing(&mut fs, b"/absent");
}

#[test]
fn socket_creation_rejects_existing_slash_destinations_without_allocating_a_description() {
    let mut fs = prepared(0o700);
    let open_directory = |fs: &mut FilesystemService| {
        fs.open_at(
            protocol::Header {
                flags: protocol::OPEN_AT_READ | protocol::OPEN_AT_DIRECTORY,
                ..Default::default()
            },
            b"/",
            PathAnchors::default(),
            root_credentials(),
        )
        .unwrap()
        .header
        .open_id
    };
    let first = open_directory(&mut fs);
    for retained in [false, true] {
        for path in [
            b"/dir-link".as_slice(),
            b"/file-link",
            b"/missing-link",
            b"/target-file",
        ] {
            let destination = [path, b"///"].concat();
            let header = protocol::Header {
                mode: 0o600,
                ..Default::default()
            };
            let result = if retained {
                fs.create_socket_at_retained(
                    header,
                    &destination,
                    PathAnchors::default(),
                    root_credentials(),
                )
            } else {
                fs.create_socket_at(
                    header,
                    &destination,
                    PathAnchors::default(),
                    root_credentials(),
                )
            };
            assert_eq!(result.err(), Some(17), "{path:?}, retained={retained}");
        }
    }
    let second = open_directory(&mut fs);
    assert_eq!(second, first + 1);
    fs.provider_close(first).unwrap();
    fs.provider_close(second).unwrap();
    missing(&mut fs, b"/absent");
}

#[test]
fn creation_lookup_preserves_original_path_length_before_removing_trailing_separators() {
    let mut fs = prepared(0o700);
    let mut path = b"/file-link".to_vec();
    path.resize(protocol::MAX_PATH_LEN + 1, b'/');
    assert_eq!(
        fs.mkdir_at(
            protocol::Header {
                mode: 0o700,
                ..Default::default()
            },
            &path,
            PathAnchors::default(),
            root_credentials()
        )
        .err(),
        Some(36)
    );
    assert_eq!(link(&mut fs, b"/target-file", &path), Err(36));
    assert_eq!(link(&mut fs, &path, b"/long-source-result"), Err(36));
    assert_eq!(
        fs.create_socket_at(
            Default::default(),
            &path,
            PathAnchors::default(),
            root_credentials()
        )
        .err(),
        Some(36)
    );
    assert_eq!(
        fs.symlink_at(
            protocol::Header {
                mode: 1,
                ..Default::default()
            },
            &[b"x".as_slice(), &path].concat(),
            PathAnchors::default(),
            root_credentials()
        )
        .err(),
        Some(36)
    );
    let target = vec![b'x'; protocol::MAX_PATH_LEN + 1];
    assert_eq!(
        fs.symlink_at(
            protocol::Header {
                mode: target.len() as u32,
                ..Default::default()
            },
            &[target.as_slice(), b"/long-target-result"].concat(),
            PathAnchors::default(),
            root_credentials()
        )
        .err(),
        Some(36)
    );
    missing(&mut fs, b"/long-source-result");
    missing(&mut fs, b"/long-target-result");
    path.truncate(protocol::MAX_PATH_LEN);
    assert_eq!(
        fs.mkdir_at(
            protocol::Header {
                mode: 0o700,
                ..Default::default()
            },
            &path,
            PathAnchors::default(),
            root_credentials()
        )
        .err(),
        Some(17)
    );
}

#[test]
fn creation_lookup_keeps_parent_components_and_search_checks() {
    let mut fs = prepared(0o700);
    for (path, error) in [
        (b"/file-link/./".as_slice(), 20),
        (b"/missing-link/child/", 2),
    ] {
        assert_eq!(
            fs.mkdir_at(
                protocol::Header {
                    mode: 0o700,
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
    assert_eq!(
        fs.mkdir_at(
            protocol::Header {
                mode: 0o700,
                ..Default::default()
            },
            b"/dir-link/new///",
            PathAnchors::default(),
            credentials(501, 20, &[])
        )
        .err(),
        Some(13)
    );
    fs.mkdir_at(
        protocol::Header {
            mode: 0o700,
            ..Default::default()
        },
        b"/dir-link/new///",
        PathAnchors::default(),
        root_credentials(),
    )
    .unwrap();
    assert_eq!(
        status(&mut fs, b"/target-dir/new").kind,
        protocol::NODE_TYPE_DIRECTORY
    );
}
