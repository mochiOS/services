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
