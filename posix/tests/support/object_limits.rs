use super::*;
use filesystem_service::provider_limits;
use mnu_abi::provider;
use protocol::object_limits as wire;

fn query(id: u64, opcode: u16) -> provider::RequestHeader {
    provider::RequestHeader {
        opcode,
        object_id: id,
        argument: 0,
        basis: wire::GET,
        length: wire::RESPONSE_LEN as u32,
        data_length: 0,
    }
}

fn open(fs: &mut FilesystemService, path: &[u8], flags: u32) -> u64 {
    fs.open_at(
        protocol::Header {
            flags,
            mode: 0o600,
            ..Default::default()
        },
        path,
        PathAnchors::default(),
        root_credentials(),
    )
    .unwrap()
    .header
    .open_id
}

#[test]
fn retained_limits_do_not_read_data_move_the_cursor_or_change_flags() {
    let mut fs = test_filesystem();
    let id = open(
        &mut fs,
        b"/limits",
        protocol::OPEN_AT_CREATE
            | protocol::OPEN_AT_READ
            | protocol::OPEN_AT_WRITE
            | protocol::OPEN_AT_APPEND,
    );
    fs.provider_write(id, b"data").unwrap();
    let before = fs
        .get_flags_handle(Default::default(), id)
        .unwrap()
        .header
        .flags;
    let expected = fs.provider_limits(id).unwrap();
    assert_eq!(
        expected.name_bytes_max,
        ext4plus::DirEntryName::MAX_LEN as u32
    );
    assert_eq!(expected.path_bytes_max, protocol::MAX_PATH_LEN as u32);
    assert_eq!(expected.link_count_max, u32::from(u16::MAX));
    for opcode in [provider::OP_QUERY, provider::OP_CONTROL] {
        let (count, bytes) = provider_limits::handle(&fs, query(id, opcode), &[], 0).unwrap();
        assert_eq!(count, wire::RESPONSE_LEN as u64);
        assert_eq!(wire::Limits::decode(&bytes), Some(expected));
    }
    assert_eq!(fs.provider_seek(id, 0, mnu_abi::HANDLE_SEEK_CURRENT), Ok(4));
    assert_eq!(fs.provider_read_at(id, 0, 4).unwrap(), b"data");
    assert_eq!(
        fs.get_flags_handle(Default::default(), id)
            .unwrap()
            .header
            .flags,
        before
    );
    fs.unlink_at(
        Default::default(),
        b"/limits",
        PathAnchors::default(),
        root_credentials(),
    )
    .unwrap();
    assert_eq!(fs.provider_limits(id).unwrap(), expected);
    fs.provider_close(id).unwrap();
    assert_eq!(
        provider_limits::handle(&fs, query(id, provider::OP_QUERY), &[], 0),
        Err(9)
    );
}

#[test]
fn malformed_queries_are_rejected_without_using_claimed_ids() {
    let mut fs = test_filesystem();
    let id = open(
        &mut fs,
        b"/query",
        protocol::OPEN_AT_CREATE | protocol::OPEN_AT_WRITE,
    );
    let header = query(id, provider::OP_QUERY);
    for malformed in [
        provider::RequestHeader {
            argument: 1,
            ..header
        },
        provider::RequestHeader {
            length: 15,
            ..header
        },
        provider::RequestHeader {
            length: 17,
            ..header
        },
        provider::RequestHeader {
            data_length: 1,
            ..header
        },
    ] {
        assert_eq!(provider_limits::handle(&fs, malformed, &[], 0), Err(22));
    }
    assert_eq!(provider_limits::handle(&fs, header, &[], 1), Err(22));
    assert_eq!(
        provider_limits::handle(
            &fs,
            provider::RequestHeader {
                data_length: 1,
                ..header
            },
            &[0],
            0
        ),
        Err(22)
    );
    assert_eq!(
        provider_limits::handle(&fs, query(id, provider::OP_WRITE), &[], 0),
        Err(95)
    );
    assert_eq!(
        provider_limits::handle(&fs, provider::RequestHeader { basis: 0, ..header }, &[], 0),
        Err(95)
    );
    assert_eq!(
        provider_limits::handle(&fs, query(u64::MAX, provider::OP_QUERY), &[], 0),
        Err(9)
    );
    // Explicit CONTROL observation supports an existing write-only description.
    provider_limits::handle(&fs, query(id, provider::OP_CONTROL), &[], 0).unwrap();
    fs.provider_close(id).unwrap();
}

#[test]
fn devices_do_not_inherit_ext4_limits() {
    let mut fs = test_filesystem();
    fs.mount_devices(b"/dev", Default::default()).unwrap();
    for (path, flags) in [
        (
            b"/dev".as_slice(),
            protocol::OPEN_AT_READ | protocol::OPEN_AT_DIRECTORY,
        ),
        (b"/dev/null", protocol::OPEN_AT_READ),
    ] {
        let id = open(&mut fs, path, flags);
        assert_eq!(
            provider_limits::handle(&fs, query(id, provider::OP_QUERY), &[], 0),
            Err(95)
        );
        fs.provider_close(id).unwrap();
    }
}

fn volume(block_bytes: u32) -> Ext4 {
    let temporary = TempTree::create();
    let path = temporary.0.join("volume.ext4");
    let output = Command::new("mke2fs")
        .args(["-q", "-t", "ext4", "-F", "-b"])
        .arg(block_bytes.to_string())
        .arg(&path)
        .arg("4096")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let image = SharedImage(
        Arc::new(Mutex::new(fs::read(path).unwrap())),
        Arc::new(Mutex::new(None)),
        Arc::new(Mutex::new(WriteFault::default())),
    );
    Ext4::load_with_writer(Box::new(image.clone()), Some(Box::new(image))).unwrap()
}

#[test]
fn retained_description_selects_its_own_mounted_volume_block_size() {
    let mut fs = FilesystemService::new(volume(1024));
    fs.mkdir_at(
        protocol::Header {
            mode: 0o700,
            ..Default::default()
        },
        b"/other",
        PathAnchors::default(),
        root_credentials(),
    )
    .unwrap();
    fs.mount_volume(b"/other", volume(4096)).unwrap();
    for (path, block_bytes) in [(b"/".as_slice(), 1024), (b"/other", 4096)] {
        let id = open(
            &mut fs,
            path,
            protocol::OPEN_AT_READ | protocol::OPEN_AT_DIRECTORY,
        );
        let (_, bytes) =
            provider_limits::handle(&fs, query(id, provider::OP_QUERY), &[], 0).unwrap();
        assert_eq!(
            wire::Limits::decode(&bytes).unwrap().filesystem_block_bytes,
            block_bytes
        );
        let reply = fs
            .object_limits_at(
                Default::default(),
                path,
                PathAnchors::default(),
                root_credentials(),
            )
            .unwrap();
        assert_eq!(
            wire::Limits::decode(&reply.payload)
                .unwrap()
                .filesystem_block_bytes,
            block_bytes
        );
        fs.provider_close(id).unwrap();
    }
}

#[test]
fn pathname_limits_require_search_but_not_target_data_read_permission() {
    let mut fs = super::trailing_lookup::prepared(0);
    fs.chmod_at(
        protocol::Header {
            mode: 0,
            ..Default::default()
        },
        b"/target-file",
        PathAnchors::default(),
        root_credentials(),
    )
    .unwrap();
    let user = credentials(501, 20, &[]);
    for path in [b"/target-file".as_slice(), b"/target-dir", b"/dir-link/"] {
        let reply = fs
            .object_limits_at(Default::default(), path, PathAnchors::default(), user)
            .unwrap();
        assert_eq!(
            wire::Limits::decode(&reply.payload).unwrap().name_bytes_max,
            255
        );
    }
    assert_eq!(
        fs.object_limits_at(
            Default::default(),
            b"/target-dir/child",
            PathAnchors::default(),
            user
        )
        .err(),
        Some(13)
    );
    assert_eq!(
        fs.object_limits_at(
            Default::default(),
            b"/missing",
            PathAnchors::default(),
            user
        )
        .err(),
        Some(2)
    );
}

#[test]
fn pathname_limits_validate_anchor_flags_and_preserve_root_confinement() {
    let mut fs = test_filesystem();
    let root = open(
        &mut fs,
        b"/jail",
        protocol::OPEN_AT_READ | protocol::OPEN_AT_DIRECTORY,
    );
    let anchors = PathAnchors {
        root_open_id: Some(root),
        base_open_id: None,
    };
    let header = protocol::Header {
        flags: protocol::STAT_AT_ROOT_ATTACHED,
        ..Default::default()
    };
    fs.object_limits_at(header, b"/inside", anchors, root_credentials())
        .unwrap();
    assert_eq!(
        fs.object_limits_at(header, b"/escape", anchors, root_credentials())
            .err(),
        Some(2)
    );
    assert_eq!(
        fs.object_limits_at(Default::default(), b"/inside", anchors, root_credentials())
            .err(),
        Some(22)
    );
    assert_eq!(
        fs.object_limits_at(
            protocol::Header {
                flags: protocol::STAT_AT_NOFOLLOW | header.flags,
                ..header
            },
            b"/inside",
            anchors,
            root_credentials()
        )
        .err(),
        Some(22)
    );
    fs.provider_close(root).unwrap();
    assert_eq!(
        fs.object_limits_at(header, b"/inside", anchors, root_credentials())
            .err(),
        Some(9)
    );
}
