//! Exercise execute admission on the same real ext4 inode that is opened.
use super::*;

fn create(service: &mut FilesystemService, path: &[u8], mode: u32) -> u64 {
    service
        .open_at(
            protocol::Header {
                flags: protocol::OPEN_AT_READ
                    | protocol::OPEN_AT_WRITE
                    | protocol::OPEN_AT_CREATE
                    | protocol::OPEN_AT_EXCLUSIVE,
                mode,
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

fn image(
    service: &mut FilesystemService,
    path: &[u8],
    credentials: protocol::Credentials,
) -> Result<u64, i32> {
    service
        .open_at(
            protocol::Header {
                flags: protocol::OPEN_AT_READ | protocol::OPEN_AT_EXECUTE,
                ..Default::default()
            },
            path,
            PathAnchors::default(),
            credentials,
        )
        .map(|reply| reply.header.open_id)
}

#[test]
fn image_open_checks_effective_owner_group_other_and_root_execute_permissions() {
    let mut service = test_filesystem();
    let path = b"/create-base/program";
    let file = create(&mut service, path, 0o644);
    service
        .chown_handle(
            protocol::Header {
                node_id: 501 | (77u64 << 32),
                ..Default::default()
            },
            file,
            root_credentials(),
        )
        .unwrap();
    for (mode, uid, gid, groups, allowed) in [
        (0o644, 501, 99, &[][..], false),
        (0o744, 501, 99, &[][..], true),
        (0o744, 502, 77, &[][..], false),
        (0o650, 502, 77, &[][..], true),
        (0o650, 501, 77, &[][..], false), // owner cannot borrow group bits
        (0o650, 502, 99, &[77][..], true),
        (0o650, 502, 99, &[][..], false),
        (0o645, 502, 99, &[][..], true),
        (0o644, 0, 0, &[][..], false), // uid zero does not invent execute bits
        (0o001, 0, 0, &[][..], true),
    ] {
        service
            .chmod_handle(
                protocol::Header {
                    mode,
                    ..Default::default()
                },
                file,
                root_credentials(),
            )
            .unwrap();
        let result = image(&mut service, path, credentials(uid, gid, groups));
        if allowed {
            service.provider_close(result.unwrap()).unwrap();
        } else {
            assert_eq!(result, Err(13), "mode={mode:o} uid={uid} gid={gid}");
        }
    }
    service.provider_close(file).unwrap();
}

#[test]
fn image_open_cannot_create_truncate_or_acquire_a_directory_or_device() {
    let mut service = test_filesystem();
    let path = b"/create-base/program";
    let file = create(&mut service, path, 0o755);
    service.provider_write(file, b"original").unwrap();
    for flags in [
        protocol::OPEN_AT_WRITE,
        protocol::OPEN_AT_CREATE,
        protocol::OPEN_AT_EXCLUSIVE,
        protocol::OPEN_AT_TRUNCATE,
        protocol::OPEN_AT_APPEND,
        protocol::OPEN_AT_DIRECTORY,
        protocol::OPEN_AT_SEARCH,
        protocol::OPEN_AT_CURSOR_RECORDS,
    ] {
        assert!(matches!(
            service.open_at(
                protocol::Header {
                    flags: protocol::OPEN_AT_READ | protocol::OPEN_AT_EXECUTE | flags,
                    mode: 0o755,
                    ..Default::default()
                },
                path,
                PathAnchors::default(),
                root_credentials()
            ),
            Err(22)
        ));
    }
    assert!(matches!(
        service.open_at(
            protocol::Header {
                flags: protocol::OPEN_AT_EXECUTE,
                ..Default::default()
            },
            path,
            PathAnchors::default(),
            root_credentials()
        ),
        Err(22)
    ));
    assert!(matches!(
        service.open_at(
            protocol::Header {
                flags: protocol::OPEN_AT_READ
                    | protocol::OPEN_AT_EXECUTE
                    | protocol::OPEN_AT_CREATE,
                mode: 0o755,
                ..Default::default()
            },
            b"/create-base/new",
            PathAnchors::default(),
            root_credentials()
        ),
        Err(22)
    ));
    assert_eq!(
        image(&mut service, b"/create-base/new", root_credentials()),
        Err(2)
    );
    assert_eq!(
        image(&mut service, b"/create-base", root_credentials()),
        Err(13)
    );
    service.mount_devices(b"/dev", Default::default()).unwrap();
    assert_eq!(
        image(&mut service, b"/dev/null", root_credentials()),
        Err(13)
    );
    assert_eq!(image(&mut service, b"/dev", root_credentials()), Err(13));
    let ordinary = service
        .open_at(
            protocol::Header {
                flags: protocol::OPEN_AT_READ,
                ..Default::default()
            },
            path,
            PathAnchors::default(),
            root_credentials(),
        )
        .unwrap()
        .header
        .open_id;
    assert_eq!(
        service.provider_read(ordinary, 100),
        Ok(b"original".to_vec())
    );
    service.provider_close(ordinary).unwrap();
    service.provider_close(file).unwrap();
}

#[test]
fn image_permission_decision_stays_bound_to_the_open_inode_after_path_replacement() {
    let mut service = test_filesystem();
    let path = b"/create-base/program";
    let file = create(&mut service, path, 0o755);
    service.provider_write(file, b"authorized inode").unwrap();
    let opened = image(&mut service, path, root_credentials()).unwrap();
    let replacement = create(&mut service, b"/create-base/replacement", 0o644);
    service
        .provider_write(replacement, b"not executable")
        .unwrap();
    let new = b"/create-base/replacement";
    let mut payload = new.to_vec();
    payload.extend_from_slice(path);
    service
        .rename_at(
            protocol::Header {
                mode: new.len() as u32,
                ..Default::default()
            },
            &payload,
            RenameAnchors::default(),
            root_credentials(),
        )
        .unwrap();
    assert_eq!(image(&mut service, path, root_credentials()), Err(13));
    assert_eq!(
        service.provider_read(opened, 100),
        Ok(b"authorized inode".to_vec())
    );
    for handle in [opened, file, replacement] {
        service.provider_close(handle).unwrap();
    }
}
