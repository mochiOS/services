use super::*;

fn rename(service: &mut FilesystemService, old: &[u8], new: &[u8]) {
    let mut payload = old.to_vec();
    payload.extend_from_slice(new);
    service
        .rename_at(
            protocol::Header {
                opcode: protocol::OP_RENAME_AT,
                mode: old.len() as u32,
                ..Default::default()
            },
            &payload,
            RenameAnchors::default(),
            root_credentials(),
        )
        .unwrap();
}

#[test]
fn raw_directory_rename_and_replacement_preserve_retained_identity() {
    for mounted in [false, true] {
        let mut service = test_filesystem();
        if mounted {
            service.mount_devices(b"/dev", Default::default()).unwrap();
        }
        let old = b"/dir-\xff";
        let new = b"/dir-\xfe";
        for path in [old, new] {
            service
                .mkdir_at(
                    protocol::Header {
                        mode: 0o700,
                        ..Default::default()
                    },
                    path,
                    PathAnchors::default(),
                    root_credentials(),
                )
                .unwrap();
        }
        let open = |service: &mut FilesystemService, path: &[u8]| {
            service
                .open_at(
                    protocol::Header {
                        flags: protocol::OPEN_AT_READ | protocol::OPEN_AT_DIRECTORY,
                        ..Default::default()
                    },
                    path,
                    PathAnchors::default(),
                    root_credentials(),
                )
                .unwrap()
                .header
        };
        let root = open(&mut service, b"/");
        let source = open(&mut service, old);
        let replaced = open(&mut service, new);
        rename(&mut service, old, new);
        assert_eq!(
            service
                .path_handle(Default::default(), root.open_id, source.open_id)
                .unwrap()
                .payload,
            new
        );
        assert!(matches!(
            service.path_handle(Default::default(), root.open_id, replaced.open_id),
            Err(2)
        ));
        for opened in [source, replaced, root] {
            service.provider_close(opened.open_id).unwrap();
        }
    }
}

#[test]
fn raw_file_replacement_does_not_change_an_already_open_description() {
    for mounted in [false, true] {
        let mut service = test_filesystem();
        if mounted {
            service.mount_devices(b"/dev", Default::default()).unwrap();
        }
        let create = |service: &mut FilesystemService, path: &[u8], bytes: &[u8]| {
            let id = service
                .open_at(
                    protocol::Header {
                        flags: protocol::OPEN_AT_READ
                            | protocol::OPEN_AT_WRITE
                            | protocol::OPEN_AT_CREATE,
                        mode: 0o600,
                        ..Default::default()
                    },
                    path,
                    PathAnchors::default(),
                    root_credentials(),
                )
                .unwrap()
                .header
                .open_id;
            service.provider_write(id, bytes).unwrap();
            id
        };
        let source = create(&mut service, b"/file-\xff", b"new");
        let replaced = create(&mut service, b"/file-\xfe", b"old");
        rename(&mut service, b"/file-\xff", b"/file-\xfe");
        service
            .provider_seek(replaced, 0, HANDLE_SEEK_START)
            .unwrap();
        assert_eq!(service.provider_read(replaced, 3).unwrap(), b"old");
        service.provider_close(source).unwrap();
        service.provider_close(replaced).unwrap();
    }
}
