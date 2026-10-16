use super::*;

fn resolve(
    service: &FilesystemService,
    path: &[u8],
    anchors: PathAnchors,
    who: protocol::Credentials,
) -> Result<Vec<u8>, i32> {
    let flags = if anchors.root_open_id.is_some() {
        protocol::STAT_AT_ROOT_ATTACHED
    } else {
        0
    } | if anchors.base_open_id.is_some() {
        protocol::STAT_AT_BASE_ATTACHED
    } else {
        0
    };
    service
        .canonical_path_at(
            protocol::Header {
                opcode: protocol::OP_CANONICAL_PATH_AT,
                flags,
                ..Default::default()
            },
            path,
            anchors,
            who,
        )
        .map(|response| {
            assert_eq!(response.header.length as usize, response.payload.len());
            response.payload
        })
}

fn directory(service: &mut FilesystemService, path: &[u8]) -> u64 {
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
        .open_id
}

#[test]
fn resolves_symlinks_before_parent_components_and_checks_existence() {
    for mounted in [false, true] {
        let mut service = test_filesystem();
        if mounted {
            service.mount_devices(b"/dev", Default::default()).unwrap();
        }
        for (input, expected) in [
            (b"/directory-link/..".as_slice(), b"/jail".as_slice()),
            (b"/relative-link/./..", b"/jail"),
            (b"//jail///inside/", b"/jail/inside"),
            (b"/redirect", b"/blocked/child"),
            (b"/../../", b"/"),
        ] {
            assert_eq!(
                resolve(&service, input, PathAnchors::default(), root_credentials()).unwrap(),
                expected
            );
        }
        for (input, error) in [
            (b"/missing".as_slice(), 2),
            (b"/missing/../jail", 2),
            (b"/create-base/dangling", 2),
            (b"/redirect/", 20),
            (b"/loop", 40),
            (b"", 2),
        ] {
            assert_eq!(
                resolve(&service, input, PathAnchors::default(), root_credentials()),
                Err(error),
                "{input:?}, namespace={mounted}"
            );
        }
        assert_eq!(
            resolve(
                &service,
                b"/redirect",
                PathAnchors::default(),
                credentials(501, 20, &[])
            ),
            Err(13)
        );
        // Search-only directories do not require readable directory authority.
        assert_eq!(
            resolve(
                &service,
                b"/search-only/.",
                PathAnchors::default(),
                credentials(501, 20, &[])
            )
            .unwrap(),
            b"/search-only"
        );
        if mounted {
            assert_eq!(
                resolve(
                    &service,
                    b"/dev/null",
                    PathAnchors::default(),
                    root_credentials()
                )
                .unwrap(),
                b"/dev/null"
            );
        }
    }
}

#[test]
fn honors_retained_cwd_root_and_live_rename_without_lexical_fallback() {
    for mounted in [false, true] {
        let mut service = test_filesystem();
        if mounted {
            service.mount_devices(b"/dev", Default::default()).unwrap();
        }
        let root = directory(&mut service, b"/jail");
        let cwd = directory(&mut service, b"/jail/inside");
        let anchors = PathAnchors {
            root_open_id: Some(root),
            base_open_id: Some(cwd),
        };
        for (input, expected) in [
            (b".".as_slice(), b"/inside".as_slice()),
            (b"../../..", b"/"),
            (b"/inside", b"/inside"),
        ] {
            assert_eq!(
                resolve(&service, input, anchors, root_credentials()).unwrap(),
                expected
            );
        }
        assert_eq!(
            resolve(&service, b"/escape", anchors, root_credentials()),
            Err(2)
        );
        let old = b"/jail/inside";
        let mut payload = old.to_vec();
        payload.extend_from_slice(b"/jail/moved");
        assert_eq!(
            service
                .handle(
                    protocol::Header {
                        opcode: protocol::OP_RENAME,
                        offset: old.len() as u64,
                        ..Default::default()
                    },
                    &payload
                )
                .header
                .status,
            0
        );
        assert_eq!(
            resolve(&service, b".", anchors, root_credentials()).unwrap(),
            b"/moved"
        );
        assert_eq!(
            service
                .handle(
                    protocol::Header {
                        opcode: protocol::OP_UNLINK,
                        flags: protocol::NODE_TYPE_DIRECTORY,
                        ..Default::default()
                    },
                    b"/jail/moved"
                )
                .header
                .status,
            0
        );
        assert_eq!(resolve(&service, b".", anchors, root_credentials()), Err(2));
        service.provider_close(cwd).unwrap();
        service.provider_close(root).unwrap();
    }
}

#[test]
fn rejects_unmatched_anchor_flags_and_nofollow() {
    let service = test_filesystem();
    for flags in [
        protocol::STAT_AT_ROOT_ATTACHED,
        protocol::STAT_AT_BASE_ATTACHED,
        protocol::STAT_AT_NOFOLLOW,
        u32::MAX,
    ] {
        assert!(matches!(
            service.canonical_path_at(
                protocol::Header {
                    flags,
                    ..Default::default()
                },
                b"/",
                PathAnchors::default(),
                root_credentials()
            ),
            Err(22)
        ));
    }
}

#[test]
fn preserves_raw_names_hard_link_spelling_and_mounted_volume_paths() {
    for mounted in [false, true] {
        let mut service = test_filesystem();
        if mounted {
            let (volume, _) = buffered_filesystem();
            service.mount_volume(b"/outside", volume).unwrap();
        }
        let raw = b"/raw-\xff";
        assert_eq!(
            service
                .mkdir_at(
                    protocol::Header {
                        opcode: protocol::OP_MKDIR_AT,
                        mode: 0o755,
                        ..Default::default()
                    },
                    raw,
                    PathAnchors::default(),
                    root_credentials()
                )
                .unwrap()
                .header
                .status,
            0
        );
        assert_eq!(
            resolve(&service, raw, PathAnchors::default(), root_credentials()).unwrap(),
            raw
        );
        let file = service
            .open_at(
                protocol::Header {
                    flags: protocol::OPEN_AT_READ | protocol::OPEN_AT_CREATE,
                    mode: 0,
                    ..Default::default()
                },
                b"/outside/first",
                PathAnchors::default(),
                root_credentials(),
            )
            .unwrap()
            .header
            .open_id;
        let old = b"/outside/first";
        let mut names = old.to_vec();
        names.extend_from_slice(b"/outside/second");
        service
            .link_at(
                protocol::Header {
                    opcode: protocol::OP_LINK_AT,
                    mode: old.len() as u32,
                    ..Default::default()
                },
                &names,
                RenameAnchors::default(),
                root_credentials(),
            )
            .unwrap();
        // Canonicalization neither requires file read permission nor replaces a
        // hard link's requested spelling with a different name for that inode.
        assert_eq!(
            resolve(
                &service,
                b"/outside/second",
                PathAnchors::default(),
                credentials(501, 20, &[])
            )
            .unwrap(),
            b"/outside/second"
        );
        assert_eq!(
            resolve(
                &service,
                b"/outside/first",
                PathAnchors::default(),
                root_credentials()
            )
            .unwrap(),
            b"/outside/first"
        );
        service.provider_close(file).unwrap();
    }
}
