use std::error::Error;
use std::fs;
use std::io;
use std::os::unix::fs::symlink;
use std::path::PathBuf;
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use ext4plus::{Ext4, Ext4Read, Ext4Write};
use filesystem_service::namespace::{Namespace, Node};
use filesystem_service::path_walk::{Credentials, Resolution};
use filesystem_service::service::{FilesystemService, PathAnchors, RenameAnchors};
use mochios_filesystem_protocol as protocol;
#[path = "support/unmapped_updates.rs"]
mod unmapped_updates;

#[derive(Clone)]
struct Image(Arc<Mutex<Vec<u8>>>);
impl Ext4Read for Image {
    fn read(&self, offset: u64, output: &mut [u8]) -> Result<(), Box<dyn Error + Send + Sync>> {
        let start = usize::try_from(offset)?;
        let end = start
            .checked_add(output.len())
            .ok_or_else(|| io::Error::other("offset overflow"))?;
        output.copy_from_slice(
            self.0
                .lock()
                .map_err(|_| io::Error::other("image lock poisoned"))?
                .get(start..end)
                .ok_or_else(|| io::Error::other("outside image"))?,
        );
        Ok(())
    }
}

impl Ext4Write for Image {
    fn write(&self, offset: u64, input: &[u8]) -> Result<(), Box<dyn Error + Send + Sync>> {
        let start = usize::try_from(offset)?;
        let end = start
            .checked_add(input.len())
            .ok_or_else(|| io::Error::other("offset overflow"))?;
        self.0
            .lock()
            .map_err(|_| io::Error::other("image lock poisoned"))?
            .get_mut(start..end)
            .ok_or_else(|| io::Error::other("outside image"))?
            .copy_from_slice(input);
        Ok(())
    }
}

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path =
            std::env::temp_dir().join(format!("mochios-mount-{}-{nonce}", std::process::id()));
        fs::create_dir(&path).unwrap();
        Self(path)
    }

    fn volume(&self, name: &str) -> Ext4 {
        let source = self.0.join(name);
        fs::create_dir(&source).unwrap();
        fs::create_dir(source.join("mount")).unwrap();
        fs::create_dir(source.join("nested")).unwrap();
        fs::create_dir(source.join("blocked")).unwrap();
        fs::write(source.join("file"), name.as_bytes()).unwrap();
        fs::write(source.join("mount/hidden"), b"covered").unwrap();
        fs::write(source.join("blocked/private"), b"private").unwrap();
        fs::write(source.join("nested/inside"), name.as_bytes()).unwrap();
        symlink("/file", source.join("nested/absolute")).unwrap();
        symlink("../file", source.join("nested/relative")).unwrap();
        symlink("/file", source.join("absolute")).unwrap();
        symlink("../file", source.join("relative")).unwrap();
        let image = self.0.join(format!("{name}.ext4"));
        let output = Command::new("mke2fs")
            .args(["-q", "-t", "ext4", "-F", "-d"])
            .arg(source)
            .arg(&image)
            .arg("8192")
            .output()
            .expect("mke2fs required for filesystem integration tests");
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let output = Command::new("debugfs")
            .args(["-w", "-R", "set_inode_field /blocked mode 040000"])
            .arg(&image)
            .output()
            .expect("debugfs required for filesystem integration tests");
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let image = Image(Arc::new(Mutex::new(fs::read(image).unwrap())));
        Ext4::load_with_writer(Box::new(image.clone()), Some(Box::new(image))).unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn credentials() -> Credentials<'static> {
    Credentials {
        uid: 501,
        gid: 20,
        groups: &[],
    }
}
fn found(result: Result<Resolution<Node>, i32>) -> Node {
    match result.unwrap() {
        Resolution::Found { inode, .. } => inode,
        Resolution::Missing { .. } => panic!("expected existing node"),
    }
}
fn walk(namespace: &Namespace, base: Node, path: &[u8]) -> Node {
    found(namespace.resolve(namespace.root(), base, path, true, credentials()))
}

fn device_open(
    service: &mut FilesystemService,
    path: &[u8],
    flags: u32,
    anchors: PathAnchors,
) -> Result<u64, i32> {
    service
        .open_at(
            protocol::Header {
                flags,
                ..protocol::Header::default()
            },
            path,
            anchors,
            root_credentials(),
        )
        .map(|response| response.header.open_id)
}

#[test]
fn device_path_operations_preserve_existing_missing_and_wrong_type_errors() {
    let fixture = Fixture::new();
    let mut service = FilesystemService::new(fixture.volume("device-path-errors"));
    service
        .mount_devices(
            b"/dev",
            filesystem_service::devfs::DeviceFilesystem::default(),
        )
        .unwrap();
    for path in [b"/dev".as_slice(), b"/dev/null"] {
        assert!(matches!(
            service.chmod_at(
                protocol::Header {
                    mode: 0o600,
                    ..protocol::Header::default()
                },
                path,
                PathAnchors::default(),
                root_credentials()
            ),
            Err(30)
        ));
        assert!(matches!(
            service.chown_at(
                protocol::Header::default(),
                path,
                PathAnchors::default(),
                root_credentials()
            ),
            Err(30)
        ));
        assert!(matches!(
            service.readlink_at(
                protocol::Header::default(),
                path,
                PathAnchors::default(),
                root_credentials()
            ),
            Err(22)
        ));
    }
    assert!(matches!(
        service.truncate_at(
            protocol::Header::default(),
            b"/dev/null",
            PathAnchors::default(),
            root_credentials()
        ),
        Err(22)
    ));
    assert!(matches!(
        service.truncate_at(
            protocol::Header::default(),
            b"/dev",
            PathAnchors::default(),
            root_credentials()
        ),
        Err(21)
    ));
    for path in [b"/dev/missing".as_slice(), b"/missing"] {
        assert!(matches!(
            service.chmod_at(
                protocol::Header::default(),
                path,
                PathAnchors::default(),
                root_credentials()
            ),
            Err(2)
        ));
        assert!(matches!(
            service.chown_at(
                protocol::Header::default(),
                path,
                PathAnchors::default(),
                root_credentials()
            ),
            Err(2)
        ));
        assert!(matches!(
            service.readlink_at(
                protocol::Header::default(),
                path,
                PathAnchors::default(),
                root_credentials()
            ),
            Err(2)
        ));
        assert!(matches!(
            service.truncate_at(
                protocol::Header::default(),
                path,
                PathAnchors::default(),
                root_credentials()
            ),
            Err(2)
        ));
    }
    assert!(matches!(
        service.readlink_at(
            protocol::Header::default(),
            b"/dev/null/child",
            PathAnchors::default(),
            root_credentials()
        ),
        Err(20)
    ));
    let null = device_open(
        &mut service,
        b"/dev/null",
        protocol::OPEN_AT_WRITE,
        PathAnchors::default(),
    )
    .unwrap();
    assert_eq!(service.provider_write(null, b"unchanged"), Ok(9));
}

#[test]
fn device_metadata_errors_follow_nodes_but_nofollow_retains_disk_symlink_identity() {
    let fixture = Fixture::new();
    let data = fixture.volume("device-path-symlink");
    let mut directory =
        ext4plus::dir::Dir::open_inode(&data, data.read_root_inode().unwrap()).unwrap();
    data.symlink(
        &mut directory,
        ext4plus::DirEntryName::try_from("alias").unwrap(),
        ext4plus::path::PathBuf::try_from("/dev/null").unwrap(),
        0,
        0,
        std::time::Duration::ZERO,
    )
    .unwrap();
    let mut service = FilesystemService::new(data);
    service
        .mount_devices(
            b"/dev",
            filesystem_service::devfs::DeviceFilesystem::default(),
        )
        .unwrap();
    assert!(matches!(
        service.chmod_at(
            protocol::Header::default(),
            b"/alias",
            PathAnchors::default(),
            root_credentials()
        ),
        Err(30)
    ));
    assert!(matches!(
        service.chown_at(
            protocol::Header::default(),
            b"/alias",
            PathAnchors::default(),
            root_credentials()
        ),
        Err(30)
    ));
    assert!(matches!(
        service.truncate_at(
            protocol::Header::default(),
            b"/alias",
            PathAnchors::default(),
            root_credentials()
        ),
        Err(22)
    ));
    assert_eq!(
        service
            .readlink_at(
                protocol::Header::default(),
                b"/alias",
                PathAnchors::default(),
                root_credentials()
            )
            .unwrap()
            .payload,
        b"/dev/null"
    );
    service
        .chown_at(
            protocol::Header {
                flags: protocol::CHOWN_AT_NOFOLLOW,
                node_id: (1001 << 32) | 1001,
                ..protocol::Header::default()
            },
            b"/alias",
            PathAnchors::default(),
            root_credentials(),
        )
        .unwrap();
    let alias = service
        .stat_at(
            protocol::Header {
                flags: protocol::STAT_AT_NOFOLLOW,
                ..protocol::Header::default()
            },
            b"/alias",
            PathAnchors::default(),
            root_credentials(),
        )
        .unwrap();
    let null = service
        .stat_at(
            protocol::Header::default(),
            b"/dev/null",
            PathAnchors::default(),
            root_credentials(),
        )
        .unwrap();
    assert_eq!(
        protocol::decode_node_status(&alias.payload).unwrap().uid,
        1001
    );
    assert_eq!(protocol::decode_node_status(&null.payload).unwrap().uid, 0);
}

#[test]
fn device_path_mutations_keep_root_confinement_and_search_permission_checks() {
    let fixture = Fixture::new();
    let mut service = FilesystemService::new(fixture.volume("device-path-authority"));
    service
        .mount_devices(
            b"/dev",
            filesystem_service::devfs::DeviceFilesystem::default(),
        )
        .unwrap();
    let root = device_open(
        &mut service,
        b"/",
        protocol::OPEN_AT_READ | protocol::OPEN_AT_DIRECTORY,
        PathAnchors::default(),
    )
    .unwrap();
    let dev = device_open(
        &mut service,
        b"/dev",
        protocol::OPEN_AT_READ | protocol::OPEN_AT_DIRECTORY,
        PathAnchors::default(),
    )
    .unwrap();
    let scoped = PathAnchors {
        root_open_id: Some(dev),
        base_open_id: Some(dev),
    };
    let chmod = protocol::Header {
        flags: protocol::CHMOD_AT_ROOT_ATTACHED | protocol::CHMOD_AT_BASE_ATTACHED,
        ..protocol::Header::default()
    };
    assert!(matches!(
        service.chmod_at(chmod, b"../../null", scoped, root_credentials()),
        Err(30)
    ));
    assert!(matches!(
        service.chmod_at(
            chmod,
            b"null",
            PathAnchors {
                root_open_id: Some(dev),
                base_open_id: Some(root)
            },
            root_credentials()
        ),
        Err(13)
    ));
    assert!(matches!(
        service.chmod_at(chmod, b"null", PathAnchors::default(), root_credentials()),
        Err(22)
    ));
    let mut user = root_credentials();
    user.effective_uid = 501;
    user.effective_gid = 20;
    assert!(matches!(
        service.chmod_at(
            protocol::Header::default(),
            b"/blocked/private",
            PathAnchors::default(),
            user
        ),
        Err(13)
    ));
}

#[test]
fn device_mutations_distinguish_valid_resources_from_closed_descriptions() {
    let fixture = Fixture::new();
    let mut service = FilesystemService::new(fixture.volume("device-mutations"));
    service
        .mount_devices(
            b"/dev",
            filesystem_service::devfs::DeviceFilesystem::default(),
        )
        .unwrap();
    let null = device_open(
        &mut service,
        b"/dev/null",
        protocol::OPEN_AT_WRITE,
        PathAnchors::default(),
    )
    .unwrap();
    let directory = device_open(
        &mut service,
        b"/dev",
        protocol::OPEN_AT_READ | protocol::OPEN_AT_DIRECTORY,
        PathAnchors::default(),
    )
    .unwrap();
    let before = service
        .stat_handle(protocol::Header::default(), null)
        .unwrap()
        .payload;
    assert!(matches!(
        service.truncate_handle(protocol::Header::default(), null),
        Err(22)
    ));
    assert!(matches!(
        service.truncate_handle(protocol::Header::default(), directory),
        Err(21)
    ));
    let chmod = protocol::Header {
        mode: 0o600,
        ..protocol::Header::default()
    };
    let chown = protocol::Header {
        node_id: (1001 << 32) | 1001,
        ..protocol::Header::default()
    };
    for id in [null, directory] {
        assert!(matches!(
            service.chmod_handle(chmod, id, root_credentials()),
            Err(30)
        ));
        assert!(matches!(
            service.chown_handle(chown, id, root_credentials()),
            Err(30)
        ));
        assert!(matches!(
            service.chmod_handle(
                protocol::Header {
                    mode: u32::MAX,
                    ..chmod
                },
                id,
                root_credentials()
            ),
            Err(22)
        ));
        assert!(matches!(
            service.chown_handle(
                protocol::Header {
                    flags: u32::MAX,
                    ..chown
                },
                id,
                root_credentials()
            ),
            Err(22)
        ));
    }
    assert_eq!(
        service
            .stat_handle(protocol::Header::default(), null)
            .unwrap()
            .payload,
        before
    );
    assert_eq!(service.provider_write(null, b"still usable"), Ok(12));
    service.provider_close(null).unwrap();
    assert!(matches!(
        service.truncate_handle(protocol::Header::default(), null),
        Err(9)
    ));
    assert!(matches!(
        service.chmod_handle(chmod, null, root_credentials()),
        Err(9)
    ));
    assert!(matches!(
        service.chown_handle(chown, null, root_credentials()),
        Err(9)
    ));
}

#[test]
fn device_provider_uses_one_id_space_and_never_allocates_regular_file_backing() {
    let fixture = Fixture::new();
    let mut service = FilesystemService::new(fixture.volume("device-provider"));
    service
        .mount_devices(
            b"/dev",
            filesystem_service::devfs::DeviceFilesystem::default(),
        )
        .unwrap();
    let disk = device_open(
        &mut service,
        b"/file",
        protocol::OPEN_AT_READ,
        PathAnchors::default(),
    )
    .unwrap();
    let reader = device_open(
        &mut service,
        b"/dev/null",
        protocol::OPEN_AT_READ,
        PathAnchors::default(),
    )
    .unwrap();
    let writer = device_open(
        &mut service,
        b"/dev/null",
        protocol::OPEN_AT_WRITE,
        PathAnchors::default(),
    )
    .unwrap();
    assert_ne!(disk, reader);
    assert_ne!(reader, writer);
    assert_eq!(
        service.provider_read(disk, 100).unwrap(),
        b"device-provider"
    );
    assert_eq!(service.provider_read(reader, 4096).unwrap(), b"");
    assert_eq!(
        service.provider_read_at(reader, u64::MAX, 4096).unwrap(),
        b""
    );
    let mut storage = [42; 64];
    assert_eq!(service.provider_read_into(reader, &mut storage), Ok((0, 0)));
    assert_eq!(storage, [42; 64]);
    assert_eq!(service.provider_write(reader, b"x"), Err(13));
    assert_eq!(service.provider_read(writer, 1), Err(13));
    assert_eq!(
        service.provider_write_with_offset(writer, b"discard"),
        Ok((7, 0))
    );
    assert_eq!(
        service.provider_write_at(writer, u64::MAX, b"discard"),
        Ok(7)
    );
    for basis in [
        mnu_abi::HANDLE_SEEK_START,
        mnu_abi::HANDLE_SEEK_CURRENT,
        mnu_abi::HANDLE_SEEK_END,
    ] {
        assert_eq!(service.provider_seek(writer, i64::MIN, basis), Ok(0));
    }
    assert_eq!(service.provider_memory_object(reader), Err(95));
    assert_eq!(service.provider_sync(writer), Err(22));
    let status = service
        .stat_handle(protocol::Header::default(), writer)
        .unwrap();
    let status = protocol::decode_node_status(&status.payload).unwrap();
    assert_eq!(
        (
            status.mode,
            status.special_device,
            status.size,
            status.node_id
        ),
        (0o020666, 259, 0, (1 << 32) | 2)
    );
    service
        .set_flags_handle(
            protocol::Header {
                flags: protocol::OPEN_STATUS_NONBLOCK,
                ..protocol::Header::default()
            },
            writer,
        )
        .unwrap();
    assert_eq!(
        service
            .get_flags_handle(protocol::Header::default(), writer)
            .unwrap()
            .header
            .flags,
        protocol::OPEN_STATUS_NONBLOCK
    );
    assert_eq!(
        service
            .get_flags_handle(protocol::Header::default(), reader)
            .unwrap()
            .header
            .flags,
        0
    );
    service.provider_close(reader).unwrap();
    assert_eq!(service.provider_read(reader, 1), Err(9));
    assert_eq!(service.provider_close(reader), Err(9));
    assert_eq!(service.provider_write(writer, b"still open"), Ok(10));
}

#[test]
fn device_directory_cursor_records_are_opt_in_and_resume_at_the_exact_entry() {
    let fixture = Fixture::new();
    let mut service = FilesystemService::new(fixture.volume("device-cursor"));
    service
        .mount_devices(b"/mount", filesystem_service::devfs::DeviceFilesystem::default())
        .unwrap();
    for cursor in [false, true] {
        let flags = protocol::OPEN_AT_READ
            | protocol::OPEN_AT_DIRECTORY
            | if cursor { protocol::OPEN_AT_CURSOR_RECORDS } else { 0 };
        let directory = device_open(&mut service, b"/mount", flags, PathAnchors::default()).unwrap();
        let mut names = Vec::new();
        loop {
            let bytes = service
                .provider_read(directory, protocol::CURSOR_DIRENT_HEADER_LEN + 4)
                .unwrap();
            if bytes.is_empty() {
                break;
            }
            let (header, name, consumed) = protocol::decode_dir_entry(&bytes).unwrap();
            assert_eq!(consumed, bytes.len());
            names.push(name.to_vec());
            assert_eq!(header.next_position, cursor.then_some(names.len() as u64));
            if cursor {
                let next = header.next_position.unwrap();
                assert_eq!(
                    service.provider_seek(directory, next as i64, mnu_abi::HANDLE_SEEK_START),
                    Ok(next)
                );
            }
        }
        assert_eq!(names, [b".".to_vec(), b"..".to_vec(), b"null".to_vec()]);
        service.provider_close(directory).unwrap();
    }
}

#[test]
fn device_directory_handles_support_relative_open_cwd_and_confined_roots() {
    let fixture = Fixture::new();
    let mut service = FilesystemService::new(fixture.volume("device-directories"));
    service
        .mount_devices(
            b"/mount",
            filesystem_service::devfs::DeviceFilesystem::default(),
        )
        .unwrap();
    let root = device_open(
        &mut service,
        b"/",
        protocol::OPEN_AT_READ | protocol::OPEN_AT_DIRECTORY,
        PathAnchors::default(),
    )
    .unwrap();
    let directory = device_open(
        &mut service,
        b"/mount",
        protocol::OPEN_AT_READ | protocol::OPEN_AT_DIRECTORY,
        PathAnchors::default(),
    )
    .unwrap();
    let path = service
        .path_handle(protocol::Header::default(), root, directory)
        .unwrap();
    assert_eq!(path.payload, b"/mount");
    let relative = device_open(
        &mut service,
        b"null",
        protocol::OPEN_AT_READ | protocol::OPEN_AT_BASE_ATTACHED,
        PathAnchors {
            root_open_id: None,
            base_open_id: Some(directory),
        },
    )
    .unwrap();
    assert_eq!(service.provider_read(relative, 1).unwrap(), b"");
    let confined = device_open(
        &mut service,
        b"../../null",
        protocol::OPEN_AT_READ | protocol::OPEN_AT_ROOT_ATTACHED | protocol::OPEN_AT_BASE_ATTACHED,
        PathAnchors {
            root_open_id: Some(directory),
            base_open_id: Some(directory),
        },
    )
    .unwrap();
    assert_eq!(service.provider_read(confined, 1).unwrap(), b"");
    let parent = device_open(
        &mut service,
        b"../file",
        protocol::OPEN_AT_READ | protocol::OPEN_AT_BASE_ATTACHED,
        PathAnchors {
            root_open_id: None,
            base_open_id: Some(directory),
        },
    )
    .unwrap();
    assert_eq!(
        service.provider_read(parent, 100).unwrap(),
        b"device-directories"
    );
    let mut names = Vec::new();
    loop {
        let bytes = service
            .provider_read(directory, protocol::CURSOR_DIRENT_HEADER_LEN + 4)
            .unwrap();
        if bytes.is_empty() {
            break;
        }
        let (_, name, length) = protocol::decode_dir_entry(&bytes).unwrap();
        assert_eq!(length, bytes.len());
        names.push(name.to_vec());
    }
    assert_eq!(names, vec![b".".to_vec(), b"..".to_vec(), b"null".to_vec()]);
    assert_eq!(
        service.provider_seek(directory, 0, mnu_abi::HANDLE_SEEK_START),
        Ok(0)
    );
    assert!(!service.provider_read(directory, 4096).unwrap().is_empty());
    assert_eq!(service.provider_write(directory, b"x"), Err(21));
}

#[test]
fn device_path_metadata_and_open_flags_do_not_bypass_directory_or_exclusive_checks() {
    let fixture = Fixture::new();
    let mut service = FilesystemService::new(fixture.volume("device-flags"));
    service
        .mount_devices(
            b"/dev",
            filesystem_service::devfs::DeviceFilesystem::default(),
        )
        .unwrap();
    assert_eq!(
        device_open(
            &mut service,
            b"/dev/null",
            protocol::OPEN_AT_READ | protocol::OPEN_AT_DIRECTORY,
            PathAnchors::default()
        ),
        Err(20)
    );
    assert_eq!(
        device_open(
            &mut service,
            b"/dev",
            protocol::OPEN_AT_WRITE,
            PathAnchors::default()
        ),
        Err(21)
    );
    assert_eq!(
        device_open(
            &mut service,
            b"/dev/null",
            protocol::OPEN_AT_WRITE | protocol::OPEN_AT_CREATE | protocol::OPEN_AT_EXCLUSIVE,
            PathAnchors::default()
        ),
        Err(17)
    );
    assert_eq!(
        device_open(
            &mut service,
            b"/dev/missing",
            protocol::OPEN_AT_WRITE | protocol::OPEN_AT_CREATE,
            PathAnchors::default()
        ),
        Err(30)
    );
    let status = service
        .stat_at(
            protocol::Header::default(),
            b"/dev/null",
            PathAnchors::default(),
            root_credentials(),
        )
        .unwrap();
    let status = protocol::decode_node_status(&status.payload).unwrap();
    assert_eq!(status.mode, 0o020666);
    assert!(
        service
            .access_at(
                protocol::Header {
                    flags: protocol::ACCESS_AT_READ | protocol::ACCESS_AT_WRITE,
                    ..protocol::Header::default()
                },
                b"/dev/null",
                PathAnchors::default(),
                root_credentials()
            )
            .is_ok()
    );
    assert!(matches!(
        service.access_at(
            protocol::Header {
                flags: protocol::ACCESS_AT_EXECUTE,
                ..protocol::Header::default()
            },
            b"/dev/null",
            PathAnchors::default(),
            root_credentials()
        ),
        Err(13)
    ));
}

#[test]
fn device_mounts_share_namespace_traversal_without_ext4_inode_aliases() {
    let fixture = Fixture::new();
    let data = fixture.volume("device-data");
    let mut directory =
        ext4plus::dir::Dir::open_inode(&data, data.read_root_inode().unwrap()).unwrap();
    data.symlink(
        &mut directory,
        ext4plus::DirEntryName::try_from("null-alias").unwrap(),
        ext4plus::path::PathBuf::try_from("/device/null").unwrap(),
        0,
        0,
        std::time::Duration::ZERO,
    )
    .unwrap();
    let mut namespace = Namespace::new(data.clone()).unwrap();
    let root = namespace.root();
    let mounted = namespace
        .mount_named_devices(
            root.clone(),
            b"device",
            filesystem_service::devfs::DeviceFilesystem::default(),
        )
        .unwrap();
    let null = walk(&namespace, root.clone(), b"/device/null");
    assert_ne!(root.id(), null.id()); // Root inode 2 and device inode 2 differ by volume.
    assert_eq!(
        walk(&namespace, root.clone(), b"/null-alias").id(),
        null.id()
    );
    assert_eq!(walk(&namespace, mounted.clone(), b"null").id(), null.id());
    assert_eq!(
        walk(&namespace, mounted.clone(), b"../file").id(),
        walk(&namespace, root.clone(), b"file").id()
    );
    let confined = found(namespace.resolve(
        mounted.clone(),
        mounted.clone(),
        b"../../null",
        true,
        credentials(),
    ));
    assert_eq!(confined.id(), null.id());
    assert!(matches!(
        namespace.resolve(mounted.clone(), root.clone(), b"file", true, credentials()),
        Err(13)
    ));
    assert!(matches!(
        namespace.resolve(
            root.clone(),
            root.clone(),
            b"/device/null/",
            true,
            credentials()
        ),
        Err(20)
    ));
    let status = namespace.device_status(&null).unwrap();
    assert_eq!(
        (status.device, status.node_id, status.special_device),
        (1, 2, 259)
    );
    assert!(matches!(null.metadata(), Err(95)));
    assert!(data.symlink_metadata("/device").is_err());
    assert!(matches!(
        namespace.mount_named_devices(
            root,
            b"device",
            filesystem_service::devfs::DeviceFilesystem::default()
        ),
        Err(17)
    ));
}

#[test]
fn covered_device_mount_hides_disk_children_and_preserves_parent_edges() {
    let fixture = Fixture::new();
    let mut namespace = Namespace::new(fixture.volume("covered-device-data")).unwrap();
    let root = namespace.root();
    let at = walk(&namespace, root.clone(), b"/mount");
    let mounted = namespace
        .mount_devices(
            at.clone(),
            filesystem_service::devfs::DeviceFilesystem::default(),
        )
        .unwrap();
    assert!(matches!(
        namespace
            .resolve(
                root.clone(),
                root.clone(),
                b"/mount/hidden",
                true,
                credentials()
            )
            .unwrap(),
        Resolution::Missing { .. }
    ));
    assert_eq!(walk(&namespace, mounted.clone(), b"..").id(), root.id());
    assert_eq!(
        walk(&namespace, root.clone(), b"/mount/null")
            .device_node()
            .unwrap()
            .kind(),
        filesystem_service::devfs::NodeKind::Null
    );
    assert!(matches!(
        namespace.mount_devices(at, filesystem_service::devfs::DeviceFilesystem::default()),
        Err(16)
    ));
    assert!(matches!(
        namespace.mount_devices(
            mounted,
            filesystem_service::devfs::DeviceFilesystem::default()
        ),
        Err(16)
    ));
}

#[test]
fn device_mount_authority_does_not_accept_another_namespaces_nodes() {
    let fixture = Fixture::new();
    let mut namespace = Namespace::new(fixture.volume("owned-device-data")).unwrap();
    let mut other = Namespace::new(fixture.volume("foreign-device-data")).unwrap();
    let foreign = other
        .mount_named_devices(
            other.root(),
            b"device",
            filesystem_service::devfs::DeviceFilesystem::default(),
        )
        .unwrap();
    assert!(matches!(
        namespace.mount_named_devices(
            foreign.clone(),
            b"nested",
            filesystem_service::devfs::DeviceFilesystem::default()
        ),
        Err(13)
    ));
    assert!(matches!(
        namespace.mount_devices(
            foreign.clone(),
            filesystem_service::devfs::DeviceFilesystem::default()
        ),
        Err(13)
    ));
    assert!(matches!(namespace.device_status(&foreign), Err(13)));
    assert!(matches!(
        namespace.resolve(namespace.root(), foreign, b"null", true, credentials()),
        Err(13)
    ));
}

#[test]
fn named_source_mount_projects_a_directory_without_modifying_the_parent_volume() {
    let fixture = Fixture::new();
    let data = fixture.volume("data");
    let mut namespace = Namespace::new(data.clone()).unwrap();
    let root = namespace.root();
    let mounted = namespace
        .mount_named(
            root.clone(),
            b"system",
            fixture.volume("system"),
            b"/nested",
        )
        .unwrap();
    let inside = walk(&namespace, root.clone(), b"/system/inside");
    assert_eq!(inside.id().volume, mounted.id().volume);
    let data_file = walk(&namespace, root.clone(), b"/file");
    for path in [
        b"/system/../file".as_slice(),
        b"/system/absolute",
        b"/system/relative",
    ] {
        assert_eq!(walk(&namespace, root.clone(), path).id(), data_file.id());
    }
    assert!(matches!(
        namespace.resolve(
            mounted.clone(),
            mounted.clone(),
            b"/absolute",
            true,
            credentials()
        ),
        Ok(Resolution::Missing { .. })
    ));
    assert!(matches!(
        namespace.resolve(mounted.clone(), root.clone(), b"file", true, credentials()),
        Err(13)
    ));
    assert!(data.symlink_metadata("/system").is_err());
    assert!(matches!(
        namespace.mount_named(
            root.clone(),
            b"system",
            fixture.volume("duplicate"),
            b"/nested"
        ),
        Err(17)
    ));
    assert!(matches!(
        namespace.mount_named(
            root.clone(),
            b"file",
            fixture.volume("collision"),
            b"/nested"
        ),
        Err(17)
    ));
    assert!(matches!(
        namespace.mount_named(
            root.clone(),
            b"bad-source",
            fixture.volume("not-directory"),
            b"/file"
        ),
        Err(20)
    ));
    assert!(matches!(
        namespace.mount_named(root, b"..", fixture.volume("invalid-name"), b"/nested"),
        Err(22)
    ));
}

#[test]
fn named_mount_handles_report_namespace_paths_and_paginated_directory_entries() {
    let fixture = Fixture::new();
    let mut service = FilesystemService::new(fixture.volume("data"));
    service
        .mount_named_volume(b"/", b"system", fixture.volume("system"), b"/nested")
        .unwrap();
    let flags = protocol::OPEN_AT_READ | protocol::OPEN_AT_DIRECTORY;
    let root = open(&mut service, b"/", flags, PathAnchors::default());
    let mounted = open(&mut service, b"/system", flags, PathAnchors::default());
    assert_eq!(
        service
            .path_handle(protocol::Header::default(), root.open_id, mounted.open_id)
            .unwrap()
            .payload,
        b"/system"
    );
    let inside = open(
        &mut service,
        b"/system/inside",
        protocol::OPEN_AT_READ,
        PathAnchors::default(),
    );
    assert_eq!(
        service.provider_read(inside.open_id, 4096).unwrap(),
        b"system"
    );
    let mut entries = Vec::new();
    loop {
        let payload = service.provider_read(root.open_id, 64).unwrap();
        if payload.is_empty() {
            break;
        }
        let mut remaining = payload.as_slice();
        while !remaining.is_empty() {
            let (entry, name, length) = protocol::decode_dir_entry(remaining).unwrap();
            entries.push((name.to_vec(), entry.node_id));
            remaining = &remaining[length..];
        }
    }
    assert_eq!(
        entries.iter().filter(|(name, _)| name == b"system").count(),
        1
    );
    assert_eq!(
        entries
            .iter()
            .find(|(name, _)| name == b"system")
            .unwrap()
            .1,
        mounted.node_id
    );
    assert!(service.provider_read(root.open_id, 64).unwrap().is_empty());
    let payload = service.provider_read(mounted.open_id, 4096).unwrap();
    let mut remaining = payload.as_slice();
    let mut parent = None;
    while !remaining.is_empty() {
        let (entry, name, length) = protocol::decode_dir_entry(remaining).unwrap();
        if name == b".." {
            parent = Some(entry.node_id);
        }
        remaining = &remaining[length..];
    }
    assert_eq!(parent, Some(root.node_id));
}

#[test]
fn real_ext4_volumes_cross_mounts_without_inode_number_aliasing() {
    let fixture = Fixture::new();
    let mut namespace = Namespace::new(fixture.volume("data")).unwrap();
    let root = namespace.root();
    let data_file = walk(&namespace, root.clone(), b"/file");
    let at = walk(&namespace, root.clone(), b"/mount");
    let mounted = namespace.mount(at, fixture.volume("system")).unwrap();
    let system_file = walk(&namespace, root.clone(), b"/mount/file");
    assert_eq!(data_file.id().inode, system_file.id().inode);
    assert_ne!(data_file.id(), system_file.id());
    assert_eq!(
        walk(&namespace, mounted.clone(), b"../file").id(),
        data_file.id()
    );
    assert_eq!(
        walk(&namespace, root.clone(), b"/mount/absolute").id(),
        data_file.id()
    );
    assert_eq!(
        walk(&namespace, root.clone(), b"/mount/relative").id(),
        data_file.id()
    );
    assert!(matches!(
        namespace.resolve(
            root.clone(),
            root.clone(),
            b"/mount/hidden",
            true,
            credentials()
        ),
        Ok(Resolution::Missing { .. })
    ));

    let nested_at = walk(&namespace, mounted, b"nested");
    let nested = namespace.mount(nested_at, fixture.volume("third")).unwrap();
    assert_eq!(walk(&namespace, nested, b"../../file").id(), data_file.id());
    assert_eq!(
        walk(&namespace, root.clone(), b"/mount/nested/file")
            .id()
            .volume,
        2
    );
}

#[test]
fn real_mount_roots_confine_links_and_reject_outside_directory_anchors() {
    let fixture = Fixture::new();
    let mut namespace = Namespace::new(fixture.volume("data")).unwrap();
    let root = namespace.root();
    let at = walk(&namespace, root.clone(), b"/mount");
    let mounted = namespace.mount(at, fixture.volume("system")).unwrap();
    let inside = walk(&namespace, root.clone(), b"/mount/file");
    for path in [b"../../file".as_slice(), b"/absolute", b"relative"] {
        assert_eq!(
            found(namespace.resolve(mounted.clone(), mounted.clone(), path, true, credentials()))
                .id(),
            inside.id()
        );
    }
    assert!(matches!(
        namespace.resolve(mounted.clone(), root.clone(), b"file", true, credentials()),
        Err(13)
    ));
    assert!(matches!(
        namespace.resolve(
            root.clone(),
            root,
            b"/mount/blocked/private",
            true,
            credentials()
        ),
        Err(13)
    ));
}

#[test]
fn namespace_identity_and_mount_validation_do_not_trust_numeric_node_ids() {
    let fixture = Fixture::new();
    let mut namespace = Namespace::new(fixture.volume("data")).unwrap();
    let other = Namespace::new(fixture.volume("other")).unwrap();
    assert_eq!(namespace.root().id(), other.root().id());
    assert!(matches!(
        namespace.resolve(namespace.root(), other.root(), b"file", true, credentials()),
        Err(13)
    ));
    assert!(matches!(
        namespace.mount(other.root(), fixture.volume("foreign")),
        Err(13)
    ));
    assert!(matches!(
        namespace.mount(namespace.root(), fixture.volume("overroot")),
        Err(16)
    ));
    let file = walk(&namespace, namespace.root(), b"file");
    assert!(matches!(
        namespace.mount(file, fixture.volume("atfile")),
        Err(20)
    ));
    let at = walk(&namespace, namespace.root(), b"mount");
    let mounted = namespace
        .mount(at.clone(), fixture.volume("mounted"))
        .unwrap();
    assert!(matches!(
        namespace.mount(at, fixture.volume("overcovered")),
        Err(16)
    ));
    assert!(matches!(
        namespace.mount(mounted, fixture.volume("overmounted")),
        Err(16)
    ));
}

fn root_credentials() -> protocol::Credentials {
    let mut bytes = [0u8; protocol::CREDENTIALS_MAX_LEN];
    let size = protocol::encode_credentials_payload(0, 0, &[], &[], &mut bytes).unwrap();
    protocol::decode_credentials_payload(&bytes[..size])
        .unwrap()
        .0
}

#[test]
fn socket_inode_creation_is_exclusive_scoped_and_not_a_regular_file_placeholder() {
    let fixture = Fixture::new();
    let mut service = FilesystemService::new(fixture.volume("socket-data"));
    service
        .mount_volume(b"/mount", fixture.volume("socket-system"))
        .unwrap();
    let mounted = open(
        &mut service,
        b"/mount",
        protocol::OPEN_AT_READ | protocol::OPEN_AT_DIRECTORY,
        PathAnchors::default(),
    );
    let anchors = PathAnchors {
        root_open_id: None,
        base_open_id: Some(mounted.open_id),
    };
    let request = protocol::Header {
        flags: protocol::SOCKET_AT_BASE_ATTACHED,
        mode: 0o100640,
        ..Default::default()
    };
    let response = service
        .create_socket_at(request, b"socket", anchors, root_credentials())
        .unwrap();
    let status = protocol::decode_node_status(&response.payload).unwrap();
    assert_eq!(status.kind, protocol::NODE_TYPE_SOCKET);
    // Filesystem wire mode carries permissions; the kind retains inode type.
    assert_eq!(status.mode, 0o640);
    assert_eq!(
        (status.uid, status.gid, status.link_count, status.size),
        (0, 0, 1, 0)
    );
    for path in [b"socket".as_slice(), b"file", b"mount", b"absolute", b"relative"] {
        assert!(matches!(
            service.create_socket_at(request, path, anchors, root_credentials()),
            Err(17)
        ));
    }
    let found = service
        .stat_at(
            protocol::Header::default(),
            b"/mount/socket",
            PathAnchors::default(),
            root_credentials(),
        )
        .unwrap();
    assert_eq!(protocol::decode_node_status(&found.payload).unwrap(), status);
    assert!(matches!(
        service.stat_at(
            protocol::Header::default(),
            b"/socket",
            PathAnchors::default(),
            root_credentials(),
        ),
        Err(2)
    ));
    for flags in [request.flags | 4, 0] {
        assert!(matches!(
            service.create_socket_at(
                protocol::Header { flags, ..request },
                b"invalid",
                anchors,
                root_credentials(),
            ),
            Err(22)
        ));
    }
    let mut bytes = [0; protocol::CREDENTIALS_MAX_LEN];
    let length = protocol::encode_credentials_payload(501, 20, &[], &[], &mut bytes).unwrap();
    let unprivileged = protocol::decode_credentials_payload(&bytes[..length])
        .unwrap()
        .0;
    assert!(matches!(
        service.create_socket_at(request, b"denied", anchors, unprivileged),
        Err(13)
    ));
    let confined = PathAnchors {
        root_open_id: Some(mounted.open_id),
        base_open_id: Some(mounted.open_id),
    };
    service
        .create_socket_at(
            protocol::Header {
                flags: protocol::SOCKET_AT_ROOT_ATTACHED | protocol::SOCKET_AT_BASE_ATTACHED,
                ..request
            },
            b"../confined-socket",
            confined,
            root_credentials(),
        )
        .unwrap();
    assert!(matches!(
        service.stat_at(
            protocol::Header::default(),
            b"/confined-socket",
            PathAnchors::default(),
            root_credentials(),
        ),
        Err(2)
    ));
    let confined_status = service
        .stat_at(
            protocol::Header::default(),
            b"/mount/confined-socket",
            PathAnchors::default(),
            root_credentials(),
        )
        .unwrap();
    assert_eq!(
        protocol::decode_node_status(&confined_status.payload).unwrap().kind,
        protocol::NODE_TYPE_SOCKET
    );
    service
        .unlink_at(
            protocol::Header {
                flags: protocol::UNLINK_AT_BASE_ATTACHED,
                ..Default::default()
            },
            b"socket",
            anchors,
            root_credentials(),
        )
        .unwrap();
    assert!(matches!(
        service.stat_at(
            protocol::Header::default(),
            b"/mount/socket",
            PathAnchors::default(),
            root_credentials(),
        ),
        Err(2)
    ));
    service.provider_close(mounted.open_id).unwrap();
}

#[test]
fn retained_socket_inode_survives_unlink_and_cannot_alias_a_recreated_name() {
    let fixture = Fixture::new();
    let mut service = FilesystemService::new(fixture.volume("socket-retained"));
    let request = protocol::Header {
        mode: 0o600,
        ..Default::default()
    };
    let response = service
        .create_socket_at_retained(
            request,
            b"/socket",
            PathAnchors::default(),
            root_credentials(),
        )
        .unwrap();
    let original = protocol::decode_node_status(&response.payload).unwrap();
    let open_id = response.header.open_id;
    assert_ne!(open_id, 0);
    assert_eq!(response.header.node_id, original.node_id);
    service
        .unlink_at(
            protocol::Header::default(),
            b"/socket",
            PathAnchors::default(),
            root_credentials(),
        )
        .unwrap();
    assert!(matches!(
        service.stat_at(
            protocol::Header::default(),
            b"/socket",
            PathAnchors::default(),
            root_credentials(),
        ),
        Err(2)
    ));
    let retained = service
        .stat_handle(protocol::Header::default(), open_id)
        .unwrap();
    let retained = protocol::decode_node_status(&retained.payload).unwrap();
    assert_eq!(retained.node_id, original.node_id);
    assert_eq!(retained.kind, protocol::NODE_TYPE_SOCKET);
    assert_eq!(retained.link_count, 0);
    let next = service
        .create_socket_at(request, b"/socket", PathAnchors::default(), root_credentials())
        .unwrap();
    let next = protocol::decode_node_status(&next.payload).unwrap();
    assert_ne!(next.node_id, original.node_id);
    assert_eq!(next.link_count, 1);
    service.provider_close(open_id).unwrap();
    assert!(matches!(
        service.stat_handle(protocol::Header::default(), open_id),
        Err(9)
    ));
    let next_status = service
        .stat_at(
            protocol::Header::default(),
            b"/socket",
            PathAnchors::default(),
            root_credentials(),
        )
        .unwrap();
    assert_eq!(protocol::decode_node_status(&next_status.payload).unwrap(), next);
}

#[test]
fn private_retention_entries_are_inaccessible_but_prefixed_user_names_remain_visible() {
    for mounted in [false, true] {
        let fixture = Fixture::new();
        let mut service = FilesystemService::new(fixture.volume("private-entry"));
        let prefix = if mounted {
            service
                .mount_named_volume(b"/", b"system", fixture.volume("private-mounted"), b"/")
                .unwrap();
            "/system"
        } else {
            ""
        };
        let path = format!("{prefix}/socket");
        let response = service
            .create_socket_at_retained(
                protocol::Header {
                    mode: 0o600,
                    ..Default::default()
                },
                path.as_bytes(),
                PathAnchors::default(),
                root_credentials(),
            )
            .unwrap();
        service
            .unlink_at(
                protocol::Header::default(),
                path.as_bytes(),
                PathAnchors::default(),
                root_credentials(),
            )
            .unwrap();
        let private_name = format!(".mochios-orphan-{}", response.header.node_id);
        let private_path = format!("{prefix}/{private_name}");
        assert!(matches!(
            service.stat_at(
                protocol::Header::default(),
                private_path.as_bytes(),
                PathAnchors::default(),
                root_credentials()
            ),
            Err(2)
        ));
        assert!(matches!(
            service.open_at(
                protocol::Header {
                    flags: protocol::OPEN_AT_WRITE | protocol::OPEN_AT_CREATE,
                    mode: 0o600,
                    ..Default::default()
                },
                private_path.as_bytes(),
                PathAnchors::default(),
                root_credentials(),
            ),
            Err(2)
        ));
        assert!(matches!(
            service.unlink_at(
                protocol::Header::default(),
                private_path.as_bytes(),
                PathAnchors::default(),
                root_credentials()
            ),
            Err(2)
        ));
        let link_path = format!("{prefix}/private-link");
        let mut link_payload = private_path.as_bytes().to_vec();
        link_payload.extend_from_slice(link_path.as_bytes());
        service
            .symlink_at(
                protocol::Header {
                    mode: private_path.len() as u32,
                    ..Default::default()
                },
                &link_payload,
                PathAnchors::default(),
                root_credentials(),
            )
            .unwrap();
        assert!(matches!(
            service.stat_at(
                protocol::Header::default(),
                link_path.as_bytes(),
                PathAnchors::default(),
                root_credentials()
            ),
            Err(2)
        ));
        assert_eq!(
            protocol::decode_node_status(
                &service
                    .stat_at(
                        protocol::Header {
                            flags: protocol::STAT_AT_NOFOLLOW,
                            ..Default::default()
                        },
                        link_path.as_bytes(),
                        PathAnchors::default(),
                        root_credentials(),
                    )
                    .unwrap()
                    .payload
            )
            .unwrap()
            .kind,
            protocol::NODE_TYPE_SYMLINK
        );
        let user_path = format!("{prefix}/.mochios-orphan-user");
        let user = open(
            &mut service,
            user_path.as_bytes(),
            protocol::OPEN_AT_WRITE | protocol::OPEN_AT_CREATE,
            PathAnchors::default(),
        );
        let user_dir_path = format!("{prefix}/.mochios-orphan-directory");
        service
            .mkdir_at(
                protocol::Header {
                    mode: 0o755,
                    ..Default::default()
                },
                user_dir_path.as_bytes(),
                PathAnchors::default(),
                root_credentials(),
            )
            .unwrap();
        let user_dir = open(
            &mut service,
            user_dir_path.as_bytes(),
            protocol::OPEN_AT_READ | protocol::OPEN_AT_DIRECTORY,
            PathAnchors::default(),
        );
        let root = open(
            &mut service,
            b"/",
            protocol::OPEN_AT_READ | protocol::OPEN_AT_DIRECTORY,
            PathAnchors::default(),
        );
        assert_eq!(
            service
                .path_handle(protocol::Header::default(), root.open_id, user_dir.open_id)
                .unwrap()
                .payload,
            user_dir_path.as_bytes()
        );
        let directory_path = if prefix.is_empty() { "/" } else { prefix };
        let directory = open(
            &mut service,
            directory_path.as_bytes(),
            protocol::OPEN_AT_READ
                | protocol::OPEN_AT_DIRECTORY
                | protocol::OPEN_AT_CURSOR_RECORDS,
            PathAnchors::default(),
        );
        let payload = service.provider_read(directory.open_id, 4096).unwrap();
        let mut remaining = payload.as_slice();
        let mut names = Vec::new();
        let mut positions = Vec::new();
        while !remaining.is_empty() {
            let (header, name, length) = protocol::decode_dir_entry(remaining).unwrap();
            names.push(name.to_vec());
            positions.push(header.next_position.unwrap());
            remaining = &remaining[length..];
        }
        assert!(positions.windows(2).any(|pair| pair[1] > pair[0] + 1));
        for (index, position) in positions.iter().enumerate() {
            service
                .provider_seek(directory.open_id, *position as i64, mnu_abi::HANDLE_SEEK_START)
                .unwrap();
            let rest = service.provider_read(directory.open_id, 4096).unwrap();
            if let Some(next) = names.get(index + 1) {
                assert_eq!(protocol::decode_dir_entry(&rest).unwrap().1, next);
            } else {
                assert!(rest.is_empty());
            }
        }
        assert!(names.iter().any(|name| name == b".mochios-orphan-user"));
        assert!(names
            .iter()
            .any(|name| name == b".mochios-orphan-directory"));
        assert!(!names.iter().any(|name| name == private_name.as_bytes()));
        assert_eq!(
            protocol::decode_node_status(
                &service
                    .stat_handle(protocol::Header::default(), response.header.open_id)
                    .unwrap()
                    .payload
            )
            .unwrap()
            .link_count,
            0
        );
        service.provider_close(response.header.open_id).unwrap();
        let reused = open(
            &mut service,
            private_path.as_bytes(),
            protocol::OPEN_AT_WRITE | protocol::OPEN_AT_CREATE,
            PathAnchors::default(),
        );
        service.provider_close(reused.open_id).unwrap();
        service.provider_close(user.open_id).unwrap();
        service.provider_close(directory.open_id).unwrap();
        service.provider_close(user_dir.open_id).unwrap();
        service.provider_close(root.open_id).unwrap();
    }
}

#[test]
fn unlinking_multiple_names_retains_an_open_inode_only_until_last_close() {
    for across_directories in [false, true] {
        let fixture = Fixture::new();
        let mut service = FilesystemService::new(fixture.volume("multiple-links"));
        let opened = open(
            &mut service,
            b"/file",
            protocol::OPEN_AT_READ,
            PathAnchors::default(),
        );
        let second = if across_directories {
            b"/nested/second".as_slice()
        } else {
            b"/second".as_slice()
        };
        let third = if across_directories {
            b"/mount/third".as_slice()
        } else {
            b"/third".as_slice()
        };
        for path in [second, third] {
            let mut payload = b"/file".to_vec();
            payload.extend_from_slice(path);
            service
                .link_at(
                    protocol::Header {
                        mode: 5,
                        ..Default::default()
                    },
                    &payload,
                    RenameAnchors::default(),
                    root_credentials(),
                )
                .unwrap();
        }
        for (index, path) in [b"/file".as_slice(), second, third].into_iter().enumerate() {
            service
                .unlink_at(
                    protocol::Header::default(),
                    path,
                    PathAnchors::default(),
                    root_credentials(),
                )
                .unwrap();
            let status = service
                .stat_handle(protocol::Header::default(), opened.open_id)
                .unwrap();
            assert_eq!(
                protocol::decode_node_status(&status.payload)
                    .unwrap()
                    .link_count,
                2 - index as u32
            );
            assert_eq!(
                service.provider_read_at(opened.open_id, 0, 4096).unwrap(),
                b"multiple-links"
            );
        }
        service.provider_close(opened.open_id).unwrap();
        // All retention links must be gone, even when deletions crossed parents.
        let orphan_name = format!(".mochios-orphan-{}", opened.node_id);
        for parent in ["", "/nested", "/mount"] {
            let path = format!("{parent}/{orphan_name}");
            assert!(matches!(
                service.stat_at(
                    protocol::Header::default(),
                    path.as_bytes(),
                    PathAnchors::default(),
                    root_credentials()
                ),
                Err(2)
            ));
        }
    }
}

#[test]
fn unlinked_open_file_does_not_keep_its_parent_directory_nonempty() {
    for mounted in [false, true] {
        let fixture = Fixture::new();
        let mut service = FilesystemService::new(fixture.volume("orphan-parent-data"));
        let prefix = if mounted {
            service
                .mount_named_volume(
                    b"/",
                    b"system",
                    fixture.volume("orphan-parent-system"),
                    b"/",
                )
                .unwrap();
            "/system"
        } else {
            ""
        };
        let directory = format!("{prefix}/temporary-parent");
        let path = format!("{directory}/file");
        service
            .mkdir_at(
                protocol::Header {
                    mode: 0o755,
                    ..Default::default()
                },
                directory.as_bytes(),
                PathAnchors::default(),
                root_credentials(),
            )
            .unwrap();
        let opened = open(
            &mut service,
            path.as_bytes(),
            protocol::OPEN_AT_READ | protocol::OPEN_AT_WRITE | protocol::OPEN_AT_CREATE,
            PathAnchors::default(),
        );
        service
            .provider_write_at(opened.open_id, 0, b"retained")
            .unwrap();
        let alias = open(
            &mut service,
            path.as_bytes(),
            protocol::OPEN_AT_READ,
            PathAnchors::default(),
        );
        // The private retention name must not reserve or overwrite user names.
        let collision = format!("{prefix}/.mochios-orphan-{}", opened.node_id);
        let private_path = format!("{collision}-1");
        let user = open(
            &mut service,
            collision.as_bytes(),
            protocol::OPEN_AT_READ | protocol::OPEN_AT_WRITE | protocol::OPEN_AT_CREATE,
            PathAnchors::default(),
        );
        service.provider_write_at(user.open_id, 0, b"user").unwrap();
        service
            .unlink_at(
                protocol::Header::default(),
                path.as_bytes(),
                PathAnchors::default(),
                root_credentials(),
            )
            .unwrap();
        service
            .unlink_at(
                protocol::Header {
                    flags: protocol::UNLINK_AT_REMOVE_DIRECTORY,
                    ..Default::default()
                },
                directory.as_bytes(),
                PathAnchors::default(),
                root_credentials(),
            )
            .unwrap();
        assert!(matches!(
            service.stat_at(
                protocol::Header::default(),
                directory.as_bytes(),
                PathAnchors::default(),
                root_credentials()
            ),
            Err(2)
        ));
        assert_eq!(
            service.provider_read_at(opened.open_id, 0, 4096).unwrap(),
            b"retained"
        );
        let status = service
            .stat_handle(protocol::Header::default(), alias.open_id)
            .unwrap();
        assert_eq!(
            protocol::decode_node_status(&status.payload)
                .unwrap()
                .link_count,
            0
        );
        assert_eq!(
            service.provider_read_at(user.open_id, 0, 4096).unwrap(),
            b"user"
        );
        // Reuse the removed directory name; the old FD must not alias its child.
        assert!(matches!(
            service.stat_at(
                protocol::Header::default(),
                private_path.as_bytes(),
                PathAnchors::default(),
                root_credentials()
            ),
            Err(2)
        ));
        // Grow the retention directory after its inode was saved. Last close
        // must refresh that inode rather than using an obsolete block map.
        for index in 0..80 {
            let growth = format!("{prefix}/retention-growth-{index:03}-long-directory-entry");
            let file = open(
                &mut service,
                growth.as_bytes(),
                protocol::OPEN_AT_READ | protocol::OPEN_AT_WRITE | protocol::OPEN_AT_CREATE,
                PathAnchors::default(),
            );
            service.provider_close(file.open_id).unwrap();
        }
        service
            .mkdir_at(
                protocol::Header {
                    mode: 0o755,
                    ..Default::default()
                },
                directory.as_bytes(),
                PathAnchors::default(),
                root_credentials(),
            )
            .unwrap();
        let replacement = open(
            &mut service,
            path.as_bytes(),
            protocol::OPEN_AT_READ | protocol::OPEN_AT_WRITE | protocol::OPEN_AT_CREATE,
            PathAnchors::default(),
        );
        assert_ne!(replacement.node_id, opened.node_id);
        service
            .provider_write_at(replacement.open_id, 0, b"new")
            .unwrap();
        service.provider_close(opened.open_id).unwrap();
        assert_eq!(
            service.provider_read_at(alias.open_id, 0, 4096).unwrap(),
            b"retained"
        );
        service.provider_close(alias.open_id).unwrap();
        assert_eq!(
            service
                .provider_read_at(replacement.open_id, 0, 4096)
                .unwrap(),
            b"new"
        );
        assert!(
            service
                .stat_at(
                    protocol::Header::default(),
                    collision.as_bytes(),
                    PathAnchors::default(),
                    root_credentials()
                )
                .is_ok()
        );
        service.provider_close(replacement.open_id).unwrap();
        service.provider_close(user.open_id).unwrap();
        // With the final reference gone, this is an ordinary available name,
        // not a filtered leak or a globally reserved filename prefix.
        let reused = open(
            &mut service,
            private_path.as_bytes(),
            protocol::OPEN_AT_READ
                | protocol::OPEN_AT_WRITE
                | protocol::OPEN_AT_CREATE
                | protocol::OPEN_AT_EXCLUSIVE,
            PathAnchors::default(),
        );
        service.provider_close(reused.open_id).unwrap();
    }
}

#[test]
fn replacing_multiple_links_does_not_overwrite_the_original_retention_record() {
    let fixture = Fixture::new();
    let mut service = FilesystemService::new(fixture.volume("rename-links"));
    let opened = open(
        &mut service,
        b"/file",
        protocol::OPEN_AT_READ,
        PathAnchors::default(),
    );
    for path in [b"/second".as_slice(), b"/third".as_slice()] {
        let mut payload = b"/file".to_vec();
        payload.extend_from_slice(path);
        service
            .link_at(
                protocol::Header {
                    mode: 5,
                    ..Default::default()
                },
                &payload,
                RenameAnchors::default(),
                root_credentials(),
            )
            .unwrap();
    }
    for (index, (source, target)) in [
        (b"/nested/inside".as_slice(), b"/file".as_slice()),
        (b"/mount/hidden".as_slice(), b"/second".as_slice()),
    ]
    .into_iter()
    .enumerate()
    {
        let mut payload = source.to_vec();
        payload.extend_from_slice(target);
        service
            .rename_at(
                protocol::Header {
                    request_id: 101 + index as u64,
                    mode: source.len() as u32,
                    ..Default::default()
                },
                &payload,
                RenameAnchors::default(),
                root_credentials(),
            )
            .unwrap();
        let status = service
            .stat_handle(protocol::Header::default(), opened.open_id)
            .unwrap();
        assert_eq!(
            protocol::decode_node_status(&status.payload)
                .unwrap()
                .link_count,
            2 - index as u32
        );
    }
    service
        .unlink_at(
            protocol::Header::default(),
            b"/third",
            PathAnchors::default(),
            root_credentials(),
        )
        .unwrap();
    assert_eq!(
        protocol::decode_node_status(
            &service
                .stat_handle(protocol::Header::default(), opened.open_id)
                .unwrap()
                .payload
        )
        .unwrap()
        .link_count,
        0
    );
    assert_eq!(
        service.provider_read_at(opened.open_id, 0, 4096).unwrap(),
        b"rename-links"
    );
    service.provider_close(opened.open_id).unwrap();
    let directory = open(
        &mut service,
        b"/",
        protocol::OPEN_AT_READ | protocol::OPEN_AT_DIRECTORY,
        PathAnchors::default(),
    );
    let payload = service.provider_read(directory.open_id, 4096).unwrap();
    let mut remaining = payload.as_slice();
    while !remaining.is_empty() {
        let (_, name, length) = protocol::decode_dir_entry(remaining).unwrap();
        assert!(!name.starts_with(b".mochios-orphan-"));
        remaining = &remaining[length..];
    }
    service.provider_close(directory.open_id).unwrap();
}

#[test]
fn rename_retention_does_not_prevent_removing_or_replacing_the_empty_parent() {
    for (mounted, legacy) in [(false, false), (false, true), (true, false)] {
        for replace_directory in [false, true] {
            let fixture = Fixture::new();
            let mut service = FilesystemService::new(fixture.volume("rename-orphan-data"));
            let prefix = if mounted {
                service
                    .mount_named_volume(
                        b"/",
                        b"system",
                        fixture.volume("rename-orphan-system"),
                        b"/",
                    )
                    .unwrap();
                "/system"
            } else {
                ""
            };
            let directory = format!("{prefix}/replace-parent");
            service
                .mkdir_at(
                    protocol::Header {
                        mode: 0o755,
                        ..Default::default()
                    },
                    directory.as_bytes(),
                    PathAnchors::default(),
                    root_credentials(),
                )
                .unwrap();
            let source_path = format!("{directory}/source");
            let target_path = format!("{directory}/target");
            let source = open(
                &mut service,
                source_path.as_bytes(),
                protocol::OPEN_AT_READ | protocol::OPEN_AT_WRITE | protocol::OPEN_AT_CREATE,
                PathAnchors::default(),
            );
            let target = open(
                &mut service,
                target_path.as_bytes(),
                protocol::OPEN_AT_READ | protocol::OPEN_AT_WRITE | protocol::OPEN_AT_CREATE,
                PathAnchors::default(),
            );
            service
                .provider_write_at(source.open_id, 0, b"new")
                .unwrap();
            service
                .provider_write_at(target.open_id, 0, b"old")
                .unwrap();
            let mut payload = source_path.as_bytes().to_vec();
            payload.extend_from_slice(target_path.as_bytes());
            if legacy {
                assert_eq!(
                    service
                        .handle(
                            protocol::Header {
                                opcode: protocol::OP_RENAME,
                                request_id: 7701,
                                offset: source_path.len() as u64,
                                ..Default::default()
                            },
                            &payload
                        )
                        .header
                        .status,
                    0
                );
            } else {
                service
                    .rename_at(
                        protocol::Header {
                            request_id: 7701,
                            mode: source_path.len() as u32,
                            ..Default::default()
                        },
                        &payload,
                        RenameAnchors::default(),
                        root_credentials(),
                    )
                    .unwrap();
            }
            let replacement = open(
                &mut service,
                target_path.as_bytes(),
                protocol::OPEN_AT_READ,
                PathAnchors::default(),
            );
            assert_eq!(replacement.node_id, source.node_id);
            service
                .unlink_at(
                    protocol::Header::default(),
                    target_path.as_bytes(),
                    PathAnchors::default(),
                    root_credentials(),
                )
                .unwrap();
            let ordinary = format!("{directory}/.mochios-orphan-rename-user");
            let file = open(
                &mut service,
                ordinary.as_bytes(),
                protocol::OPEN_AT_READ | protocol::OPEN_AT_WRITE | protocol::OPEN_AT_CREATE,
                PathAnchors::default(),
            );
            service.provider_close(file.open_id).unwrap();
            assert!(matches!(
                service.unlink_at(
                    protocol::Header {
                        flags: protocol::UNLINK_AT_REMOVE_DIRECTORY,
                        ..Default::default()
                    },
                    directory.as_bytes(),
                    PathAnchors::default(),
                    root_credentials()
                ),
                Err(39)
            ));
            service
                .unlink_at(
                    protocol::Header::default(),
                    ordinary.as_bytes(),
                    PathAnchors::default(),
                    root_credentials(),
                )
                .unwrap();
            if replace_directory {
                let empty = format!("{prefix}/empty-directory");
                service
                    .mkdir_at(
                        protocol::Header {
                            mode: 0o755,
                            ..Default::default()
                        },
                        empty.as_bytes(),
                        PathAnchors::default(),
                        root_credentials(),
                    )
                    .unwrap();
                let mut payload = empty.as_bytes().to_vec();
                payload.extend_from_slice(directory.as_bytes());
                if legacy {
                    assert_eq!(
                        service
                            .handle(
                                protocol::Header {
                                    opcode: protocol::OP_RENAME,
                                    request_id: 7702,
                                    offset: empty.len() as u64,
                                    ..Default::default()
                                },
                                &payload
                            )
                            .header
                            .status,
                        0
                    );
                } else {
                    service
                        .rename_at(
                            protocol::Header {
                                request_id: 7702,
                                mode: empty.len() as u32,
                                ..Default::default()
                            },
                            &payload,
                            RenameAnchors::default(),
                            root_credentials(),
                        )
                        .unwrap();
                }
            }
            service
                .unlink_at(
                    protocol::Header {
                        flags: protocol::UNLINK_AT_REMOVE_DIRECTORY,
                        ..Default::default()
                    },
                    directory.as_bytes(),
                    PathAnchors::default(),
                    root_credentials(),
                )
                .unwrap();
            assert_eq!(
                service.provider_read_at(target.open_id, 0, 4096).unwrap(),
                b"old"
            );
            assert_eq!(
                service
                    .provider_read_at(replacement.open_id, 0, 4096)
                    .unwrap(),
                b"new"
            );
            for open_id in [target.open_id, source.open_id, replacement.open_id] {
                let status = service
                    .stat_handle(protocol::Header::default(), open_id)
                    .unwrap();
                assert_eq!(
                    protocol::decode_node_status(&status.payload)
                        .unwrap()
                        .link_count,
                    0
                );
                service.provider_close(open_id).unwrap();
            }
            let root = open(
                &mut service,
                if mounted { prefix.as_bytes() } else { b"/" },
                protocol::OPEN_AT_READ | protocol::OPEN_AT_DIRECTORY,
                PathAnchors::default(),
            );
            let bytes = service.provider_read(root.open_id, 4096).unwrap();
            let mut remaining = bytes.as_slice();
            while !remaining.is_empty() {
                let (_, name, length) = protocol::decode_dir_entry(remaining).unwrap();
                assert!(!name.starts_with(b".mochios-orphan-"));
                remaining = &remaining[length..];
            }
            service.provider_close(root.open_id).unwrap();
        }
    }
}

#[test]
fn socket_binding_records_keep_real_unlinked_inodes_distinct_from_recreated_names() {
    use posix_service::socket_binding::{Bindings, Filesystem, NODE_RIGHTS};
    struct Backend<'a>(&'a mut FilesystemService);
    impl Filesystem<u64> for Backend<'_> {
        fn create_socket(
            &mut self,
            path: &[u8],
        ) -> Result<(posix_service::OpenedObject<u64>, protocol::NodeStatus), i32> {
            let response = self
                .0
                .create_socket_at_retained(
                    protocol::Header {
                        mode: 0o755,
                        ..Default::default()
                    },
                    path,
                    PathAnchors::default(),
                    root_credentials(),
                )
                .map_err(|error| -error)?;
            Ok((
                posix_service::OpenedObject {
                    handle: response.header.open_id,
                    rights: NODE_RIGHTS,
                },
                protocol::decode_node_status(&response.payload).unwrap(),
            ))
        }
        fn open_socket(
            &mut self,
            path: &[u8],
        ) -> Result<(posix_service::OpenedObject<u64>, protocol::NodeStatus), i32> {
            let response = self
                .0
                .open_socket_at_retained(
                    protocol::Header::default(),
                    path,
                    PathAnchors::default(),
                    root_credentials(),
                )
                .map_err(|error| -error)?;
            Ok((
                posix_service::OpenedObject {
                    handle: response.header.open_id,
                    rights: NODE_RIGHTS,
                },
                protocol::decode_node_status(&response.payload).unwrap(),
            ))
        }
        fn close(&mut self, handle: u64) {
            self.0.provider_close(handle).unwrap();
        }
    }
    for mounted in [false, true] {
        let fixture = Fixture::new();
        let mut filesystem = FilesystemService::new(fixture.volume("binding-data"));
        let path = if mounted {
            filesystem
                .mount_named_volume(b"/", b"system", fixture.volume("binding-system"), b"/")
                .unwrap();
            b"/system/socket".as_slice()
        } else {
            b"/socket".as_slice()
        };
        let mut policy = posix_service::PosixService::<u32>::new();
        policy
            .initialize_bootstrap_process(
                posix_service::AuthenticatedProcess {
                    handle: 1,
                    process_id: 1,
                },
                0,
                0,
                &[],
            )
            .unwrap();
        let peer = posix_service::PeerIdentity {
            process_id: 1,
            effective_uid: 0,
            effective_gid: 0,
        };
        let request = mochios_posix_protocol::socket::Create {
            domain: mochios_posix_protocol::socket::Domain::Unix,
            kind: mochios_posix_protocol::socket::Kind::Stream,
            protocol: 0,
            options: 0,
        };
        let mut streams = posix_service::socket::Streams::new();
        let a = policy.create_socket(peer, request, &mut streams).unwrap();
        let b = policy.create_socket(peer, request, &mut streams).unwrap();
        let client = policy.create_socket(peer, request, &mut streams).unwrap();
        let rejected = policy.create_socket(peer, request, &mut streams).unwrap();
        let waiting = policy.create_socket(peer, request, &mut streams).unwrap();
        let mut bindings = Bindings::new();
        let mut backend = Backend(&mut filesystem);
        bindings.bind_path(&streams, a, path, &mut backend).unwrap();
        assert_eq!(
            bindings.bind_path(&streams, b, path, &mut backend),
            Err(-98)
        );
        let old = bindings.retained_file(a).unwrap();
        streams.listen(a, 1).unwrap();
        let target = bindings
            .prepare_connect(&streams, waiting, path, &mut backend)
            .unwrap();
        backend
            .0
            .unlink_at(
                protocol::Header::default(),
                path,
                PathAnchors::default(),
                root_credentials(),
            )
            .unwrap();
        bindings.bind_path(&streams, b, path, &mut backend).unwrap();
        let new = bindings.retained_file(b).unwrap();
        let old_status = backend
            .0
            .stat_handle(protocol::Header::default(), old)
            .unwrap();
        let old_status = protocol::decode_node_status(&old_status.payload).unwrap();
        let new_status = backend
            .0
            .stat_handle(protocol::Header::default(), new)
            .unwrap();
        let new_status = protocol::decode_node_status(&new_status.payload).unwrap();
        assert_ne!(old_status.node_id, new_status.node_id);
        assert_eq!((old_status.link_count, new_status.link_count), (0, 1));
        assert_eq!(bindings.address(a), Some(path));
        streams.listen(a, 1).unwrap();
        streams.listen(b, 1).unwrap();
        let (listener, accepted) = bindings
            .connect_path(&mut streams, client, path, &mut backend)
            .unwrap();
        assert_eq!(listener, b);
        // An already authorized wait stays on the unlinked original inode;
        // a fresh lookup above connects to the replacement instead.
        let (original, old_accepted) = bindings.try_connect(&mut streams, &target).unwrap();
        assert_eq!(original, a);
        target.release_with(|handle| backend.close(handle));
        let old_ticket = streams.begin_accept(a).unwrap();
        assert_eq!(old_ticket.endpoint(), old_accepted);
        streams.commit_accept(old_ticket, (0, 0), 0).unwrap();
        assert_eq!(streams.write(waiting, b"old"), Ok(3));
        assert_eq!(streams.read(old_accepted, &mut [0; 3]), Ok(3));
        assert_eq!(streams.begin_accept(a), Err(-11));
        let ticket = streams.begin_accept(b).unwrap();
        assert_eq!(ticket.endpoint(), accepted);
        streams.commit_accept(ticket, (0, 0), 0).unwrap();
        assert_eq!(
            streams.peer_address(client),
            Ok(mochios_posix_protocol::socket::Address::UnixPath(path))
        );
        bindings.release(a, &mut backend);
        streams.release(a).unwrap();
        assert!(matches!(
            backend.0.stat_handle(protocol::Header::default(), old),
            Err(9)
        ));
        assert!(
            backend
                .0
                .stat_handle(protocol::Header::default(), new)
                .is_ok()
        );
        bindings.release(b, &mut backend);
        streams.release(b).unwrap();
        assert_eq!(
            streams.address(accepted),
            Ok(mochios_posix_protocol::socket::Address::UnixPath(path))
        );
        assert_eq!(
            bindings.connect_path(&mut streams, rejected, path, &mut backend),
            Err(-111)
        );
        assert_eq!(streams.write(client, b"live"), Ok(4));
        assert_eq!(streams.read(accepted, &mut [0; 4]), Ok(4));
        // Closing a bound socket does not unlink its filesystem name.
        assert!(
            backend
                .0
                .stat_at(
                    protocol::Header::default(),
                    path,
                    PathAnchors::default(),
                    root_credentials()
                )
                .is_ok()
        );
    }
}

#[test]
fn socket_lookup_retains_authorized_mounted_inode_without_path_reopening() {
    let fixture = Fixture::new();
    let mut service = FilesystemService::new(fixture.volume("lookup-data"));
    service
        .mount_named_volume(b"/", b"system", fixture.volume("lookup-system"), b"/")
        .unwrap();
    service
        .create_socket_at(
            protocol::Header {
                mode: 0o620,
                ..Default::default()
            },
            b"/system/socket",
            PathAnchors::default(),
            root_credentials(),
        )
        .unwrap();
    let mut credential_bytes = [0; protocol::CREDENTIALS_MAX_LEN];
    let length =
        protocol::encode_credentials_payload(501, 20, &[0], &[], &mut credential_bytes).unwrap();
    let member = protocol::decode_credentials_payload(&credential_bytes[..length])
        .unwrap()
        .0;
    let opened = service
        .open_socket_at_retained(
            protocol::Header::default(),
            b"/system/socket",
            PathAnchors::default(),
            member,
        )
        .unwrap();
    let original = protocol::decode_node_status(&opened.payload).unwrap();
    assert_ne!(opened.header.open_id, 0);
    assert_eq!(original.node_id, opened.header.node_id);
    let mut link_payload = b"socket".to_vec();
    link_payload.extend_from_slice(b"/system/link");
    service
        .symlink_at(
            protocol::Header {
                mode: 6,
                ..Default::default()
            },
            &link_payload,
            PathAnchors::default(),
            root_credentials(),
        )
        .unwrap();
    let linked = service
        .open_socket_at_retained(
            protocol::Header::default(),
            b"/system/link",
            PathAnchors::default(),
            member,
        )
        .unwrap();
    assert_eq!(linked.header.node_id, original.node_id);
    service.provider_close(linked.header.open_id).unwrap();
    let directory = open(
        &mut service,
        b"/system",
        protocol::OPEN_AT_READ | protocol::OPEN_AT_DIRECTORY,
        PathAnchors::default(),
    );
    let confined = service
        .open_socket_at_retained(
            protocol::Header {
                flags: protocol::SOCKET_AT_ROOT_ATTACHED,
                ..Default::default()
            },
            b"/../socket",
            PathAnchors {
                root_open_id: Some(directory.open_id),
                base_open_id: None,
            },
            member,
        )
        .unwrap();
    assert_eq!(confined.header.node_id, original.node_id);
    service.provider_close(confined.header.open_id).unwrap();
    service.provider_close(directory.open_id).unwrap();
    let length =
        protocol::encode_credentials_payload(501, 20, &[], &[], &mut credential_bytes).unwrap();
    let denied = protocol::decode_credentials_payload(&credential_bytes[..length])
        .unwrap()
        .0;
    assert!(matches!(
        service.open_socket_at_retained(
            protocol::Header::default(),
            b"/system/socket",
            PathAnchors::default(),
            denied
        ),
        Err(13)
    ));
    for (path, error) in [
        (b"/system/file".as_slice(), 88),
        (b"/system".as_slice(), 88),
        (b"/system/missing".as_slice(), 2),
        (b"/system/blocked/private".as_slice(), 13),
    ] {
        assert!(
            matches!(service.open_socket_at_retained(protocol::Header::default(), path, PathAnchors::default(), member), Err(actual) if actual == error)
        );
    }
    service
        .unlink_at(
            protocol::Header::default(),
            b"/system/socket",
            PathAnchors::default(),
            root_credentials(),
        )
        .unwrap();
    service
        .create_socket_at(
            protocol::Header {
                mode: 0o600,
                ..Default::default()
            },
            b"/system/socket",
            PathAnchors::default(),
            root_credentials(),
        )
        .unwrap();
    let retained = service
        .stat_handle(protocol::Header::default(), opened.header.open_id)
        .unwrap();
    let retained = protocol::decode_node_status(&retained.payload).unwrap();
    assert_eq!(
        (retained.node_id, retained.link_count),
        (original.node_id, 0)
    );
    let replacement = service
        .open_socket_at_retained(
            protocol::Header::default(),
            b"/system/socket",
            PathAnchors::default(),
            root_credentials(),
        )
        .unwrap();
    assert_ne!(replacement.header.node_id, original.node_id);
    service.provider_close(opened.header.open_id).unwrap();
    assert!(matches!(
        service.stat_handle(protocol::Header::default(), opened.header.open_id),
        Err(9)
    ));
    service.provider_close(replacement.header.open_id).unwrap();
}

fn open(
    service: &mut FilesystemService,
    path: &[u8],
    flags: u32,
    anchors: PathAnchors,
) -> protocol::Header {
    service
        .open_at(
            protocol::Header {
                opcode: protocol::OP_OPEN_AT,
                flags,
                mode: 0o600,
                ..Default::default()
            },
            path,
            anchors,
            root_credentials(),
        )
        .unwrap()
        .header
}

#[test]
fn service_open_descriptions_keep_volume_identity_for_io_metadata_and_pager() {
    let fixture = Fixture::new();
    let mut service = FilesystemService::new(fixture.volume("data"));
    service
        .configure_memory_updates(Box::new(unmapped_updates::UnmappedUpdates))
        .unwrap();
    service
        .mount_volume(b"/mount", fixture.volume("system"))
        .unwrap();
    let flags = protocol::OPEN_AT_READ | protocol::OPEN_AT_WRITE;
    let data = open(&mut service, b"/file", flags, PathAnchors::default());
    let system = open(&mut service, b"/mount/file", flags, PathAnchors::default());
    let alias = open(&mut service, b"/mount/file", flags, PathAnchors::default());
    assert_eq!(data.node_id as u32, system.node_id as u32);
    assert_ne!(data.node_id, system.node_id);
    assert_ne!(
        service.provider_memory_object(data.open_id).unwrap(),
        service.provider_memory_object(system.open_id).unwrap()
    );
    assert_eq!(
        service.provider_memory_object(system.open_id).unwrap(),
        service.provider_memory_object(alias.open_id).unwrap()
    );
    assert_eq!(service.provider_read(data.open_id, 4096).unwrap(), b"data");
    assert_eq!(
        service.provider_read(system.open_id, 4096).unwrap(),
        b"system"
    );
    service
        .provider_write_at(system.open_id, 0, b"SYSTEM")
        .unwrap();
    assert_eq!(
        service.provider_read_at(alias.open_id, 0, 4096).unwrap(),
        b"SYSTEM"
    );
    assert_eq!(
        service.provider_read_at(data.open_id, 0, 4096).unwrap(),
        b"data"
    );
    service
        .truncate_handle(
            protocol::Header {
                offset: 2,
                ..Default::default()
            },
            system.open_id,
        )
        .unwrap();
    assert_eq!(
        service.provider_read_at(alias.open_id, 0, 4096).unwrap(),
        b"SY"
    );
    assert_eq!(
        service.provider_read_at(data.open_id, 0, 4096).unwrap(),
        b"data"
    );
    service
        .chmod_handle(
            protocol::Header {
                mode: 0o640,
                ..Default::default()
            },
            system.open_id,
            root_credentials(),
        )
        .unwrap();
    service
        .chown_handle(
            protocol::Header {
                node_id: 501 | (20u64 << 32),
                ..Default::default()
            },
            system.open_id,
            root_credentials(),
        )
        .unwrap();
    let status = service
        .stat_handle(protocol::Header::default(), system.open_id)
        .unwrap();
    let status = protocol::decode_node_status(&status.payload).unwrap();
    assert_eq!(status.device, system.node_id >> 32);
    assert_eq!(
        (
            status.node_id,
            status.size,
            status.mode & 0o7777,
            status.uid,
            status.gid
        ),
        (system.node_id, 2, 0o640, 501, 20)
    );
    let reopened = open(&mut service, b"/mount/file", flags, PathAnchors::default());
    assert_eq!(
        service.provider_read(reopened.open_id, 4096).unwrap(),
        b"SY"
    );
    service.provider_close(reopened.open_id).unwrap();
    let root_status = service
        .stat_handle(protocol::Header::default(), data.open_id)
        .unwrap();
    assert_eq!(
        protocol::decode_node_status(&root_status.payload)
            .unwrap()
            .size,
        4
    );
    let created = open(
        &mut service,
        b"/mount/new",
        flags | protocol::OPEN_AT_CREATE | protocol::OPEN_AT_EXCLUSIVE,
        PathAnchors::default(),
    );
    assert_eq!(created.node_id >> 32, system.node_id >> 32);
    service
        .provider_write(created.open_id, b"new on system")
        .unwrap();
    assert!(matches!(
        service.open_at(
            protocol::Header {
                flags: protocol::OPEN_AT_READ,
                ..Default::default()
            },
            b"/new",
            PathAnchors::default(),
            root_credentials()
        ),
        Err(2)
    ));
    for opened in [created, alias, system, data] {
        service.provider_close(opened.open_id).unwrap();
    }
}

#[test]
fn service_retained_mount_directories_resolve_relative_paths_and_report_namespace_cwd() {
    let fixture = Fixture::new();
    let mut service = FilesystemService::new(fixture.volume("data"));
    service
        .mount_volume(b"/mount", fixture.volume("system"))
        .unwrap();
    let directory_flags = protocol::OPEN_AT_READ | protocol::OPEN_AT_DIRECTORY;
    let root = open(&mut service, b"/", directory_flags, PathAnchors::default());
    let mounted = open(
        &mut service,
        b"/mount",
        directory_flags,
        PathAnchors::default(),
    );
    let base = PathAnchors {
        root_open_id: None,
        base_open_id: Some(mounted.open_id),
    };
    let inside = open(
        &mut service,
        b"file",
        protocol::OPEN_AT_READ | protocol::OPEN_AT_BASE_ATTACHED,
        base,
    );
    assert_eq!(
        service.provider_read(inside.open_id, 4096).unwrap(),
        b"system"
    );
    let outside = open(
        &mut service,
        b"../file",
        protocol::OPEN_AT_READ | protocol::OPEN_AT_BASE_ATTACHED,
        base,
    );
    assert_eq!(
        service.provider_read(outside.open_id, 4096).unwrap(),
        b"data"
    );
    let jail = PathAnchors {
        root_open_id: Some(mounted.open_id),
        base_open_id: Some(mounted.open_id),
    };
    let jailed = open(
        &mut service,
        b"/absolute",
        protocol::OPEN_AT_READ | protocol::OPEN_AT_ROOT_ATTACHED | protocol::OPEN_AT_BASE_ATTACHED,
        jail,
    );
    assert_eq!(
        service.provider_read(jailed.open_id, 4096).unwrap(),
        b"system"
    );
    assert_eq!(
        service
            .path_handle(protocol::Header::default(), root.open_id, mounted.open_id)
            .unwrap()
            .payload,
        b"/mount"
    );
    assert_eq!(
        service
            .path_handle(
                protocol::Header::default(),
                mounted.open_id,
                mounted.open_id
            )
            .unwrap()
            .payload,
        b"/"
    );
    assert!(matches!(
        service.path_handle(protocol::Header::default(), mounted.open_id, root.open_id),
        Err(13)
    ));
    let entries = service.provider_read(mounted.open_id, 4096).unwrap();
    assert!(!entries.is_empty());
    let mut remaining = entries.as_slice();
    let mut ids = std::collections::HashMap::new();
    while !remaining.is_empty() {
        let (entry, name, length) = protocol::decode_dir_entry(remaining).unwrap();
        ids.insert(name.to_vec(), entry.node_id);
        remaining = &remaining[length..];
    }
    assert_eq!(ids[b".".as_slice()], mounted.node_id);
    assert_eq!(ids[b"..".as_slice()], root.node_id);
    assert_eq!(ids[b"file".as_slice()], inside.node_id);
    service
        .chmod_handle(
            protocol::Header {
                mode: 0,
                ..Default::default()
            },
            mounted.open_id,
            root_credentials(),
        )
        .unwrap();
    let mut bytes = [0u8; protocol::CREDENTIALS_MAX_LEN];
    let size = protocol::encode_credentials_payload(501, 20, &[], &[], &mut bytes).unwrap();
    let unprivileged = protocol::decode_credentials_payload(&bytes[..size])
        .unwrap()
        .0;
    assert!(matches!(
        service.open_at(
            protocol::Header {
                flags: protocol::OPEN_AT_READ | protocol::OPEN_AT_BASE_ATTACHED,
                ..Default::default()
            },
            b"file",
            base,
            unprivileged
        ),
        Err(13)
    ));
    for opened in [jailed, outside, inside, mounted, root] {
        service.provider_close(opened.open_id).unwrap();
    }
}

#[test]
fn service_path_metadata_mutations_and_readlink_use_the_resolved_volume() {
    let fixture = Fixture::new();
    let mut service = FilesystemService::new(fixture.volume("data"));
    service
        .mount_volume(b"/mount", fixture.volume("system"))
        .unwrap();
    service
        .truncate_at(
            protocol::Header {
                open_id: 2,
                ..Default::default()
            },
            b"/mount/file",
            PathAnchors::default(),
            root_credentials(),
        )
        .unwrap();
    service
        .chmod_at(
            protocol::Header {
                mode: 0o600,
                ..Default::default()
            },
            b"/mount/file",
            PathAnchors::default(),
            root_credentials(),
        )
        .unwrap();
    service
        .chown_at(
            protocol::Header {
                node_id: 600 | (30u64 << 32),
                ..Default::default()
            },
            b"/mount/file",
            PathAnchors::default(),
            root_credentials(),
        )
        .unwrap();
    let mounted = service
        .stat_at(
            protocol::Header::default(),
            b"/mount/file",
            PathAnchors::default(),
            root_credentials(),
        )
        .unwrap();
    let mounted = protocol::decode_node_status(&mounted.payload).unwrap();
    assert_eq!(
        (
            mounted.size,
            mounted.mode & 0o7777,
            mounted.uid,
            mounted.gid
        ),
        (2, 0o600, 600, 30)
    );
    let root = service
        .stat_at(
            protocol::Header::default(),
            b"/file",
            PathAnchors::default(),
            root_credentials(),
        )
        .unwrap();
    let root = protocol::decode_node_status(&root.payload).unwrap();
    assert_eq!(root.size, 4);
    assert_ne!(root.uid, mounted.uid);
    assert_ne!(root.node_id, mounted.node_id);
    let target = service
        .readlink_at(
            protocol::Header::default(),
            b"/mount/absolute",
            PathAnchors::default(),
            root_credentials(),
        )
        .unwrap();
    assert_eq!(target.payload, b"/file");
}

#[test]
fn directory_and_symlink_creation_use_the_mounted_parent_and_preserve_literal_targets() {
    let fixture = Fixture::new();
    let mut service = FilesystemService::new(fixture.volume("data"));
    service
        .mount_volume(b"/mount", fixture.volume("system"))
        .unwrap();
    let mounted = open(
        &mut service,
        b"/mount",
        protocol::OPEN_AT_READ | protocol::OPEN_AT_DIRECTORY,
        PathAnchors::default(),
    );
    let anchors = PathAnchors {
        root_open_id: None,
        base_open_id: Some(mounted.open_id),
    };
    let mkdir = protocol::Header {
        flags: protocol::MKDIR_AT_BASE_ATTACHED,
        mode: 0o755,
        ..Default::default()
    };
    service
        .mkdir_at(mkdir, b"created", anchors, root_credentials())
        .unwrap();
    assert!(matches!(
        service.mkdir_at(mkdir, b"created", anchors, root_credentials()),
        Err(17)
    ));
    let directory = service
        .stat_at(
            protocol::Header::default(),
            b"/mount/created",
            PathAnchors::default(),
            root_credentials(),
        )
        .unwrap();
    let directory = protocol::decode_node_status(&directory.payload).unwrap();
    assert_eq!(directory.kind, protocol::NODE_TYPE_DIRECTORY);
    assert_eq!(directory.node_id >> 32, mounted.node_id >> 32);
    assert!(matches!(
        service.stat_at(
            protocol::Header::default(),
            b"/created",
            PathAnchors::default(),
            root_credentials()
        ),
        Err(2)
    ));

    let mut payload = b"/file".to_vec();
    payload.extend_from_slice(b"created/link");
    let symlink = protocol::Header {
        flags: protocol::SYMLINK_AT_BASE_ATTACHED,
        mode: 5,
        ..Default::default()
    };
    service
        .symlink_at(symlink, &payload, anchors, root_credentials())
        .unwrap();
    assert!(matches!(
        service.symlink_at(symlink, &payload, anchors, root_credentials()),
        Err(17)
    ));
    let target = service
        .readlink_at(
            protocol::Header::default(),
            b"/mount/created/link",
            PathAnchors::default(),
            root_credentials(),
        )
        .unwrap();
    assert_eq!(target.payload, b"/file");
    let global = open(
        &mut service,
        b"/mount/created/link",
        protocol::OPEN_AT_READ,
        PathAnchors::default(),
    );
    assert_eq!(
        service.provider_read(global.open_id, 4096).unwrap(),
        b"data"
    );
    let confined = open(
        &mut service,
        b"created/link",
        protocol::OPEN_AT_READ | protocol::OPEN_AT_ROOT_ATTACHED | protocol::OPEN_AT_BASE_ATTACHED,
        PathAnchors {
            root_open_id: Some(mounted.open_id),
            base_open_id: Some(mounted.open_id),
        },
    );
    assert_eq!(
        service.provider_read(confined.open_id, 4096).unwrap(),
        b"system"
    );

    let mut bytes = [0u8; protocol::CREDENTIALS_MAX_LEN];
    let size = protocol::encode_credentials_payload(501, 20, &[], &[], &mut bytes).unwrap();
    let unprivileged = protocol::decode_credentials_payload(&bytes[..size])
        .unwrap()
        .0;
    assert!(matches!(
        service.mkdir_at(mkdir, b"denied", anchors, unprivileged),
        Err(13)
    ));
    let mut denied_link = b"/file".to_vec();
    denied_link.extend_from_slice(b"denied-link");
    assert!(matches!(
        service.symlink_at(symlink, &denied_link, anchors, unprivileged),
        Err(13)
    ));
    for opened in [confined, global, mounted] {
        service.provider_close(opened.open_id).unwrap();
    }
}

#[test]
fn unlink_in_a_mounted_volume_retains_its_open_files_and_never_aliases_root_inodes() {
    let fixture = Fixture::new();
    let mut service = FilesystemService::new(fixture.volume("data"));
    service
        .mount_volume(b"/mount", fixture.volume("system"))
        .unwrap();
    let data = open(
        &mut service,
        b"/file",
        protocol::OPEN_AT_READ,
        PathAnchors::default(),
    );
    let system = open(
        &mut service,
        b"/mount/file",
        protocol::OPEN_AT_READ | protocol::OPEN_AT_WRITE,
        PathAnchors::default(),
    );
    let alias = open(
        &mut service,
        b"/mount/file",
        protocol::OPEN_AT_READ,
        PathAnchors::default(),
    );
    let memory_id = service.provider_memory_object(system.open_id).unwrap();
    service
        .unlink_at(
            protocol::Header::default(),
            b"/mount/file",
            PathAnchors::default(),
            root_credentials(),
        )
        .unwrap();
    assert!(matches!(
        service.stat_at(
            protocol::Header::default(),
            b"/mount/file",
            PathAnchors::default(),
            root_credentials()
        ),
        Err(2)
    ));
    assert_eq!(
        service.provider_read_at(system.open_id, 0, 4096).unwrap(),
        b"system"
    );
    assert_eq!(
        service.provider_read_at(data.open_id, 0, 4096).unwrap(),
        b"data"
    );
    service
        .provider_write_at(system.open_id, 0, b"SYSTEM")
        .unwrap();
    assert_eq!(
        service.provider_read_at(alias.open_id, 0, 4096).unwrap(),
        b"SYSTEM"
    );
    service.provider_close(system.open_id).unwrap();
    assert_eq!(
        service.provider_read_at(alias.open_id, 0, 4096).unwrap(),
        b"SYSTEM"
    );
    let status = service
        .stat_handle(protocol::Header::default(), alias.open_id)
        .unwrap();
    assert_eq!(
        protocol::decode_node_status(&status.payload)
            .unwrap()
            .node_id,
        alias.node_id
    );
    service.provider_close(alias.open_id).unwrap();
    let replacement = open(
        &mut service,
        b"/mount/file",
        protocol::OPEN_AT_READ | protocol::OPEN_AT_WRITE | protocol::OPEN_AT_CREATE,
        PathAnchors::default(),
    );
    assert_ne!(
        service.provider_memory_object(replacement.open_id).unwrap(),
        memory_id
    );
    service
        .provider_write(replacement.open_id, b"replacement")
        .unwrap();
    assert_eq!(
        service.provider_read_at(data.open_id, 0, 4096).unwrap(),
        b"data"
    );

    assert!(matches!(
        service.unlink_at(
            protocol::Header {
                flags: protocol::UNLINK_AT_REMOVE_DIRECTORY,
                ..Default::default()
            },
            b"/mount",
            PathAnchors::default(),
            root_credentials()
        ),
        Err(16)
    ));
    service
        .mkdir_at(
            protocol::Header {
                mode: 0o755,
                ..Default::default()
            },
            b"/mount/empty",
            PathAnchors::default(),
            root_credentials(),
        )
        .unwrap();
    service
        .unlink_at(
            protocol::Header {
                flags: protocol::UNLINK_AT_REMOVE_DIRECTORY,
                ..Default::default()
            },
            b"/mount/empty",
            PathAnchors::default(),
            root_credentials(),
        )
        .unwrap();
    assert!(matches!(
        service.stat_at(
            protocol::Header::default(),
            b"/mount/empty",
            PathAnchors::default(),
            root_credentials()
        ),
        Err(2)
    ));
    for opened in [replacement, data] {
        service.provider_close(opened.open_id).unwrap();
    }
}

#[test]
fn hard_links_share_mounted_inode_identity_and_reject_actual_cross_volume_operations() {
    let fixture = Fixture::new();
    let mut service = FilesystemService::new(fixture.volume("data"));
    service
        .mount_volume(b"/mount", fixture.volume("system"))
        .unwrap();
    let link = |service: &mut FilesystemService, old: &[u8], new: &[u8], flags, anchors| {
        let mut payload = old.to_vec();
        payload.extend_from_slice(new);
        service.link_at(
            protocol::Header {
                flags,
                mode: old.len() as u32,
                ..Default::default()
            },
            &payload,
            anchors,
            root_credentials(),
        )
    };
    let mounted = open(
        &mut service,
        b"/mount",
        protocol::OPEN_AT_READ | protocol::OPEN_AT_DIRECTORY,
        PathAnchors::default(),
    );
    let nested = open(
        &mut service,
        b"/mount/nested",
        protocol::OPEN_AT_READ | protocol::OPEN_AT_DIRECTORY,
        PathAnchors::default(),
    );
    let anchors = RenameAnchors {
        root_open_id: None,
        old_base_open_id: Some(mounted.open_id),
        new_base_open_id: Some(nested.open_id),
    };
    let flags = protocol::LINK_AT_OLD_BASE_ATTACHED | protocol::LINK_AT_NEW_BASE_ATTACHED;
    link(&mut service, b"file", b"alias", flags, anchors).unwrap();
    assert!(matches!(
        link(&mut service, b"file", b"alias", flags, anchors),
        Err(17)
    ));
    let source = service
        .stat_at(
            protocol::Header::default(),
            b"/mount/file",
            PathAnchors::default(),
            root_credentials(),
        )
        .unwrap();
    let alias = service
        .stat_at(
            protocol::Header::default(),
            b"/mount/nested/alias",
            PathAnchors::default(),
            root_credentials(),
        )
        .unwrap();
    let source = protocol::decode_node_status(&source.payload).unwrap();
    let alias = protocol::decode_node_status(&alias.payload).unwrap();
    assert_eq!(source.node_id, alias.node_id);
    assert_eq!(source.link_count, 2);
    assert!(matches!(
        link(
            &mut service,
            b"/file",
            b"/mount/cross",
            0,
            RenameAnchors::default()
        ),
        Err(18)
    ));
    assert!(matches!(
        link(
            &mut service,
            b"/mount/file",
            b"/cross",
            0,
            RenameAnchors::default()
        ),
        Err(18)
    ));
    assert!(matches!(
        service.stat_at(
            protocol::Header::default(),
            b"/mount/cross",
            PathAnchors::default(),
            root_credentials()
        ),
        Err(2)
    ));
    link(
        &mut service,
        b"/mount/absolute",
        b"/mount/link-copy",
        0,
        RenameAnchors::default(),
    )
    .unwrap();
    assert_eq!(
        service
            .readlink_at(
                protocol::Header::default(),
                b"/mount/link-copy",
                PathAnchors::default(),
                root_credentials()
            )
            .unwrap()
            .payload,
        b"/file"
    );
    assert!(matches!(
        link(
            &mut service,
            b"/mount/absolute",
            b"/mount/followed",
            protocol::LINK_AT_FOLLOW_SOURCE,
            RenameAnchors::default()
        ),
        Err(18)
    ));
    service
        .unlink_at(
            protocol::Header::default(),
            b"/mount/file",
            PathAnchors::default(),
            root_credentials(),
        )
        .unwrap();
    let retained = open(
        &mut service,
        b"/mount/nested/alias",
        protocol::OPEN_AT_READ,
        PathAnchors::default(),
    );
    assert_eq!(
        service.provider_read(retained.open_id, 4096).unwrap(),
        b"system"
    );
    for opened in [retained, nested, mounted] {
        service.provider_close(opened.open_id).unwrap();
    }
}

#[test]
fn mounted_rename_replaces_a_file_without_invalidating_its_retained_description() {
    let fixture = Fixture::new();
    let mut service = FilesystemService::new(fixture.volume("data"));
    service
        .mount_volume(b"/mount", fixture.volume("system"))
        .unwrap();
    let directory_flags = protocol::OPEN_AT_READ | protocol::OPEN_AT_DIRECTORY;
    let mounted = open(
        &mut service,
        b"/mount",
        directory_flags,
        PathAnchors::default(),
    );
    let nested = open(
        &mut service,
        b"/mount/nested",
        directory_flags,
        PathAnchors::default(),
    );
    let old_target = open(
        &mut service,
        b"/mount/nested/target",
        protocol::OPEN_AT_READ | protocol::OPEN_AT_WRITE | protocol::OPEN_AT_CREATE,
        PathAnchors::default(),
    );
    service
        .provider_write(old_target.open_id, b"original target")
        .unwrap();
    let root_file = open(
        &mut service,
        b"/file",
        protocol::OPEN_AT_READ,
        PathAnchors::default(),
    );
    let mut payload = b"file".to_vec();
    payload.extend_from_slice(b"target");
    service
        .rename_at(
            protocol::Header {
                flags: protocol::RENAME_AT_OLD_BASE_ATTACHED
                    | protocol::RENAME_AT_NEW_BASE_ATTACHED,
                mode: 4,
                ..Default::default()
            },
            &payload,
            RenameAnchors {
                root_open_id: None,
                old_base_open_id: Some(mounted.open_id),
                new_base_open_id: Some(nested.open_id),
            },
            root_credentials(),
        )
        .unwrap();
    assert!(matches!(
        service.stat_at(
            protocol::Header::default(),
            b"/mount/file",
            PathAnchors::default(),
            root_credentials()
        ),
        Err(2)
    ));
    let target = open(
        &mut service,
        b"/mount/nested/target",
        protocol::OPEN_AT_READ,
        PathAnchors::default(),
    );
    assert_eq!(
        service.provider_read(target.open_id, 4096).unwrap(),
        b"system"
    );
    assert_eq!(
        service
            .provider_read_at(old_target.open_id, 0, 4096)
            .unwrap(),
        b"original target"
    );
    assert_eq!(
        service.provider_read(root_file.open_id, 4096).unwrap(),
        b"data"
    );
    service
        .provider_write_at(old_target.open_id, 0, &[b'x'; 8192])
        .unwrap_err(); // Provider packets remain bounded.
    service
        .provider_write_at(old_target.open_id, 4096, &[b'x'; 4096])
        .unwrap();
    let old = service
        .stat_handle(protocol::Header::default(), old_target.open_id)
        .unwrap();
    assert_eq!(
        protocol::decode_node_status(&old.payload).unwrap().size,
        8192
    );
    service.provider_close(old_target.open_id).unwrap();
    assert_eq!(
        service.provider_read_at(target.open_id, 0, 4096).unwrap(),
        b"system"
    );
    for opened in [target, root_file, nested, mounted] {
        service.provider_close(opened.open_id).unwrap();
    }
}

#[test]
fn mounted_directory_rename_updates_virtual_parents_and_rejects_cross_volume_and_mount_roots() {
    let fixture = Fixture::new();
    let mut service = FilesystemService::new(fixture.volume("data"));
    service
        .mount_volume(b"/mount", fixture.volume("system"))
        .unwrap();
    let rename = |service: &mut FilesystemService, old: &[u8], new: &[u8]| {
        let mut payload = old.to_vec();
        payload.extend_from_slice(new);
        service.rename_at(
            protocol::Header {
                mode: old.len() as u32,
                ..Default::default()
            },
            &payload,
            RenameAnchors::default(),
            root_credentials(),
        )
    };
    let directory_flags = protocol::OPEN_AT_READ | protocol::OPEN_AT_DIRECTORY;
    let root = open(&mut service, b"/", directory_flags, PathAnchors::default());
    let retained = open(
        &mut service,
        b"/mount/nested",
        directory_flags,
        PathAnchors::default(),
    );
    service
        .mkdir_at(
            protocol::Header {
                mode: 0o755,
                ..Default::default()
            },
            b"/mount/parent",
            PathAnchors::default(),
            root_credentials(),
        )
        .unwrap();
    rename(&mut service, b"/mount/nested", b"/mount/parent/moved").unwrap();
    assert_eq!(
        service
            .path_handle(protocol::Header::default(), root.open_id, retained.open_id)
            .unwrap()
            .payload,
        b"/mount/parent/moved"
    );
    assert!(matches!(
        rename(&mut service, b"/mount/parent", b"/mount/parent/moved/cycle"),
        Err(22)
    ));
    assert!(matches!(
        rename(&mut service, b"/file", b"/mount/file"),
        Err(18)
    ));
    assert!(matches!(
        rename(&mut service, b"/mount/file", b"/file"),
        Err(18)
    ));
    assert!(matches!(
        rename(&mut service, b"/mount", b"/moved-mount"),
        Err(16)
    ));
    assert!(matches!(
        rename(&mut service, b"/nested", b"/mount"),
        Err(16)
    ));
    for path in [b"/file".as_slice(), b"/mount/file"] {
        let file = open(
            &mut service,
            path,
            protocol::OPEN_AT_READ,
            PathAnchors::default(),
        );
        assert_eq!(
            service.provider_read(file.open_id, 4096).unwrap(),
            if path == b"/file" {
                b"data".as_slice()
            } else {
                b"system".as_slice()
            }
        );
        service.provider_close(file.open_id).unwrap();
    }
    for opened in [retained, root] {
        service.provider_close(opened.open_id).unwrap();
    }
}
