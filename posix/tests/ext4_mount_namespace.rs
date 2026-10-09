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
use filesystem_service::service::{FilesystemService, PathAnchors};
use mochios_filesystem_protocol as protocol;

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
