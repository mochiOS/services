use std::error::Error;
use std::fs;
use std::io;
use std::os::unix::fs::symlink;
use std::path::PathBuf;
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use ext4plus::{Ext4, Ext4Read, Ext4Write};
use filesystem_service::service::{FilesystemService, PathAnchors, RenameAnchors};
use mochi_user_platform::handle::HANDLE_SEEK_START;
use mochios_filesystem_protocol as protocol;

#[derive(Clone)]
struct SharedImage(Arc<Mutex<Vec<u8>>>);

impl Ext4Read for SharedImage {
    fn read(
        &self,
        start_byte: u64,
        destination: &mut [u8],
    ) -> Result<(), Box<dyn Error + Send + Sync + 'static>> {
        let start = usize::try_from(start_byte)?;
        let end = start
            .checked_add(destination.len())
            .ok_or_else(|| io::Error::other("image offset overflow"))?;
        let image = self
            .0
            .lock()
            .map_err(|_| io::Error::other("poisoned image"))?;
        destination.copy_from_slice(
            image
                .get(start..end)
                .ok_or_else(|| io::Error::other("read outside image"))?,
        );
        Ok(())
    }
}

impl Ext4Write for SharedImage {
    fn write(
        &self,
        start_byte: u64,
        source: &[u8],
    ) -> Result<(), Box<dyn Error + Send + Sync + 'static>> {
        let start = usize::try_from(start_byte)?;
        let end = start
            .checked_add(source.len())
            .ok_or_else(|| io::Error::other("image offset overflow"))?;
        let mut image = self
            .0
            .lock()
            .map_err(|_| io::Error::other("poisoned image"))?;
        image
            .get_mut(start..end)
            .ok_or_else(|| io::Error::other("write outside image"))?
            .copy_from_slice(source);
        Ok(())
    }
}

struct TempTree(PathBuf);

impl TempTree {
    fn create() -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path =
            std::env::temp_dir().join(format!("mochios-posix-fs-{}-{nonce}", std::process::id()));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}

impl Drop for TempTree {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn test_filesystem() -> FilesystemService {
    let temporary = TempTree::create();
    let source = temporary.0.join("source");
    let directory = source.join("removed");
    let blocked = source.join("blocked");
    let create_base = source.join("create-base");
    let jail = source.join("jail");
    let image_path = temporary.0.join("filesystem.ext4");
    fs::create_dir_all(&directory).unwrap();
    fs::create_dir_all(&blocked).unwrap();
    fs::create_dir_all(&create_base).unwrap();
    fs::create_dir_all(jail.join("inside")).unwrap();
    fs::create_dir_all(source.join("outside")).unwrap();
    fs::write(blocked.join("child"), b"private").unwrap();
    symlink("/blocked/child", source.join("redirect")).unwrap();
    symlink("target", create_base.join("dangling")).unwrap();
    symlink("/outside", jail.join("escape")).unwrap();
    let output = Command::new("mke2fs")
        .args(["-q", "-t", "ext4", "-F", "-d"])
        .arg(&source)
        .arg(&image_path)
        .arg("8192")
        .output()
        .expect("mke2fs is required for filesystem integration tests");
    assert!(
        output.status.success(),
        "mke2fs failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let image = SharedImage(Arc::new(Mutex::new(fs::read(image_path).unwrap())));
    let filesystem =
        Ext4::load_with_writer(Box::new(image.clone()), Some(Box::new(image))).unwrap();
    let mut service = FilesystemService::new(filesystem);
    let restricted = service.handle(
        protocol::Header {
            opcode: protocol::OP_SETATTR,
            flags: protocol::SETATTR_MODE,
            mode: 0,
            ..protocol::Header::default()
        },
        b"/blocked",
    );
    assert_eq!(restricted.header.status, 0);
    service
}

#[test]
fn an_open_directory_remains_a_valid_object_after_unlink() {
    let mut filesystem = test_filesystem();
    let opened = filesystem
        .open_at(
            protocol::Header {
                opcode: protocol::OP_OPEN_AT,
                flags: protocol::OPEN_AT_READ | protocol::OPEN_AT_DIRECTORY,
                ..protocol::Header::default()
            },
            b"/removed",
            PathAnchors::default(),
        )
        .unwrap();
    let open_id = opened.header.open_id;

    let removed = filesystem.handle(
        protocol::Header {
            opcode: protocol::OP_UNLINK,
            flags: protocol::NODE_TYPE_DIRECTORY,
            ..protocol::Header::default()
        },
        b"/removed",
    );
    assert_eq!(removed.header.status, 0);

    let status = filesystem
        .stat_handle(
            protocol::Header {
                opcode: protocol::OP_STAT_HANDLE,
                ..protocol::Header::default()
            },
            open_id,
        )
        .unwrap();
    let status = protocol::decode_node_status(&status.payload).unwrap();
    assert_eq!(status.kind, protocol::NODE_TYPE_DIRECTORY);

    let entries = filesystem
        .provider_read(open_id, protocol::MAX_IO_LEN)
        .unwrap();
    assert!(!entries.is_empty());
}

#[test]
fn truncate_and_sync_address_an_open_object_without_a_path() {
    let mut filesystem = test_filesystem();
    let opened = filesystem
        .open_at(
            protocol::Header {
                opcode: protocol::OP_OPEN_AT,
                flags: protocol::OPEN_AT_READ
                    | protocol::OPEN_AT_WRITE
                    | protocol::OPEN_AT_CREATE,
                mode: 0o644,
                ..protocol::Header::default()
            },
            b"/truncate.txt",
            PathAnchors::default(),
        )
        .unwrap();
    let open_id = opened.header.open_id;
    filesystem.provider_write(open_id, b"abcdefgh").unwrap();

    filesystem
        .truncate_handle(
            protocol::Header {
                opcode: protocol::OP_TRUNCATE_HANDLE,
                offset: 3,
                ..protocol::Header::default()
            },
            open_id,
        )
        .unwrap();
    filesystem
        .provider_seek(open_id, 0, HANDLE_SEEK_START)
        .unwrap();
    assert_eq!(filesystem.provider_read(open_id, 8).unwrap(), b"abc");
    filesystem
        .sync_handle(
            protocol::Header {
                opcode: protocol::OP_SYNC_HANDLE,
                ..protocol::Header::default()
            },
            open_id,
        )
        .unwrap();
}

#[test]
fn duplicated_open_descriptions_share_mutable_status_flags() {
    let mut filesystem = test_filesystem();
    let opened = filesystem
        .open_at(
            protocol::Header {
                opcode: protocol::OP_OPEN_AT,
                flags: protocol::OPEN_AT_READ | protocol::OPEN_AT_WRITE | protocol::OPEN_AT_CREATE,
                mode: 0o644,
                ..protocol::Header::default()
            },
            b"/flags.txt",
            PathAnchors::default(),
        )
        .unwrap();
    let open_id = opened.header.open_id;
    let wanted = protocol::OPEN_STATUS_APPEND | protocol::OPEN_STATUS_NONBLOCK;
    filesystem
        .set_flags_handle(
            protocol::Header {
                opcode: protocol::OP_SET_FLAGS_HANDLE,
                flags: wanted,
                ..protocol::Header::default()
            },
            open_id,
        )
        .unwrap();

    let flags = filesystem
        .get_flags_handle(
            protocol::Header {
                opcode: protocol::OP_GET_FLAGS_HANDLE,
                ..protocol::Header::default()
            },
            open_id,
        )
        .unwrap();
    assert_eq!(flags.header.flags, wanted);

    filesystem.provider_write(open_id, b"a").unwrap();
    filesystem
        .provider_seek(open_id, 0, HANDLE_SEEK_START)
        .unwrap();
    filesystem.provider_write(open_id, b"b").unwrap();
    filesystem
        .provider_seek(open_id, 0, HANDLE_SEEK_START)
        .unwrap();
    assert_eq!(filesystem.provider_read(open_id, 2).unwrap(), b"ab");
}

#[test]
fn mkdir_at_is_anchored_to_an_open_directory() {
    let mut filesystem = test_filesystem();
    let base = filesystem
        .open_at(
            protocol::Header {
                opcode: protocol::OP_OPEN_AT,
                flags: protocol::OPEN_AT_READ | protocol::OPEN_AT_DIRECTORY,
                ..protocol::Header::default()
            },
            b"/removed",
            PathAnchors::default(),
        )
        .unwrap();
    filesystem
        .mkdir_at(
            protocol::Header {
                opcode: protocol::OP_MKDIR_AT,
                offset: 1000 | (1000 << 32),
                flags: protocol::MKDIR_AT_BASE_ATTACHED,
                mode: 0o755,
                ..protocol::Header::default()
            },
            b"child",
            PathAnchors {
                root_open_id: None,
                base_open_id: Some(base.header.open_id),
            },
        )
        .unwrap();

    let status = filesystem.handle(
        protocol::Header {
            opcode: protocol::OP_LOOKUP,
            flags: protocol::LOOKUP_FOLLOW_SYMLINKS,
            ..protocol::Header::default()
        },
        b"/removed/child",
    );
    assert_eq!(status.header.status, 0);
    assert_eq!(status.header.flags, protocol::NODE_TYPE_DIRECTORY);
}

#[test]
fn orphan_cleanup_uses_parent_inode_after_parent_rename() {
    let mut filesystem = test_filesystem();
    filesystem
        .mkdir_at(
            protocol::Header {
                opcode: protocol::OP_MKDIR_AT,
                mode: 0o755,
                ..protocol::Header::default()
            },
            b"/create-base/parent",
            PathAnchors::default(),
        )
        .unwrap();
    let opened = filesystem
        .open_at(
            protocol::Header {
                opcode: protocol::OP_OPEN_AT,
                flags: protocol::OPEN_AT_READ
                    | protocol::OPEN_AT_WRITE
                    | protocol::OPEN_AT_CREATE,
                mode: 0o644,
                ..protocol::Header::default()
            },
            b"/create-base/parent/file",
            PathAnchors::default(),
        )
        .unwrap();
    let removed = filesystem.handle(
        protocol::Header {
            opcode: protocol::OP_UNLINK,
            flags: protocol::NODE_TYPE_REGULAR,
            ..protocol::Header::default()
        },
        b"/create-base/parent/file",
    );
    assert_eq!(removed.header.status, 0);

    let old = b"/create-base/parent";
    let new = b"/create-base/renamed";
    let mut paths = old.to_vec();
    paths.extend_from_slice(new);
    let renamed = filesystem.handle(
        protocol::Header {
            opcode: protocol::OP_RENAME,
            offset: old.len() as u64,
            ..protocol::Header::default()
        },
        &paths,
    );
    assert_eq!(renamed.header.status, 0);
    filesystem.provider_close(opened.header.open_id).unwrap();
}

#[test]
fn unlink_at_removes_entries_relative_to_an_open_directory() {
    let mut filesystem = test_filesystem();
    let base = filesystem
        .open_at(
            protocol::Header {
                opcode: protocol::OP_OPEN_AT,
                flags: protocol::OPEN_AT_READ | protocol::OPEN_AT_DIRECTORY,
                ..protocol::Header::default()
            },
            b"/create-base",
            PathAnchors::default(),
        )
        .unwrap();
    filesystem
        .mkdir_at(
            protocol::Header {
                opcode: protocol::OP_MKDIR_AT,
                flags: protocol::MKDIR_AT_BASE_ATTACHED,
                mode: 0o755,
                ..protocol::Header::default()
            },
            b"victim",
            PathAnchors {
                root_open_id: None,
                base_open_id: Some(base.header.open_id),
            },
        )
        .unwrap();
    filesystem
        .unlink_at(
            protocol::Header {
                opcode: protocol::OP_UNLINK_AT,
                flags: protocol::UNLINK_AT_BASE_ATTACHED
                    | protocol::UNLINK_AT_REMOVE_DIRECTORY,
                ..protocol::Header::default()
            },
            b"victim",
            PathAnchors {
                root_open_id: None,
                base_open_id: Some(base.header.open_id),
            },
        )
        .unwrap();

    let missing = filesystem.handle(
        protocol::Header {
            opcode: protocol::OP_LOOKUP,
            flags: protocol::LOOKUP_FOLLOW_SYMLINKS,
            ..protocol::Header::default()
        },
        b"/create-base/victim",
    );
    assert_eq!(missing.header.status, -2);
}

#[test]
fn unlink_at_keeps_an_open_file_description_alive() {
    let mut filesystem = test_filesystem();
    let base = filesystem
        .open_at(
            protocol::Header {
                opcode: protocol::OP_OPEN_AT,
                flags: protocol::OPEN_AT_READ | protocol::OPEN_AT_DIRECTORY,
                ..protocol::Header::default()
            },
            b"/create-base",
            PathAnchors::default(),
        )
        .unwrap();
    let file = filesystem
        .open_at(
            protocol::Header {
                opcode: protocol::OP_OPEN_AT,
                flags: protocol::OPEN_AT_READ
                    | protocol::OPEN_AT_WRITE
                    | protocol::OPEN_AT_CREATE
                    | protocol::OPEN_AT_BASE_ATTACHED,
                mode: 0o644,
                ..protocol::Header::default()
            },
            b"open-victim",
            PathAnchors {
                root_open_id: None,
                base_open_id: Some(base.header.open_id),
            },
        )
        .unwrap();
    filesystem
        .provider_write(file.header.open_id, b"alive")
        .unwrap();
    filesystem
        .unlink_at(
            protocol::Header {
                opcode: protocol::OP_UNLINK_AT,
                flags: protocol::UNLINK_AT_BASE_ATTACHED,
                ..protocol::Header::default()
            },
            b"open-victim",
            PathAnchors {
                root_open_id: None,
                base_open_id: Some(base.header.open_id),
            },
        )
        .unwrap();
    filesystem
        .provider_seek(file.header.open_id, 0, HANDLE_SEEK_START)
        .unwrap();
    assert_eq!(
        filesystem.provider_read(file.header.open_id, 5).unwrap(),
        b"alive"
    );
    filesystem.provider_close(file.header.open_id).unwrap();
}

#[test]
fn rename_at_moves_between_two_open_directories_and_replaces_atomically() {
    let mut filesystem = test_filesystem();
    let old_base = filesystem
        .open_at(
            protocol::Header {
                opcode: protocol::OP_OPEN_AT,
                flags: protocol::OPEN_AT_READ | protocol::OPEN_AT_DIRECTORY,
                ..protocol::Header::default()
            },
            b"/create-base",
            PathAnchors::default(),
        )
        .unwrap();
    let new_base = filesystem
        .open_at(
            protocol::Header {
                opcode: protocol::OP_OPEN_AT,
                flags: protocol::OPEN_AT_READ | protocol::OPEN_AT_DIRECTORY,
                ..protocol::Header::default()
            },
            b"/removed",
            PathAnchors::default(),
        )
        .unwrap();
    let source = filesystem
        .open_at(
            protocol::Header {
                opcode: protocol::OP_OPEN_AT,
                flags: protocol::OPEN_AT_READ
                    | protocol::OPEN_AT_WRITE
                    | protocol::OPEN_AT_CREATE
                    | protocol::OPEN_AT_BASE_ATTACHED,
                mode: 0o644,
                ..protocol::Header::default()
            },
            b"source",
            PathAnchors {
                root_open_id: None,
                base_open_id: Some(old_base.header.open_id),
            },
        )
        .unwrap();
    filesystem
        .provider_write(source.header.open_id, b"source-data")
        .unwrap();
    let destination = filesystem
        .open_at(
            protocol::Header {
                opcode: protocol::OP_OPEN_AT,
                flags: protocol::OPEN_AT_READ
                    | protocol::OPEN_AT_WRITE
                    | protocol::OPEN_AT_CREATE
                    | protocol::OPEN_AT_BASE_ATTACHED,
                mode: 0o644,
                ..protocol::Header::default()
            },
            b"destination",
            PathAnchors {
                root_open_id: None,
                base_open_id: Some(new_base.header.open_id),
            },
        )
        .unwrap();
    filesystem
        .provider_write(destination.header.open_id, b"old")
        .unwrap();
    let mut payload = b"source".to_vec();
    payload.extend_from_slice(b"destination");
    filesystem
        .rename_at(
            protocol::Header {
                opcode: protocol::OP_RENAME_AT,
                flags: protocol::RENAME_AT_OLD_BASE_ATTACHED
                    | protocol::RENAME_AT_NEW_BASE_ATTACHED,
                mode: 6,
                ..protocol::Header::default()
            },
            &payload,
            RenameAnchors {
                root_open_id: None,
                old_base_open_id: Some(old_base.header.open_id),
                new_base_open_id: Some(new_base.header.open_id),
            },
        )
        .unwrap();

    filesystem
        .provider_seek(source.header.open_id, 0, HANDLE_SEEK_START)
        .unwrap();
    assert_eq!(
        filesystem.provider_read(source.header.open_id, 11).unwrap(),
        b"source-data"
    );
    filesystem
        .provider_seek(destination.header.open_id, 0, HANDLE_SEEK_START)
        .unwrap();
    assert_eq!(
        filesystem
            .provider_read(destination.header.open_id, 3)
            .unwrap(),
        b"old"
    );
    filesystem.provider_close(destination.header.open_id).unwrap();
}

#[test]
fn truncate_at_resolves_and_mutates_in_one_anchored_operation() {
    let mut filesystem = test_filesystem();
    let base = filesystem
        .open_at(
            protocol::Header {
                opcode: protocol::OP_OPEN_AT,
                flags: protocol::OPEN_AT_READ | protocol::OPEN_AT_DIRECTORY,
                ..protocol::Header::default()
            },
            b"/create-base",
            PathAnchors::default(),
        )
        .unwrap();
    let file = filesystem
        .open_at(
            protocol::Header {
                opcode: protocol::OP_OPEN_AT,
                flags: protocol::OPEN_AT_READ
                    | protocol::OPEN_AT_WRITE
                    | protocol::OPEN_AT_CREATE
                    | protocol::OPEN_AT_BASE_ATTACHED,
                mode: 0o666,
                ..protocol::Header::default()
            },
            b"truncate-path",
            PathAnchors {
                root_open_id: None,
                base_open_id: Some(base.header.open_id),
            },
        )
        .unwrap();
    filesystem
        .provider_write(file.header.open_id, b"abcdefgh")
        .unwrap();
    filesystem
        .truncate_at(
            protocol::Header {
                opcode: protocol::OP_TRUNCATE_AT,
                open_id: 3,
                flags: protocol::TRUNCATE_AT_BASE_ATTACHED,
                ..protocol::Header::default()
            },
            b"truncate-path",
            PathAnchors {
                root_open_id: None,
                base_open_id: Some(base.header.open_id),
            },
        )
        .unwrap();
    filesystem
        .provider_seek(file.header.open_id, 0, HANDLE_SEEK_START)
        .unwrap();
    assert_eq!(filesystem.provider_read(file.header.open_id, 8).unwrap(), b"abc");
}

#[test]
fn open_directory_paths_follow_rename_and_reject_unlinked_cwds() {
    let mut filesystem = test_filesystem();
    let root = filesystem
        .open_at(
            protocol::Header {
                opcode: protocol::OP_OPEN_AT,
                flags: protocol::OPEN_AT_READ | protocol::OPEN_AT_DIRECTORY,
                ..protocol::Header::default()
            },
            b"/",
            PathAnchors::default(),
        )
        .unwrap()
        .header
        .open_id;
    let cwd = filesystem
        .open_at(
            protocol::Header {
                opcode: protocol::OP_OPEN_AT,
                flags: protocol::OPEN_AT_READ | protocol::OPEN_AT_DIRECTORY,
                ..protocol::Header::default()
            },
            b"/jail/inside",
            PathAnchors::default(),
        )
        .unwrap()
        .header
        .open_id;

    let initial = filesystem
        .path_handle(
            protocol::Header {
                opcode: protocol::OP_PATH_HANDLE,
                ..protocol::Header::default()
            },
            root,
            cwd,
        )
        .unwrap();
    assert_eq!(initial.payload, b"/jail/inside");

    let old = b"/jail/inside";
    let new = b"/jail/moved";
    let mut rename = Vec::from(old.as_slice());
    rename.extend_from_slice(new);
    let renamed = filesystem.handle(
        protocol::Header {
            opcode: protocol::OP_RENAME,
            offset: old.len() as u64,
            ..protocol::Header::default()
        },
        &rename,
    );
    assert_eq!(renamed.header.status, 0);
    let current = filesystem
        .path_handle(
            protocol::Header {
                opcode: protocol::OP_PATH_HANDLE,
                ..protocol::Header::default()
            },
            root,
            cwd,
        )
        .unwrap();
    assert_eq!(current.payload, b"/jail/moved");

    let removed = filesystem.handle(
        protocol::Header {
            opcode: protocol::OP_UNLINK,
            flags: protocol::NODE_TYPE_DIRECTORY,
            ..protocol::Header::default()
        },
        b"/jail/moved",
    );
    assert_eq!(removed.header.status, 0);
    let missing = filesystem.path_handle(
        protocol::Header {
            opcode: protocol::OP_PATH_HANDLE,
            ..protocol::Header::default()
        },
        root,
        cwd,
    );
    assert!(matches!(missing, Err(2)));
}

#[test]
fn symlink_targets_enforce_search_permission_on_the_actual_directory() {
    let mut filesystem = test_filesystem();
    let result = filesystem.stat_at(
        protocol::Header {
            opcode: protocol::OP_STAT_AT,
            offset: u64::from(501u32) | (u64::from(20u32) << 32),
            ..protocol::Header::default()
        },
        b"/redirect",
        PathAnchors::default(),
    );
    assert!(matches!(result, Err(13)));

    let result = filesystem.open_at(
        protocol::Header {
            opcode: protocol::OP_OPEN_AT,
            offset: u64::from(501u32) | (u64::from(20u32) << 32),
            flags: protocol::OPEN_AT_READ,
            ..protocol::Header::default()
        },
        b"/redirect",
        PathAnchors::default(),
    );
    assert!(matches!(result, Err(13)));
}

#[test]
fn filesystem_node_ids_are_stable_ext4_inode_numbers() {
    let mut filesystem = test_filesystem();
    let mounted = filesystem.handle(
        protocol::Header {
            opcode: protocol::OP_MOUNT,
            ..protocol::Header::default()
        },
        &[],
    );
    let root = filesystem
        .stat_at(
            protocol::Header {
                opcode: protocol::OP_STAT_AT,
                ..protocol::Header::default()
            },
            b"/",
            PathAnchors::default(),
        )
        .unwrap();
    let root = protocol::decode_node_status(&root.payload).unwrap();
    assert_eq!(mounted.header.node_id, root.node_id);
    assert_eq!(root.node_id, 2);

    let lookup = filesystem.handle(
        protocol::Header {
            opcode: protocol::OP_LOOKUP,
            flags: protocol::LOOKUP_FOLLOW_SYMLINKS,
            ..protocol::Header::default()
        },
        b"/blocked/child",
    );
    let status = filesystem
        .stat_at(
            protocol::Header {
                opcode: protocol::OP_STAT_AT,
                offset: u64::from(0u32),
                ..protocol::Header::default()
            },
            b"/blocked/child",
            PathAnchors::default(),
        )
        .unwrap();
    let status = protocol::decode_node_status(&status.payload).unwrap();
    assert_eq!(lookup.header.node_id, status.node_id);
}

#[test]
fn create_at_uses_the_open_parent_inode_and_follows_a_dangling_symlink() {
    let mut filesystem = test_filesystem();
    let base = filesystem
        .open_at(
            protocol::Header {
                opcode: protocol::OP_OPEN_AT,
                flags: protocol::OPEN_AT_READ | protocol::OPEN_AT_DIRECTORY,
                ..protocol::Header::default()
            },
            b"/create-base",
            PathAnchors::default(),
        )
        .unwrap()
        .header
        .open_id;

    let directory_only = filesystem.open_at(
        protocol::Header {
            opcode: protocol::OP_OPEN_AT,
            flags: protocol::OPEN_AT_BASE_ATTACHED
                | protocol::OPEN_AT_READ
                | protocol::OPEN_AT_CREATE
                | protocol::OPEN_AT_DIRECTORY,
            mode: 0o755,
            ..protocol::Header::default()
        },
        b"directory-only",
        PathAnchors {
            base_open_id: Some(base),
            ..PathAnchors::default()
        },
    );
    assert!(matches!(directory_only, Err(2)));
    let absent = filesystem.stat_at(
        protocol::Header {
            opcode: protocol::OP_STAT_AT,
            flags: protocol::STAT_AT_BASE_ATTACHED,
            ..protocol::Header::default()
        },
        b"directory-only",
        PathAnchors {
            base_open_id: Some(base),
            ..PathAnchors::default()
        },
    );
    assert!(matches!(absent, Err(2)));

    let exclusive = filesystem.open_at(
        protocol::Header {
            opcode: protocol::OP_OPEN_AT,
            flags: protocol::OPEN_AT_BASE_ATTACHED
                | protocol::OPEN_AT_READ
                | protocol::OPEN_AT_WRITE
                | protocol::OPEN_AT_CREATE
                | protocol::OPEN_AT_EXCLUSIVE,
            mode: 0o640,
            ..protocol::Header::default()
        },
        b"dangling",
        PathAnchors {
            base_open_id: Some(base),
            ..PathAnchors::default()
        },
    );
    assert!(matches!(exclusive, Err(17)));

    filesystem
        .open_at(
            protocol::Header {
                opcode: protocol::OP_OPEN_AT,
                flags: protocol::OPEN_AT_BASE_ATTACHED
                    | protocol::OPEN_AT_READ
                    | protocol::OPEN_AT_WRITE
                    | protocol::OPEN_AT_CREATE,
                mode: 0o640,
                ..protocol::Header::default()
            },
            b"dangling",
            PathAnchors {
                base_open_id: Some(base),
                ..PathAnchors::default()
            },
        )
        .unwrap();

    let target = filesystem
        .stat_at(
            protocol::Header {
                opcode: protocol::OP_STAT_AT,
                flags: protocol::STAT_AT_BASE_ATTACHED,
                ..protocol::Header::default()
            },
            b"target",
            PathAnchors {
                base_open_id: Some(base),
                ..PathAnchors::default()
            },
        )
        .unwrap();
    let target = protocol::decode_node_status(&target.payload).unwrap();
    assert_eq!(target.kind, protocol::NODE_TYPE_REGULAR);
    assert_eq!(target.mode & 0o777, 0o640);

    let link = filesystem
        .stat_at(
            protocol::Header {
                opcode: protocol::OP_STAT_AT,
                flags: protocol::STAT_AT_BASE_ATTACHED | protocol::STAT_AT_NOFOLLOW,
                ..protocol::Header::default()
            },
            b"dangling",
            PathAnchors {
                base_open_id: Some(base),
                ..PathAnchors::default()
            },
        )
        .unwrap();
    let link = protocol::decode_node_status(&link.payload).unwrap();
    assert_eq!(link.kind, protocol::NODE_TYPE_SYMLINK);
}

#[test]
fn root_anchor_confines_absolute_paths_symlinks_and_parent_components() {
    let mut filesystem = test_filesystem();
    let root = filesystem
        .open_at(
            protocol::Header {
                opcode: protocol::OP_OPEN_AT,
                flags: protocol::OPEN_AT_READ | protocol::OPEN_AT_DIRECTORY,
                ..protocol::Header::default()
            },
            b"/jail",
            PathAnchors::default(),
        )
        .unwrap()
        .header
        .open_id;
    let inside = filesystem
        .open_at(
            protocol::Header {
                opcode: protocol::OP_OPEN_AT,
                flags: protocol::OPEN_AT_READ
                    | protocol::OPEN_AT_DIRECTORY
                    | protocol::OPEN_AT_ROOT_ATTACHED,
                ..protocol::Header::default()
            },
            b"/inside",
            PathAnchors {
                root_open_id: Some(root),
                ..PathAnchors::default()
            },
        )
        .unwrap()
        .header
        .open_id;

    for path in [b"/../outside".as_slice(), b"/escape".as_slice()] {
        let escaped = filesystem.stat_at(
            protocol::Header {
                opcode: protocol::OP_STAT_AT,
                flags: protocol::STAT_AT_ROOT_ATTACHED,
                ..protocol::Header::default()
            },
            path,
            PathAnchors {
                root_open_id: Some(root),
                ..PathAnchors::default()
            },
        );
        assert!(matches!(escaped, Err(2)));
    }

    let escaped = filesystem.stat_at(
        protocol::Header {
            opcode: protocol::OP_STAT_AT,
            flags: protocol::STAT_AT_ROOT_ATTACHED | protocol::STAT_AT_BASE_ATTACHED,
            ..protocol::Header::default()
        },
        b"../../outside",
        PathAnchors {
            root_open_id: Some(root),
            base_open_id: Some(inside),
        },
    );
    assert!(matches!(escaped, Err(2)));
}
