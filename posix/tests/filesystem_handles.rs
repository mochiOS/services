use std::error::Error;
use std::fs;
use std::io;
use std::os::unix::fs::symlink;
use std::path::PathBuf;
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use ext4plus::{Ext4, Ext4Read, Ext4Write};
use filesystem_service::service::FilesystemService;
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
    let image_path = temporary.0.join("filesystem.ext4");
    fs::create_dir_all(&directory).unwrap();
    fs::create_dir_all(&blocked).unwrap();
    fs::write(blocked.join("child"), b"private").unwrap();
    symlink("/blocked/child", source.join("redirect")).unwrap();
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
            None,
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
fn symlink_targets_enforce_search_permission_on_the_actual_directory() {
    let mut filesystem = test_filesystem();
    let result = filesystem.stat_at(
        protocol::Header {
            opcode: protocol::OP_STAT_AT,
            offset: u64::from(501u32) | (u64::from(20u32) << 32),
            ..protocol::Header::default()
        },
        b"/redirect",
        None,
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
        None,
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
            None,
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
            None,
        )
        .unwrap();
    let status = protocol::decode_node_status(&status.payload).unwrap();
    assert_eq!(lookup.header.node_id, status.node_id);
}
