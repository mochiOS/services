use filesystem_service::readonly_tree::{Budget, Open, Tree};
use mochios_filesystem_protocol::{self as wire, readonly_tree as format};
fn bytes() -> Vec<u8> {
    let mut bytes = format::begin();
    format::append(&mut bytes, "fonts/a.ttf", b"abcdef").unwrap();
    format::append(&mut bytes, "secret", b"neighbor").unwrap();
    bytes
}
#[test]
fn explicit_tree_rejects_ambient_paths_and_subdirectory_escape() {
    let tree = Tree::capture(bytes(), &Budget::default()).unwrap();
    let fonts = tree.resolve(0, b"fonts").unwrap();
    for path in [
        b"../secret".as_slice(),
        b"/secret",
        b"a.ttf/../..",
        b"../../fonts/a.ttf",
        b"a.ttf/",
    ] {
        assert!(tree.resolve(fonts, path).is_err());
    }
    assert!(tree.resolve(fonts, b"./a.ttf").is_ok());
    let a = tree.resolve(fonts, b"a.ttf").unwrap();
    let mut output = [0xaa; 32];
    assert_eq!(tree.read(a, 4, &mut output).unwrap(), 2);
    assert_eq!(&output[..2], b"ef");
    assert_eq!(output[2], 0xaa);
    assert_eq!(tree.read(a, u64::MAX, &mut output).unwrap(), 0);
}
#[test]
fn malformed_duplicates_collisions_and_trailing_bytes_are_rejected() {
    let budget = Budget::default();
    for names in [["a", "a"], ["a", "a/b"], ["a/b", "a"]] {
        let mut bytes = format::begin();
        for name in names {
            format::append(&mut bytes, name, b"x").unwrap();
        }
        assert!(Tree::capture(bytes, &budget).is_err());
    }
    let bytes = bytes();
    for end in 0..bytes.len() {
        assert!(Tree::capture(bytes[..end].to_vec(), &budget).is_err());
    }
    let mut extra = bytes.clone();
    extra.push(0);
    assert!(Tree::capture(extra, &budget).is_err());
    let mut reserved = bytes;
    reserved[20] = 1;
    assert!(Tree::capture(reserved, &budget).is_err());
    assert_eq!(budget.used(), 0);
}
#[test]
fn captured_bytes_and_budget_follow_the_last_reference() {
    let budget = Budget::default();
    let source = bytes();
    let tree = Tree::capture(source.clone(), &budget).unwrap();
    assert!(budget.used() >= source.len());
    let node = tree.resolve(0, b"fonts/a.ttf").unwrap();
    let mut open = Open {
        tree: tree.clone(),
        node,
        identity_base: 10,
        offset: 0,
        flags: 0,
        cursor_records: true,
    };
    drop(tree);
    assert!(budget.used() > 0);
    let mut out = [0; 3];
    assert_eq!(open.read(&mut out).unwrap(), (3, 0));
    assert_eq!(&out, b"abc");
    assert_eq!(open.seek(-1, mnu_abi::HANDLE_SEEK_END).unwrap(), 5);
    assert_eq!(open.read(&mut out).unwrap(), (1, 5));
    assert_eq!(out[0], b'f');
    drop(open);
    assert_eq!(budget.used(), 0);
}
#[test]
fn directory_stream_preserves_cookies_and_omits_other_directory_contents() {
    let tree = Tree::capture(bytes(), &Budget::default()).unwrap();
    let mut open = Open {
        tree,
        node: 0,
        identity_base: 10,
        offset: 0,
        flags: 0,
        cursor_records: true,
    };
    let records = open.read_directory(32).unwrap();
    let (header, name, used) = wire::decode_dir_entry(&records).unwrap();
    assert_eq!(name, b"fonts");
    assert_eq!(header.next_position, Some(1));
    assert_eq!(used, records.len());
    let records = open.read_directory(128).unwrap();
    let (_, name, _) = wire::decode_dir_entry(&records).unwrap();
    assert_eq!(name, b"secret");
    assert!(open.read_directory(128).unwrap().is_empty());
    open.seek(0, mnu_abi::HANDLE_SEEK_START).unwrap();
    assert!(!open.read_directory(128).unwrap().is_empty());
    assert!(open.seek(0, mnu_abi::HANDLE_SEEK_END).is_err());
}

use ext4plus::{Ext4, Ext4Read};
use filesystem_service::service::{FilesystemService, PathAnchors};
use std::{path::PathBuf, process::Command};
struct Fixture(PathBuf);
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
struct Image(Vec<u8>);
impl Ext4Read for Image {
    fn read(
        &self,
        offset: u64,
        output: &mut [u8],
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let start = usize::try_from(offset)?;
        output.copy_from_slice(
            self.0
                .get(start..start.checked_add(output.len()).ok_or("overflow")?)
                .ok_or("outside image")?,
        );
        Ok(())
    }
}
fn fixture() -> (Fixture, FilesystemService) {
    let dir = std::env::temp_dir().join(format!("mochi-readonly-tree-{}", std::process::id()));
    std::fs::create_dir_all(dir.join("source")).unwrap();
    let fixture = Fixture(dir);
    std::fs::write(fixture.0.join("source/file"), b"data").unwrap();
    std::fs::hard_link(
        fixture.0.join("source/file"),
        fixture.0.join("source/alias"),
    )
    .unwrap();
    let image = fixture.0.join("fs.img");
    std::fs::File::create(&image)
        .unwrap()
        .set_len(8 * 1024 * 1024)
        .unwrap();
    let output = Command::new("mke2fs")
        .args(["-q", "-t", "ext4", "-I", "256", "-F", "-d"])
        .arg(fixture.0.join("source"))
        .arg(&image)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let fs = Ext4::load(Box::new(Image(std::fs::read(image).unwrap()))).unwrap();
    (fixture, FilesystemService::new(fs))
}

#[test]
fn filesystem_status_open_pager_and_mutation_use_the_same_snapshot() {
    let (_fixture, mut service) = fixture();
    let root = service.create_readonly_tree(bytes()).unwrap();
    let mut credentials_bytes = [0; wire::CREDENTIALS_MAX_LEN];
    let n = wire::encode_credentials_payload(1000, 1000, &[], &[], &mut credentials_bytes).unwrap();
    let mut credentials = wire::decode_credentials_payload(&credentials_bytes[..n])
        .unwrap()
        .0;
    credentials.namespace = wire::namespace_policy::NamespacePolicy {
        explicit_read_bases: 1,
        ..wire::namespace_policy::NamespacePolicy::denied()
    };
    let anchors = PathAnchors {
        base_open_id: Some(root),
        ..Default::default()
    };
    let request = wire::Header {
        flags: wire::OPEN_AT_BASE_ATTACHED | wire::OPEN_AT_READ,
        ..Default::default()
    };
    let mut denied = credentials;
    denied.namespace.explicit_read_bases = 0;
    assert!(
        service
            .open_at(request, b"fonts/a.ttf", anchors, denied)
            .is_err()
    );
    let file = service
        .open_at(request, b"fonts/a.ttf", anchors, credentials)
        .unwrap()
        .header
        .open_id;
    let status = service.stat_handle(wire::Header::default(), file).unwrap();
    let status = wire::decode_node_status(&status.payload).unwrap();
    assert_eq!(status.size, 6);
    assert_eq!(status.mode, 0o444);
    assert_eq!(service.provider_read(file, 2).unwrap(), b"ab");
    let mut mapped_page = [0; 4096];
    assert_eq!(
        service
            .provider_read_at_into(file, 0, &mut mapped_page)
            .unwrap(),
        6
    );
    assert_eq!(&mapped_page[..6], b"abcdef");
    assert!(mapped_page[6..].iter().all(|b| *b == 0));
    let other = service
        .open_at(request, b"fonts/a.ttf", anchors, credentials)
        .unwrap()
        .header
        .open_id;
    assert_eq!(
        service.provider_memory_object(file).unwrap(),
        service.provider_memory_object(other).unwrap()
    );
    assert_eq!(
        service.snapshot_rights(file).unwrap()
            & (mnu_abi::HANDLE_RIGHT_WRITE | mnu_abi::HANDLE_RIGHT_CONTROL),
        0
    );
    assert_eq!(service.provider_write(file, b"x"), Err(30));
    assert!(
        service
            .open_at(
                wire::Header {
                    flags: request.flags | wire::OPEN_AT_WRITE,
                    ..request
                },
                b"fonts/a.ttf",
                anchors,
                credentials
            )
            .is_err()
    );
    assert!(
        service
            .open_at(
                wire::Header {
                    flags: request.flags | wire::OPEN_AT_EXECUTE,
                    ..request
                },
                b"fonts/a.ttf",
                anchors,
                credentials
            )
            .is_err()
    );
    service.provider_close(root).unwrap();
    assert_eq!(service.provider_read_at(file, 0, 99).unwrap(), b"abcdef");
    service.provider_close(file).unwrap();
    service.provider_close(other).unwrap();
    assert!(service.stat_handle(wire::Header::default(), file).is_err());
}
