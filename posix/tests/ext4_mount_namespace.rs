use std::error::Error;
use std::fs;
use std::io;
use std::os::unix::fs::symlink;
use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use ext4plus::{Ext4, Ext4Read};
use filesystem_service::namespace::{Namespace, Node};
use filesystem_service::path_walk::{Credentials, Resolution};

struct Image(Vec<u8>);
impl Ext4Read for Image {
    fn read(&self, offset: u64, output: &mut [u8]) -> Result<(), Box<dyn Error + Send + Sync>> {
        let start = usize::try_from(offset)?;
        let end = start
            .checked_add(output.len())
            .ok_or_else(|| io::Error::other("offset overflow"))?;
        output.copy_from_slice(
            self.0
                .get(start..end)
                .ok_or_else(|| io::Error::other("outside image"))?,
        );
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
        Ext4::load(Box::new(Image(fs::read(image).unwrap()))).unwrap()
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
