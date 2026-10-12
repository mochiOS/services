use std::io::Write;
use std::process::{Command, Stdio};

#[test]
fn actual_kernel_size_queries_preserve_boot_precedence_and_provider_errors() {
    let source = include_str!("../../../core/src/syscall/fs.rs");
    let mut program = String::from(
        r#"
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
const EIO: u64 = (-5i64) as u64;
static INIT: AtomicBool = AtomicBool::new(false);
static MOUNTED: AtomicBool = AtomicBool::new(false);
static FAIL: AtomicBool = AtomicBool::new(false);
static CEXT_CALLS: AtomicUsize = AtomicUsize::new(0);
static LOOKUPS: AtomicUsize = AtomicUsize::new(0);
static ROOT_CALLS: AtomicUsize = AtomicUsize::new(0);
mod performance { pub fn record_vfs_metadata_query() {} }
mod init { pub mod fs {
    pub fn initfs_file_metadata(_: &str) -> Option<(u16, u64)> {
        crate::INIT.load(std::sync::atomic::Ordering::Acquire).then_some((0, 11))
    }
    pub fn file_metadata(_: &str) -> Option<(u16, u64)> {
        crate::ROOT_CALLS.fetch_add(1, std::sync::atomic::Ordering::Relaxed); Some((0xffff, 44))
    }
} }
mod cext { pub mod fs {
    pub fn handle_metadata(handle: u64) -> Option<(u16, u64, u32, u32)> {
        if handle == 1 { Some((0xffff, 55, u32::MAX, u32::MAX)) } else { None }
    }
    pub fn file_metadata(_: &str) -> Option<(u16, u64, u32, u32)> {
        crate::CEXT_CALLS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        (!crate::FAIL.load(std::sync::atomic::Ordering::Acquire)).then_some((0, 33, u32::MAX, u32::MAX))
    }
} }
mod vfs {
    pub struct MountId(pub u64);
    pub mod userspace {
        pub struct Node { pub size: u64 }
        pub fn lookup(_: u64, _: &str) -> Result<Node, u64> {
            crate::LOOKUPS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            if crate::FAIL.load(std::sync::atomic::Ordering::Acquire) { Err(crate::EIO) } else { Ok(Node { size: 22 }) }
        }
        pub fn stat(_: u64, _: u64, _: u64) -> Result<Node, u64> {
            if crate::FAIL.load(std::sync::atomic::Ordering::Acquire) { Err(crate::EIO) } else { Ok(Node { size: 66 }) }
        }
    }
}
struct Mount { mount_id: vfs::MountId, path: String }
fn userspace_mount(path: &str) -> Option<Mount> {
    MOUNTED.load(Ordering::Acquire).then(|| Mount { mount_id: vfs::MountId(2), path: path.into() })
}
struct Inode { mount_id: vfs::MountId }
struct Vnode { inode: Inode, user: bool, handle: Option<u64> }
impl Vnode {
    fn userspace_handle_ids(&self) -> Option<(u64, u64)> { self.user.then_some((1, 2)) }
    fn cext_handle_id(&self) -> Option<u64> { self.handle }
    fn path(&self) -> &str { "/image" }
}
"#,
    );
    for entry in ["fn vnode_size(", "fn file_size_rootfs_first("] {
        let start = source.find(entry).unwrap();
        let end = start + source[start..].find("\n}\n").unwrap() + 3;
        program.push_str(&source[start..end]);
    }
    program.push_str(r#"
fn main() {
    INIT.store(true, Ordering::Release); MOUNTED.store(true, Ordering::Release);
    assert_eq!(file_size_rootfs_first("/image"), Some(11));
    assert_eq!(LOOKUPS.load(Ordering::Relaxed), 0);
    assert_eq!(CEXT_CALLS.load(Ordering::Relaxed), 0);
    INIT.store(false, Ordering::Release);
    assert_eq!(file_size_rootfs_first("/image"), Some(22));
    FAIL.store(true, Ordering::Release);
    assert_eq!(file_size_rootfs_first("/image"), None);
    assert_eq!(CEXT_CALLS.load(Ordering::Relaxed), 0);
    assert_eq!(ROOT_CALLS.load(Ordering::Relaxed), 0);
    let user = Vnode { inode: Inode { mount_id: vfs::MountId(2) }, user: true, handle: Some(1) };
    assert_eq!(vnode_size(&user), Err(EIO)); // Never fall back from an open provider object to a pathname.
    FAIL.store(false, Ordering::Release);
    assert_eq!(vnode_size(&user), Ok(Some(66)));
    let cext = Vnode { inode: Inode { mount_id: vfs::MountId(1) }, user: false, handle: Some(1) };
    assert_eq!(vnode_size(&cext), Ok(Some(55)));
    assert_eq!(CEXT_CALLS.load(Ordering::Relaxed), 0);
    MOUNTED.store(false, Ordering::Release);
    assert_eq!(file_size_rootfs_first("/image"), Some(33));
    FAIL.store(true, Ordering::Release);
    assert_eq!(file_size_rootfs_first("/image"), Some(44));
}
"#);
    let directory = std::env::temp_dir().join(format!(
        "mochios-kernel-size-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&directory).unwrap();
    let executable = directory.join("probe");
    let mut compiler = Command::new("rustc")
        .args(["--edition=2021", "-Awarnings", "-"])
        .arg("-o")
        .arg(&executable)
        .stdin(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    compiler
        .stdin
        .take()
        .unwrap()
        .write_all(program.as_bytes())
        .unwrap();
    let result = compiler.wait_with_output().unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let result = Command::new(executable).output().unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn transitional_kernel_object_records_no_longer_store_posix_ownership_or_modes() {
    let source = include_str!("../../../core/src/vfs/userspace.rs");
    let fields = source
        .split("pub struct NodeInfo {")
        .nth(1)
        .unwrap()
        .split('}')
        .next()
        .unwrap();
    assert!(!fields.contains("mode:") && !fields.contains("uid:") && !fields.contains("gid:"));
    let fs = include_str!("../../../core/src/syscall/fs.rs");
    assert!(!fs.contains("struct FileMetadata") && !fs.contains("fn userspace_mode("));
    assert!(source.contains("protocol::decode_metadata(payload).map_err(|_| EIO)?;"));
}
