use std::io::Write;
use std::process::{Command, Stdio};

#[test]
fn actual_kernel_size_queries_preserve_boot_precedence_and_provider_errors() {
    let source = include_str!("../../../core/src/syscall/fs.rs");
    let mut program = String::from(
        r#"
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
const EIO: u64 = (-5i64) as u64;
const EACCES: u64 = (-13i64) as u64;
const EINVAL: u64 = (-22i64) as u64;
const EOVERFLOW: u64 = (-75i64) as u64;
use std::sync::Arc;
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
    pub fn handle_metadata(handle: u64) -> Result<(u16, u64, u32, u32), i32> {
        if handle == 1 { Ok((0xffff, 55, u32::MAX, u32::MAX)) } else { Err(-13) }
    }
    pub fn file_metadata(_: &str) -> Option<(u16, u64, u32, u32)> {
        crate::CEXT_CALLS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        (!crate::FAIL.load(std::sync::atomic::Ordering::Acquire)).then_some((0, 33, u32::MAX, u32::MAX))
    }
} }
mod vfs {
    pub struct MountId(pub u64);
    pub mod userspace {
        pub fn lookup_size(_: u64, _: &str) -> Result<u64, u64> {
            crate::LOOKUPS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            if crate::FAIL.load(std::sync::atomic::Ordering::Acquire) { Err(crate::EIO) } else { Ok(22) }
        }
    }
}
struct Mount { mount_id: vfs::MountId, path: String }
fn userspace_mount(path: &str) -> Option<Mount> {
    MOUNTED.load(Ordering::Acquire).then(|| Mount { mount_id: vfs::MountId(2), path: path.into() })
}
struct Vnode { handle: Option<u64> }
impl Vnode {
    fn cext_handle_id(&self) -> Option<u64> { self.handle }
    fn path(&self) -> &str { "/image" }
}
struct Lock<T>(std::sync::Mutex<T>);
impl<T> Lock<T> { fn lock(&self) -> std::sync::MutexGuard<'_, T> { self.0.lock().unwrap() } }
struct OpenFile { vnode: Option<Arc<Vnode>>, data: Vec<u8>, pos: usize }
struct FileHandle { cap: FileHandleCap, open: Arc<Lock<OpenFile>> }
#[derive(Clone, Copy)] struct FileHandleCap(u32);
impl FileHandleCap { const SEEK: Self = Self(1); fn contains(&self, other: Self) -> bool { self.0 & other.0 != 0 } }
#[derive(PartialEq, Eq)] enum SeekBasis { Start, Current, End }
"#,
    );
    for entry in [
        "fn vnode_size(",
        "fn file_size_rootfs_first(",
        "pub(crate) fn seek_file_handle(",
    ] {
        let start = source.find(entry).unwrap();
        let end = start + source[start..].find("\n}\n").unwrap() + 3;
        program.push_str(&source[start..end]);
    }
    let write = &source[source.find("pub(crate) fn write_file_handle(").unwrap()..];
    let append_start = write.find("    if (open_flags & O_APPEND) != 0 {").unwrap();
    let append_end = write.find("    let mut written = 0usize;").unwrap();
    program.push_str("const O_APPEND: u32 = 1;\nfn append_position(vnode: Option<Arc<Vnode>>, mut start_pos: usize, open_flags: u32) -> u64 {\n");
    program.push_str(&write[append_start..append_end]);
    program.push_str("start_pos as u64\n}\n");
    program.push_str(r#"
mod actual_metadata {
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
static MOUNTED: AtomicBool = AtomicBool::new(true);
static AVAILABLE: AtomicBool = AtomicBool::new(true);
static STATUS: AtomicI32 = AtomicI32::new(0);
struct Ops { stat_handle: unsafe fn(u64, *mut u16, *mut u64, *mut u32, *mut u32) -> i32 }
unsafe fn stat(handle: u64, mode: *mut u16, size: *mut u64, uid: *mut u32, gid: *mut u32) -> i32 {
    assert_eq!(handle, 7);
    unsafe { mode.write(0xffff); size.write(55); uid.write(12); gid.write(13); }
    STATUS.load(Ordering::Acquire)
}
static OPS: Ops = Ops { stat_handle: stat };
fn ops_ptr() -> *const Ops { if AVAILABLE.load(Ordering::Acquire) { &OPS } else { std::ptr::null() } }
pub fn verify() {
    assert_eq!(handle_metadata(7), Ok((0xffff, 55, 12, 13)));
    STATUS.store(-13, Ordering::Release);
    assert_eq!(handle_metadata(7), Err(-13));
    STATUS.store(7, Ordering::Release);
    assert_eq!(handle_metadata(7), Err(-5));
    MOUNTED.store(false, Ordering::Release);
    assert_eq!(handle_metadata(7), Err(-38));
    MOUNTED.store(true, Ordering::Release);
    AVAILABLE.store(false, Ordering::Release);
    assert_eq!(handle_metadata(7), Err(-38));
}
"#);
    let backend = include_str!("../../../core/src/cext/fs.rs");
    let start = backend.find("pub fn handle_metadata(").unwrap();
    let end = start + backend[start..].find("\n}\n").unwrap() + 3;
    program.push_str(&backend[start..end]);
    program.push_str("}\n");
    program.push_str(
        r#"
fn main() {
    actual_metadata::verify();
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
    FAIL.store(false, Ordering::Release);
    let cext = Vnode { handle: Some(1) };
    assert_eq!(vnode_size(&cext), Ok(Some(55)));
    let failed_handle = Vnode { handle: Some(2) };
    let before = LOOKUPS.load(Ordering::Relaxed);
    assert_eq!(vnode_size(&failed_handle), Err((-13i64) as u64));
    assert_eq!(LOOKUPS.load(Ordering::Relaxed), before);
    assert_eq!(CEXT_CALLS.load(Ordering::Relaxed), 0);
    let failed = Arc::new(failed_handle);
    let file = FileHandle { cap: FileHandleCap::SEEK,
        open: Arc::new(Lock(std::sync::Mutex::new(OpenFile { vnode: Some(Arc::clone(&failed)), data: vec![0; 99], pos: 17 }))) };
    assert_eq!(seek_file_handle(&file, 0, SeekBasis::End), EACCES);
    assert_eq!(file.open.lock().pos, 17);
    assert_eq!(append_position(Some(failed), 17, O_APPEND), EACCES);
    assert_eq!(CEXT_CALLS.load(Ordering::Relaxed), 0);
    assert_eq!(LOOKUPS.load(Ordering::Relaxed), before);
    let good = Arc::new(cext);
    file.open.lock().vnode = Some(Arc::clone(&good));
    assert_eq!(seek_file_handle(&file, 4, SeekBasis::End), 59);
    assert_eq!(append_position(Some(good), 17, O_APPEND), 55);
    MOUNTED.store(false, Ordering::Release);
    assert_eq!(file_size_rootfs_first("/image"), Some(33));
    FAIL.store(true, Ordering::Release);
    assert_eq!(file_size_rootfs_first("/image"), Some(44));
}
"#,
    );
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
    assert!(!source.contains("struct NodeInfo"));
    let fs = include_str!("../../../core/src/syscall/fs.rs");
    assert!(!fs.contains("struct FileMetadata") && !fs.contains("fn userspace_mode("));
    assert!(source.contains("protocol::decode_metadata(payload).map_err(|_| EIO)?;"));
}
