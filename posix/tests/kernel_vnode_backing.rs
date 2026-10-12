use std::io::Write;
use std::process::{Command, Stdio};

#[test]
fn actual_cext_vnode_io_keeps_object_identity_and_closes_only_on_last_reference() {
    let source = include_str!("../../../core/src/vfs/mod.rs");
    let mut program = String::from(
        r#"
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
static FAIL: AtomicBool = AtomicBool::new(false);
static PATH_CALLS: AtomicUsize = AtomicUsize::new(0);
static CLOSES: AtomicUsize = AtomicUsize::new(0);
mod syscall {
    pub const EIO: u64 = (-5i64) as u64;
    pub mod fs {
        pub fn read_file_range_rootfs_first(_: &str, offset: u64, output: &mut [u8]) -> Option<usize> {
            assert_eq!(offset, 9); crate::PATH_CALLS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            output[0] = 3; Some(1)
        }
    }
}
mod cext { pub mod fs {
    pub fn read_handle(handle: u64, offset: u64, output: &mut [u8]) -> Result<usize, i32> {
        assert_eq!((handle, offset), (7, 12));
        if crate::FAIL.load(std::sync::atomic::Ordering::Acquire) { return Err(-13); }
        output[..2].copy_from_slice(b"ok"); Ok(2)
    }
    pub fn write_handle(handle: u64, offset: u64, input: &[u8]) -> Result<usize, i32> {
        assert_eq!((handle, offset, input), (7, 13, b"ok".as_slice()));
        if crate::FAIL.load(std::sync::atomic::Ordering::Acquire) { Err(-13) } else { Ok(input.len()) }
    }
    pub fn write_all(_: &str, offset: u64, input: &[u8]) -> Result<usize, i32> {
        assert_eq!(offset, 10); crate::PATH_CALLS.fetch_add(1, std::sync::atomic::Ordering::Relaxed); Ok(input.len())
    }
    pub fn close_handle(handle: u64) -> Result<(), i32> {
        assert_eq!(handle, 7); crate::CLOSES.fetch_add(1, std::sync::atomic::Ordering::Relaxed); Ok(())
    }
} }
mod mochios_filesystem_protocol { pub const MAX_IO_LEN: usize = 16384; }
"#,
    );
    for entry in [
        "pub struct MountId(",
        "pub struct InodeId(",
        "pub enum VnodeKind {",
        "pub struct Inode {",
        "pub enum VnodeBacking {",
        "pub struct Vnode {",
        "impl Vnode {",
        "fn cext_errno(",
        "impl Drop for Vnode {",
        "fn legacy_inode_id(",
    ] {
        let start = source.find(entry).unwrap();
        if entry.starts_with("pub struct MountId(") || entry.starts_with("pub struct InodeId(") {
            let end = start + source[start..].find(';').unwrap() + 1;
            program.push_str("#[derive(Clone, Copy)]\n");
            program.push_str(&source[start..end]);
            program.push('\n');
        } else {
            let end = start + source[start..].find("\n}\n").unwrap() + 3;
            if entry == "pub enum VnodeKind {" {
                program.push_str(source[..start].lines().last().unwrap());
                program.push('\n');
            }
            program.push_str(&source[start..end]);
        }
    }
    program.push_str(
        r#"
fn main() {
    let vnode = Arc::new(Vnode::cext_handle(MountId(1), "/old-name".into(), 7, VnodeKind::Regular));
    let duplicate = Arc::clone(&vnode);
    let mut bytes = [0; 8];
    assert_eq!(vnode.read_at(12, &mut bytes), Ok(2));
    assert_eq!(&bytes[..2], b"ok");
    assert_eq!(duplicate.write_at(13, b"ok"), Ok(2));
    assert_eq!(vnode.read_io_limit(), mochios_filesystem_protocol::MAX_IO_LEN);
    FAIL.store(true, Ordering::Release);
    assert_eq!(vnode.read_at(12, &mut bytes), Err((-13i64) as u64));
    assert_eq!(duplicate.write_at(13, b"ok"), Err((-13i64) as u64));
    assert_eq!(PATH_CALLS.load(Ordering::Relaxed), 0);
    drop(vnode); assert_eq!(CLOSES.load(Ordering::Relaxed), 0);
    drop(duplicate); assert_eq!(CLOSES.load(Ordering::Relaxed), 1);
    let legacy = Vnode::legacy_path("/boot-entry".into(), VnodeKind::Regular);
    assert_eq!(legacy.read_at(9, &mut bytes), Ok(1));
    assert_eq!(legacy.write_at(10, b"old"), Ok(3));
    drop(legacy);
    assert_eq!(PATH_CALLS.load(Ordering::Relaxed), 2);
    assert_eq!(CLOSES.load(Ordering::Relaxed), 1);
}
"#,
    );
    let directory = std::env::temp_dir().join(format!(
        "mochios-vnode-backing-{}-{}",
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
fn filesystem_specific_vnode_handles_cannot_replace_generic_provider_objects() {
    let source = include_str!("../../../core/src/vfs/mod.rs");
    assert!(!source.contains("UserspaceHandle") && !source.contains("fn userspace_handle"));
    let handles = include_str!("../../../core/src/syscall/handle.rs");
    assert!(handles.contains("Provider"));
    let provider = include_str!("../../filesystem/src/main.rs");
    assert!(provider.contains("provider::OP_READ") && provider.contains("provider::OP_RELEASE"));
}
