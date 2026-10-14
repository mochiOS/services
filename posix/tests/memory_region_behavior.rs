use std::fs;
use std::io::Write;
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

struct Temporary(std::path::PathBuf);

impl Drop for Temporary {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn production_region_preserves_authority_offsets_and_access_when_sliced() {
    // Compile the production metadata implementation, not a duplicated model.
    // Only the backing object's opaque payload is stubbed: these operations
    // retain its Arc and do not call the pager or privileged kernel code.
    let source = include_str!("../../../core/src/task/process.rs");
    let definitions_start = source
        .find("#[derive(Clone, Debug)]\npub enum MemoryBacking")
        .unwrap();
    let definitions_end = source
        .find("#[derive(Clone, Debug)]\npub struct DmaBuffer")
        .unwrap();
    let implementation_start = source.find("impl MemoryRegion {").unwrap();
    let implementation_end = source
        .find("/// Stable native process lifecycle object retained by `ProcessHandle`s")
        .unwrap();
    let mut probe = format!(
        "extern crate alloc; use alloc::sync::Arc;\n\
         mod mem {{ pub mod vm_object {{ #[derive(Debug)] pub struct VmObject; }} }}\n\
         mod mnu_abi {{ pub const MEMORY_ACCESS_READ:u64={};\n\
         pub const MEMORY_ACCESS_WRITE:u64={}; pub const MEMORY_ACCESS_EXECUTE:u64={};\n\
         pub const MEMORY_ACCESS_ALL:u64={}; pub const MEMORY_MAP_SHARED:u64={}; }}\n",
        mnu_abi::MEMORY_ACCESS_READ,
        mnu_abi::MEMORY_ACCESS_WRITE,
        mnu_abi::MEMORY_ACCESS_EXECUTE,
        mnu_abi::MEMORY_ACCESS_ALL,
        mnu_abi::MEMORY_MAP_SHARED,
    );
    probe.push_str(&source[definitions_start..definitions_end]);
    probe.push_str(&source[implementation_start..implementation_end]);
    // Also compile the production two-phase removal planner. Metadata remains
    // unchanged while PTE revocation can still fail; commit happens afterward.
    probe.push_str("mod memory_range {\n");
    probe.push_str(
        &include_str!("../../../core/src/task/memory_range.rs")
            .lines()
            .filter(|line| !line.starts_with("//!"))
            .collect::<Vec<_>>()
            .join("\n"),
    );
    probe.push_str("\n}\nmod removal { use super::*; pub struct Process { pub memory_regions: Vec<MemoryRegion> } impl Process {\n");
    let removal_start = source
        .find("    pub(crate) fn prepare_remove_memory_range(")
        .unwrap();
    let removal_end = source[removal_start..]
        .find("    pub fn has_kernel_authority(")
        .unwrap()
        + removal_start;
    probe.push_str(&source[removal_start..removal_end]);
    probe.push_str("\n} }\n");
    probe.push_str(r#"
fn main() {
    use mnu_abi::*;
    let object = Arc::new(mem::vm_object::VmObject);
    let mut region = MemoryRegion::file_backed(0x1000, 0x4000,
        MEMORY_ACCESS_READ | MEMORY_ACCESS_WRITE, MEMORY_MAP_SHARED,
        object.clone(), 8192, true, true, MEMORY_ACCESS_READ | MEMORY_ACCESS_WRITE);
    assert!(region.set_access(0x2000, 0x1000, MEMORY_ACCESS_READ));
    assert!(!region.allows_write_at(0x2000));
    assert!(region.allows_write_at(0x3000));
    for page in 0..4 { region.mark_dirty_page(page); }
    let mut slice = region.slice(0x2000, 0x4000).unwrap();
    assert_eq!(slice.start(), 0x2000);
    assert_eq!(slice.len(), 0x2000);
    assert_eq!(slice.backing().file_offset(), 12288);
    assert!(Arc::ptr_eq(slice.backing().file_object().unwrap(), &object));
    assert_eq!(slice.dirty_pages(), &[0, 1]);
    assert!(!slice.allows_write_at(0x2000));
    assert!(slice.allows_write_at(0x3000));
    assert!(!slice.set_access(0x2000, 0x2000, MEMORY_ACCESS_EXECUTE));
    assert!(!slice.allows_execute_at(0x3000));
    assert!(slice.set_access(0x2000, 0x1000, MEMORY_ACCESS_READ | MEMORY_ACCESS_WRITE));
    assert!(slice.allows_write_range(0x2000, 0x2000));
    assert!(region.slice(0, 0x2000).is_none());
    assert!(region.slice(0x2000, 0x2000).is_none());
    let mut restricted = MemoryRegion::file_backed(0x1000, 0x2000,
        MEMORY_ACCESS_READ, MEMORY_MAP_SHARED, object.clone(), 0,
        false, true, MEMORY_ACCESS_READ);
    assert!(!restricted.set_access(0x1000, 0x2000, MEMORY_ACCESS_WRITE));
    let mut restricted_slice = restricted.slice(0x2000, 0x3000).unwrap();
    assert!(!restricted_slice.set_access(0x2000, 0x1000, MEMORY_ACCESS_WRITE));
    let private = MemoryRegion::file_backed(0x1000, 0x2000,
        MEMORY_ACCESS_READ | MEMORY_ACCESS_WRITE, 0, object, 0, true, false, MEMORY_ACCESS_ALL);
    assert!(!private.is_shared());
    assert!(!private.backing().file_shared());
    let anonymous = MemoryRegion::anonymous(0x1000, 0x2000, MEMORY_ACCESS_WRITE, MEMORY_MAP_SHARED, true, true);
    assert!(anonymous.is_shared());
    let process = removal::Process { memory_regions: vec![region.clone()] };
    let (retained, removed) = process.prepare_remove_memory_range(0x2000, 0x2000).unwrap();
    assert_eq!(process.memory_regions.len(), 1);
    assert_eq!(process.memory_regions[0].len(), 0x4000);
    assert_eq!(retained.len(), 2);
    assert_eq!((retained[0].start(), retained[0].len()), (0x1000, 0x1000));
    assert_eq!((retained[1].start(), retained[1].len()), (0x4000, 0x1000));
    assert_eq!(removed.len(), 1);
    assert_eq!(removed[0].backing().file_offset(), 12288);
    assert!(!removed[0].allows_write_at(0x2000));
    assert!(process.prepare_remove_memory_range(u64::MAX, 4096).is_none());
}
"#);
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let temporary = Temporary(std::env::temp_dir().join(format!(
        "mochios-region-behavior-{}-{nonce}",
        std::process::id()
    )));
    fs::create_dir(&temporary.0).unwrap();
    let binary = temporary.0.join("probe");
    let mut compiler = Command::new("rustc")
        .args(["--edition=2021", "-Awarnings", "-"])
        .arg("-o")
        .arg(&binary)
        .stdin(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    compiler
        .stdin
        .take()
        .unwrap()
        .write_all(probe.as_bytes())
        .unwrap();
    let output = compiler.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let output = Command::new(binary).output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}
