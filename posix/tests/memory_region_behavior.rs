use std::fs;
use std::io::Write;
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};
#[allow(dead_code)]
#[path = "support/native_error_probe.rs"]
mod native_probe;

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
         mod mem {{ pub use crate::scan_budget; pub mod paging {{pub fn is_user_range_mapped_in_table(_:u64,_:u64,length:u64)->bool{{assert!(crate::VM_LOCKED.get());assert_eq!(length,1);crate::PTE_QUERIES.set(crate::PTE_QUERIES.get()+1);crate::RESIDENT.get()}}}} pub mod vm_object {{ #[derive(Debug)] pub struct VmObject; impl VmObject {{pub fn page_is_resident(&self,_:u64)->Result<bool,crate::mnu_abi::status::Error>{{Ok(false)}}}} }} }}\n\
         mod mnu_abi {{ pub const MEMORY_ACCESS_READ:u64={};\n\
         pub const MEMORY_ACCESS_WRITE:u64={}; pub const MEMORY_ACCESS_EXECUTE:u64={};\n\
         pub const MEMORY_ACCESS_ALL:u64={}; pub const MEMORY_MAP_SHARED:u64={}; pub mod status {{\n{status}\n}} }}\n",
        mnu_abi::MEMORY_ACCESS_READ,
        mnu_abi::MEMORY_ACCESS_WRITE,
        mnu_abi::MEMORY_ACCESS_EXECUTE,
        mnu_abi::MEMORY_ACCESS_ALL,
        mnu_abi::MEMORY_MAP_SHARED,
        status = include_str!("../../../core/crates/abi/src/status.rs"),
    );
    probe.push_str(r#"
use std::{cell::Cell,sync::atomic::{AtomicUsize,Ordering}};
thread_local!{static FAIL_AFTER:Cell<Option<usize>>=const{Cell::new(None)};}
static LIVE:AtomicUsize=AtomicUsize::new(0);
struct Allocator;
unsafe impl std::alloc::GlobalAlloc for Allocator {
    unsafe fn alloc(&self,layout:std::alloc::Layout)->*mut u8 {
        if FAIL_AFTER.with(|s|match s.get(){Some(0)=>{s.set(None);true},Some(n)=>{s.set(Some(n-1));false},None=>false}){return std::ptr::null_mut();}
        let p=unsafe{std::alloc::System.alloc(layout)};if !p.is_null(){LIVE.fetch_add(1,Ordering::Relaxed);}p
    }
    unsafe fn dealloc(&self,p:*mut u8,layout:std::alloc::Layout){LIVE.fetch_sub(1,Ordering::Relaxed);unsafe{std::alloc::System.dealloc(p,layout)}}
}
#[global_allocator]static ALLOCATOR:Allocator=Allocator;
"#);
    probe.push_str(&source[definitions_start..definitions_end]);
    probe.push_str(&source[implementation_start..implementation_end]);
    let budget = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../core/src/mem/scan_budget.rs")
        .canonicalize()
        .unwrap();
    probe.push_str(&format!("#[path={budget:?}]pub mod scan_budget;\n"));
    probe.push_str(r#"
thread_local!{
 static VM_LOCKED:Cell<bool>=const{Cell::new(false)};
 static RESIDENT:Cell<bool>=const{Cell::new(false)};
 static PTE_QUERIES:Cell<usize>=const{Cell::new(0)};
}
mod task{
 pub struct Process{pub regions:Vec<crate::MemoryRegion>}
 impl Process{pub fn page_table(&self)->Option<u64>{Some(7)}pub fn memory_regions(&self)->&[crate::MemoryRegion]{&self.regions}}
 thread_local!{pub static PROCESS:std::cell::RefCell<Process>=const{std::cell::RefCell::new(Process{regions:Vec::new()})};}
 pub struct Thread;impl Thread{pub fn process_id(&self)->u64{1}}
 pub fn current_thread_id()->Option<u64>{Some(1)}
 pub fn with_thread<T>(_:u64,body:impl FnOnce(&Thread)->T)->Option<T>{Some(body(&Thread))}
 pub fn with_process<T>(_:u64,body:impl FnOnce(&Process)->T)->Option<T>{
  assert!(!crate::VM_LOCKED.replace(true));let result=PROCESS.with_borrow(body);assert!(crate::VM_LOCKED.replace(false));Some(result)
 }
}
"#);
    for declaration in ["pub fn validate_user_ptr(", "fn is_canonical_user_range("] {
        probe.push_str(&native_probe::definition(
            include_str!("../../../core/src/syscall/mod.rs"),
            declaration,
        ));
        probe.push('\n');
    }
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
fn apply_access(region:&mut MemoryRegion,start:u64,length:u64,access:u64)->bool {
    match region.prepare_access(start,length,access) {
        Ok(prepared)=>{region.publish_access(prepared);true},Err(_)=>false
    }
}
fn main() {
    use mnu_abi::*;
    let object = Arc::new(mem::vm_object::VmObject);
    let mut region = MemoryRegion::file_backed(0x1000, 0x4000, MEMORY_ACCESS_READ | MEMORY_ACCESS_WRITE, MEMORY_MAP_SHARED, object.clone(), 8192, MEMORY_ACCESS_READ | MEMORY_ACCESS_WRITE);
    assert!(apply_access(&mut region,0x2000, 0x1000, MEMORY_ACCESS_READ));
    assert!(!region.allows_write_at(0x2000));
    assert!(region.allows_write_at(0x3000));
    for page in 0..4 { region.mark_dirty_page(page); }
    for allocation in 0..2 {
        let pins=Arc::strong_count(&object);let live=LIVE.load(Ordering::Relaxed);FAIL_AFTER.set(Some(allocation));
        assert_eq!(region.try_clone().err(),Some(mnu_abi::status::Error::ResourceUnavailable));
        assert_eq!(FAIL_AFTER.get(),None);assert_eq!(Arc::strong_count(&object),pins);assert_eq!(LIVE.load(Ordering::Relaxed),live);
    }
    let mut copied=region.try_clone().unwrap();assert_eq!(copied.backing().file_offset(),8192);assert!(Arc::ptr_eq(copied.backing().file_object().unwrap(),&object));
    assert_eq!(copied.dirty_pages(),region.dirty_pages());assert_eq!(copied.max_access,region.max_access);assert_eq!(copied.options,region.options);assert!(!copied.allows_write_at(0x2000));
    copied.clear_dirty_pages(0,4);assert_eq!(region.dirty_pages(),&[0,1,2,3]);drop(copied);
    let mut slice = region.slice(0x2000, 0x4000).unwrap();
    assert_eq!(slice.start(), 0x2000);
    assert_eq!(slice.len(), 0x2000);
    assert_eq!(slice.backing().file_offset(), 12288);
    assert!(Arc::ptr_eq(slice.backing().file_object().unwrap(), &object));
    assert_eq!(slice.dirty_pages(), &[0, 1]);
    assert!(!slice.allows_write_at(0x2000));
    assert!(slice.allows_write_at(0x3000));
    assert!(!apply_access(&mut slice,0x2000, 0x2000, MEMORY_ACCESS_EXECUTE));
    assert!(!slice.allows_execute_at(0x3000));
    assert!(apply_access(&mut slice,0x2000, 0x1000, MEMORY_ACCESS_READ | MEMORY_ACCESS_WRITE));
    assert!(slice.allows_write_range(0x2000, 0x2000));
    assert_eq!(region.slice(0, 0x2000).unwrap_err(), MemoryRangeError::InvalidRange);
    assert_eq!(region.slice(0x2000, 0x2000).unwrap_err(), MemoryRangeError::InvalidRange);
    let mut restricted = MemoryRegion::file_backed(0x1000, 0x2000, MEMORY_ACCESS_READ, MEMORY_MAP_SHARED, object.clone(), 0, MEMORY_ACCESS_READ);
    assert!(!apply_access(&mut restricted,0x1000, 0x2000, MEMORY_ACCESS_WRITE));
    let mut restricted_slice = restricted.slice(0x2000, 0x3000).unwrap();
    assert!(!apply_access(&mut restricted_slice,0x2000, 0x1000, MEMORY_ACCESS_WRITE));
    let private = MemoryRegion::file_backed(0x1000, 0x2000, MEMORY_ACCESS_READ | MEMORY_ACCESS_WRITE, 0, object, 0, MEMORY_ACCESS_ALL);
    assert!(!private.is_shared());
    assert!(!private.is_shared());
    let mut anonymous = MemoryRegion::anonymous(0x1000, 0x2000, MEMORY_ACCESS_WRITE, MEMORY_MAP_SHARED);
    assert!(anonymous.is_shared());
    if let MemoryBacking::Anonymous{data,..}=&mut anonymous.backing {*data=vec![7;8192];}
    assert!(apply_access(&mut anonymous,0x1000,4096,MEMORY_ACCESS_READ));
    for page in [0,1,17] {anonymous.mark_dirty_page(page);}
    for allocation in 0..3 {
        let live=LIVE.load(Ordering::Relaxed);FAIL_AFTER.set(Some(allocation));
        assert_eq!(anonymous.try_clone().err(),Some(mnu_abi::status::Error::ResourceUnavailable));assert_eq!(FAIL_AFTER.get(),None);assert_eq!(LIVE.load(Ordering::Relaxed),live);
    }
    let mut copied=anonymous.try_clone().unwrap();assert_eq!(copied.dirty_pages(),&[0,1,17]);assert_eq!(copied.access_ranges.len(),anonymous.access_ranges.len());
    for (a,b) in copied.access_ranges.iter().zip(&anonymous.access_ranges){assert_eq!((a.start,a.end,a.access),(b.start,b.end,b.access));}
    if let MemoryBacking::Anonymous{data}=&mut copied.backing {assert_eq!(data,&vec![7;8192]);data[0]=9;}
    if let MemoryBacking::Anonymous{data,..}=&anonymous.backing {assert_eq!(data[0],7);}
    // Exercise the production dirty-page set with nonsequential/repeated faults.
    let mut dirty = MemoryRegion::anonymous(0x1000, 16 * 4096, MEMORY_ACCESS_READ | MEMORY_ACCESS_WRITE, 0);
    for page in [9, 2, 15, 0, 9, 7, 2, 15, 1] { dirty.mark_dirty_page(page); }
    assert_eq!(dirty.dirty_pages(), &[0, 1, 2, 7, 9, 15]);
    let mut cloned = dirty.try_clone().unwrap();
    cloned.mark_dirty_page(3);
    assert_eq!(cloned.dirty_pages(), &[0, 1, 2, 3, 7, 9, 15]);
    assert_eq!(dirty.dirty_pages(), &[0, 1, 2, 7, 9, 15]);
    let mut sliced = dirty.slice(0x3000, 0xb000).unwrap();
    assert_eq!(sliced.dirty_pages(), &[0, 5, 7]);
    sliced.mark_dirty_page(2);
    sliced.clear_dirty_pages(2, 4);
    assert_eq!(sliced.take_dirty_pages(), &[0, 7]);
    assert!(sliced.dirty_pages().is_empty());
    sliced.mark_dirty_page(1);
    assert_eq!(sliced.dirty_pages(), &[1]);
    // Large monotonic first-write workloads retain every page exactly once.
    let mut sequential = MemoryRegion::anonymous(0x1000, 100_000 * 4096, MEMORY_ACCESS_READ | MEMORY_ACCESS_WRITE, 0);
    for page in 0..100_000 { sequential.mark_dirty_page(page); }
    for page in (0..100_000).rev() { sequential.mark_dirty_page(page); }
    assert_eq!(sequential.dirty_pages().len(), 100_000);
    assert!(sequential.dirty_pages().iter().copied().eq(0..100_000));
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
    assert_eq!(process.prepare_remove_memory_range(u64::MAX, 4096).unwrap_err(), MemoryRangeError::InvalidRange);
    assert_eq!(process.prepare_remove_memory_range(0x1000, 0).unwrap_err(), MemoryRangeError::InvalidRange);
    let invalid_offset = MemoryRegion::file_backed(0x1000, 0x2000, MEMORY_ACCESS_READ, 0, Arc::new(mem::vm_object::VmObject), u64::MAX, MEMORY_ACCESS_READ);
    assert_eq!(invalid_offset.slice(0x2000,0x3000).unwrap_err(),MemoryRangeError::InvalidRange);
    // Execute the real validator and metadata together: a lazy TiB takes one
    // interval step, and a hidden PROT_NONE page is never skipped or rescued
    // by an old resident mapping.
    task::PROCESS.with_borrow_mut(|p|p.regions=vec![MemoryRegion::anonymous(0x10000,1<<40,3,0)]);
    assert!(validate_user_ptr(0x10000,1<<40));assert_eq!(PTE_QUERIES.get(),0);
    task::PROCESS.with_borrow_mut(|p|assert!(apply_access(&mut p.regions[0],0x30000,4096,0)));
    RESIDENT.set(true);
    assert!(!validate_user_ptr(0x10000,1<<40));assert_eq!(PTE_QUERIES.get(),0);
    assert!(validate_user_ptr(0x10000,0x20000));
    assert!(validate_user_ptr(0x31000,(1<<40)-0x21000));
    task::PROCESS.with_borrow_mut(|p|p.regions.clear());
    assert!(validate_user_ptr(0x10000,8192));assert_eq!(PTE_QUERIES.get(),2);
    RESIDENT.set(false);assert!(!validate_user_ptr(0x10000,4096));
    RESIDENT.set(true);PTE_QUERIES.set(0);
    assert!(!validate_user_ptr(0x10000,1<<40));assert!(PTE_QUERIES.get()<=4096);
    task::PROCESS.with_borrow_mut(|p|for index in 0..20_000{p.regions.push(MemoryRegion::anonymous(0x10000+index*8192,4096,3,0));});
    PTE_QUERIES.set(0);
    assert!(!validate_user_ptr(0x10000+19_999*8192,4096));assert_eq!(PTE_QUERIES.get(),0);
    for (pointer,length) in [(0,1),(u64::MAX,2),((1<<47)-1,2)]{assert!(!validate_user_ptr(pointer,length));}
    assert!(!VM_LOCKED.get());
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
        .args(["--edition=2021", "-Awarnings", "-Cstrip=symbols", "-"])
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
