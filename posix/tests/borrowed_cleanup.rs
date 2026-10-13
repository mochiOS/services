use std::io::Write;
use std::process::{Command, Stdio};

#[test]
fn native_cleanup_probe_matches_current_generic_abi() {
    let source = include_str!("native_borrowed_cleanup.c");
    for (name, number) in [
        ("MAP_PHYSICAL", mnu_abi::SyscallNumber::MapPhysicalRange),
        ("MEMORY_MAP", mnu_abi::SyscallNumber::MemoryMap),
        ("MEMORY_UNMAP", mnu_abi::SyscallNumber::MemoryUnmap),
        ("DMA_ALLOC", mnu_abi::SyscallNumber::DmaAlloc),
        ("DMA_FREE", mnu_abi::SyscallNumber::DmaFree),
        ("DEBUG_WRITE", mnu_abi::SyscallNumber::DebugWrite),
    ] {
        assert!(source.contains(&format!("{name} = {}", number as u64)));
    }
}

#[test]
fn actual_batch_cleanup_keeps_records_until_ack_and_preserves_failed_batches() {
    let source = include_str!("../../../core/src/task/process.rs");
    let start = source
        .find("pub fn release_process_borrowed_mappings(")
        .unwrap();
    let end = source[start..].find("/// 現在のプロセス数").unwrap() + start;
    let mut program = String::from(
        r#"
extern crate self as x86_64;
use std::sync::atomic::{AtomicBool,AtomicUsize,Ordering};
type ProcessId=u64;
static LOCKED:AtomicBool=AtomicBool::new(false);static MODE:AtomicUsize=AtomicUsize::new(0);
static ACKED:AtomicBool=AtomicBool::new(false);static RELEASED:AtomicUsize=AtomicUsize::new(0);
fn locked() {assert!(LOCKED.load(Ordering::Acquire));}
pub struct PhysAddr(u64);impl PhysAddr {pub fn new(v:u64)->Self {Self(v)}}
pub mod structures {pub mod paging {
    pub struct PhysFrame(pub u64);impl PhysFrame {pub fn containing_address(v:crate::PhysAddr)->Self {Self(v.0)}}
}}
mod syscall {pub const EINVAL:u64=(-22i64) as u64;pub const ENOMEM:u64=(-12i64) as u64;pub const ESRCH:u64=(-3i64) as u64;}
struct Mapping(u64,u64);
impl Mapping {fn virt_start(&self)->u64 {self.0} fn end(&self)->Option<u64> {if MODE.load(Ordering::Acquire)==2 && self.0==0x20000 {None} else {Some(self.1)}}fn page_count(&self)->usize {2}fn phys_start(&self)->u64 {0x30000}}
struct Process {mmio:Vec<Mapping>,dma:Vec<Mapping>,arena:u64}
impl Process {
    fn mmio_mappings(&self)->&[Mapping] {locked();&self.mmio}fn dma_buffers(&self)->&[Mapping] {locked();&self.dma}
    fn reset_dma_arena(&mut self) {locked();assert!(self.mmio.is_empty()&&self.dma.is_empty());self.arena=0;}
    fn page_table(&self)->Option<u64> {locked();(MODE.load(Ordering::Acquire)!=3).then_some(4096)}
    fn take_mmio_mappings(&mut self)->Vec<Mapping> {locked();assert!(ACKED.load(Ordering::Acquire));std::mem::take(&mut self.mmio)}
    fn take_dma_buffers(&mut self)->Vec<Mapping> {locked();assert!(ACKED.load(Ordering::Acquire));std::mem::take(&mut self.dma)}
}
thread_local! {static PROCESS:std::cell::RefCell<Process>=std::cell::RefCell::new(Process {mmio:Vec::new(),dma:Vec::new(),arena:0});}
fn with_process_mut<T>(_:u64,f:impl FnOnce(&mut Process)->T)->Option<T> {
    if MODE.load(Ordering::Acquire)==5 {return None;}
    assert!(!LOCKED.swap(true,Ordering::AcqRel));let result=PROCESS.with(|p|f(&mut p.borrow_mut()));LOCKED.store(false,Ordering::Release);Some(result)
}
mod mem {
    pub mod frame {pub fn deallocate_frame(frame:crate::structures::paging::PhysFrame)->bool {
        assert!(!crate::LOCKED.load(crate::Ordering::Acquire));assert!(crate::ACKED.load(crate::Ordering::Acquire));assert!([0x30000,0x31000].contains(&frame.0));crate::RELEASED.fetch_add(1,crate::Ordering::AcqRel);true
    }}
    pub mod mapping_revocation_native {
        pub struct Native<'a>(pub &'a crate::Process);impl<'a> Native<'a> {pub unsafe fn for_process(p:&'a crate::Process,owned:bool)->Self {crate::locked();assert!(!owned);Self(p)}}
    }
    pub mod mapping_revocation {
        pub enum Error {InvalidRange,Allocation,Backend(u64)}
        pub fn revoke(ranges:impl IntoIterator<Item=(u64,u64,u64)>,backend:&mut super::mapping_revocation_native::Native<'_>)->Result<(),Error> {
            crate::locked();assert_eq!(backend.0.mmio.len(),1);assert_eq!(backend.0.dma.len(),1);assert_eq!(ranges.into_iter().collect::<Vec<_>>(),[(4096,0x10000,0x11000),(4096,0x20000,0x22000)]);
            if crate::MODE.load(crate::Ordering::Acquire)==1 {return Err(Error::Backend((-5i64) as u64));}crate::ACKED.store(true,crate::Ordering::Release);Ok(())
        }
    }
}
"#,
    );
    program.push_str(&source[start..end]);
    program.push_str(r#"
fn main() {
    for (mode,expected) in [(0,Ok(())),(1,Err((-5i64) as u64)),(2,Err(syscall::EINVAL)),(3,Err(syscall::EINVAL)),(4,Ok(())),(5,Err(syscall::ESRCH))] {
        MODE.store(mode,Ordering::Release);ACKED.store(false,Ordering::Release);RELEASED.store(0,Ordering::Release);
        PROCESS.with(|p| {let mut p=p.borrow_mut();p.mmio=if mode==4 {vec![]} else {vec![Mapping(0x10000,0x11000)]};p.dma=if mode==4 {vec![]} else {vec![Mapping(0x20000,0x22000)]};p.arena=0x22000;});
        assert_eq!(release_process_borrowed_mappings(1),expected);
        assert_eq!(RELEASED.load(Ordering::Acquire),if mode==0 {2} else {0});
        PROCESS.with(|p| {let p=p.borrow();assert_eq!(p.mmio.len(),usize::from(mode!=0&&mode!=4));assert_eq!(p.dma.len(),usize::from(mode!=0&&mode!=4));assert_eq!(p.arena,if mode==0||mode==4 {0} else {0x22000});});
        assert!(!LOCKED.load(Ordering::Acquire));
    }
}
"#);
    let directory = std::env::temp_dir().join(format!(
        "mochios-borrowed-cleanup-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&directory).unwrap();
    let executable = directory.join("probe");
    let mut compiler = Command::new("rustc")
        .args(["--edition=2024", "-Awarnings", "-"])
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
    let result = Command::new(&executable).output().unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    std::fs::remove_dir_all(directory).unwrap();
}
