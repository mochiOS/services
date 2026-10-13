use std::io::Write;
use std::process::{Command, Stdio};

#[test]
fn native_dma_probe_matches_current_generic_abi() {
    let source = include_str!("native_dma_free.c");
    for (name, number) in [
        ("MEMORY_MAP", mnu_abi::SyscallNumber::MemoryMap),
        ("MEMORY_UNMAP", mnu_abi::SyscallNumber::MemoryUnmap),
        ("DMA_ALLOC", mnu_abi::SyscallNumber::DmaAlloc),
        ("DMA_FREE", mnu_abi::SyscallNumber::DmaFree),
        ("DEBUG_WRITE", mnu_abi::SyscallNumber::DebugWrite),
    ] {
        assert!(source.contains(&format!("{name} = {}", number as u64)));
    }
    assert_eq!(core::mem::size_of::<mnu_abi::DmaAllocation>(), 32);
}

#[test]
fn actual_dma_free_preserves_ownership_on_failure_and_releases_only_after_ack() {
    let source = include_str!("../../../core/src/syscall/dma.rs");
    let start = source.find("pub fn free(handle: u64) -> u64 {").unwrap();
    let mut program = String::from(
        r#"
use std::sync::atomic::{AtomicBool,AtomicUsize,Ordering};
const EACCES:u64=(-13i64) as u64;const EINVAL:u64=(-22i64) as u64;const ENOMEM:u64=(-12i64) as u64;const SUCCESS:u64=0;
static LOCKED:AtomicBool=AtomicBool::new(false);
static MODE:AtomicUsize=AtomicUsize::new(0);
static RECORD:AtomicBool=AtomicBool::new(true);
static ACKED:AtomicBool=AtomicBool::new(false);
static RELEASED:AtomicUsize=AtomicUsize::new(0);
fn locked() {assert!(LOCKED.load(Ordering::Acquire));}
fn caller_has_dma_capability()->bool {MODE.load(Ordering::Acquire)!=4}
fn current_process()->Option<(u64,u64)> {(MODE.load(Ordering::Acquire)!=5).then_some((1,4096))}
fn release_dma_frames(physical:u64,count:usize) {
    assert!(!LOCKED.load(Ordering::Acquire));assert!(ACKED.load(Ordering::Acquire));assert!(!RECORD.load(Ordering::Acquire));
    assert_eq!((physical,count),(0x20000,2));RELEASED.fetch_add(count,Ordering::AcqRel);
}
mod task {
    #[derive(Clone)] pub struct Buffer;
    impl Buffer {
        pub fn handle(&self)->u64 {7} pub fn end(&self)->Option<u64> {Some(0x12000)}
        pub fn virt_start(&self)->u64 {0x10000} pub fn phys_start(&self)->u64 {0x20000} pub fn page_count(&self)->usize {2}
    }
    pub struct Process {pub buffers:Vec<Buffer>}
    impl Process {
        pub fn page_table(&self)->Option<u64> {crate::locked();Some(if crate::MODE.load(crate::Ordering::Acquire)==2 {8192} else {4096})}
        pub fn dma_buffers(&self)->&[Buffer] {crate::locked();&self.buffers}
        pub fn remove_dma_buffer(&mut self,handle:u64)->Option<Buffer> {
            crate::locked();assert!(crate::ACKED.load(crate::Ordering::Acquire));assert_eq!(handle,7);
            crate::RECORD.store(false,crate::Ordering::Release);self.buffers.pop()
        }
    }
    pub fn with_process_mut<T>(_:u64,f:impl FnOnce(&mut Process)->T)->Option<T> {
        assert!(!crate::LOCKED.swap(true,crate::Ordering::AcqRel));
        let mut process=Process {buffers:if crate::MODE.load(crate::Ordering::Acquire)==1 {Vec::new()} else {vec![Buffer]}};
        let result=f(&mut process);crate::LOCKED.store(false,crate::Ordering::Release);Some(result)
    }
}
mod mem {
    pub mod mapping_revocation_native {
        pub struct Native<'a>(&'a crate::task::Process);
        impl<'a> Native<'a> {pub unsafe fn for_process(process:&'a crate::task::Process,owned:bool)->Self {crate::locked();assert!(!owned);Self(process)}}
    }
    pub mod mapping_revocation {
        pub enum Error {InvalidRange,Allocation,Backend(u64)}
        pub fn revoke(ranges:impl IntoIterator<Item=(u64,u64,u64)>,_: &mut super::mapping_revocation_native::Native<'_>)->Result<(),Error> {
            crate::locked();assert!(crate::RECORD.load(crate::Ordering::Acquire));assert_eq!(ranges.into_iter().collect::<Vec<_>>(),[(4096,0x10000,0x12000)]);
            if crate::MODE.load(crate::Ordering::Acquire)==3 {return Err(Error::Backend((-5i64) as u64));}
            crate::ACKED.store(true,crate::Ordering::Release);Ok(())
        }
    }
}
"#,
    );
    program.push_str(&source[start..]);
    program.push_str(r#"
fn main() {
    for (mode,expected) in [(0,0),(1,EINVAL),(2,EINVAL),(3,(-5i64) as u64),(4,EACCES),(5,ENOMEM)] {
        MODE.store(mode,Ordering::Release);RECORD.store(true,Ordering::Release);ACKED.store(false,Ordering::Release);RELEASED.store(0,Ordering::Release);
        assert_eq!(free(7),expected);assert_eq!(RECORD.load(Ordering::Acquire),mode!=0);assert_eq!(RELEASED.load(Ordering::Acquire),if mode==0 {2} else {0});assert!(!LOCKED.load(Ordering::Acquire));
    }
    MODE.store(0,Ordering::Release);assert_eq!(free(0),EINVAL);
}
"#);
    let directory = std::env::temp_dir().join(format!(
        "mochios-dma-free-{}-{}",
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
