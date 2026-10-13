use std::io::Write;
use std::process::{Command, Stdio};

#[test]
fn native_mmio_probe_matches_current_generic_abi() {
    let source = include_str!("native_mmio_mapping.c");
    for (name, number) in [
        ("MAP_PHYSICAL", mnu_abi::SyscallNumber::MapPhysicalRange),
        ("MEMORY_MAP", mnu_abi::SyscallNumber::MemoryMap),
        ("MEMORY_UNMAP", mnu_abi::SyscallNumber::MemoryUnmap),
        ("DEBUG_WRITE", mnu_abi::SyscallNumber::DebugWrite),
    ] {
        assert!(source.contains(&format!("{name} = {}", number as u64)));
    }
}

#[test]
fn native_framebuffer_probe_matches_current_abi() {
    let source = include_str!("native_framebuffer_mapping.c");
    for (name, number) in [
        (
            "FRAMEBUFFER_INFO",
            mnu_abi::SyscallNumber::GetFramebufferInfo,
        ),
        ("MAP_FRAMEBUFFER", mnu_abi::SyscallNumber::MapFramebuffer),
        ("MEMORY_UNMAP", mnu_abi::SyscallNumber::MemoryUnmap),
        ("DEBUG_WRITE", mnu_abi::SyscallNumber::DebugWrite),
    ] {
        assert!(source.contains(&format!("{name} = {}", number as u64)));
    }
}

#[test]
fn production_mmio_dispatcher_keeps_root_and_metadata_locked_through_rollback() {
    let source = include_str!("../../../core/src/syscall/mod.rs");
    let start = source.find("pub fn map_physical_range(").unwrap();
    let end = source[start..].find("#[repr(C)]").unwrap() + start;
    let mut program = String::from(
        r#"
use std::sync::atomic::{AtomicBool,AtomicUsize,Ordering};
static LOCKED:AtomicBool=AtomicBool::new(false);
static MODE:AtomicUsize=AtomicUsize::new(0);
static RECORD:AtomicBool=AtomicBool::new(false);
static MAPPED:AtomicBool=AtomicBool::new(false);
static ACKED:AtomicBool=AtomicBool::new(false);
fn locked() {assert!(LOCKED.load(Ordering::Acquire));}
struct KernelAuthority; enum KernelCapability {PhysMap} enum KernelObjectRef {MmioRegion {base:u64,size:u64}}
impl KernelAuthority {fn new(_:KernelCapability,_:KernelObjectRef)->Self {Self}}
fn is_canonical_user_range(_:u64,_:u64)->bool {true}
mod capability {pub enum Capability {DeviceGpu,DeviceNet,SerialAccess}}
mod audit {pub enum AuditEventKind {Policy} pub fn log(_:AuditEventKind,_:&str) {}}
mod syscall {
    pub mod types {pub const EACCES:u64=(-13i64) as u64;pub const EINVAL:u64=(-22i64) as u64;pub const ENOMEM:u64=(-12i64) as u64;pub const EPERM:u64=(-1i64) as u64;pub const SUCCESS:u64=0;}
    pub mod security {
        pub fn current_process_id()->Option<u64> {Some(1)}
        pub fn caller_has_any_capability(_: &[crate::capability::Capability])->bool {false}
    }
}
mod task {
    pub type ProcessId=u64;
    #[derive(Clone)] pub struct MmioMapping;
    impl MmioMapping {pub fn new(_:u64,_:u64,_:u64,write:bool)->Self {assert!(write);Self}}
    pub struct Limits {pub max_mmio_ranges:usize}
    pub struct Process;
    impl Process {
        pub fn page_table(&self)->Option<u64> {crate::locked();if crate::MODE.load(crate::Ordering::Acquire)==6 {None} else {Some(4096)}}
        pub fn mmio_mapping_count(&self)->usize {crate::locked();usize::from(crate::MODE.load(crate::Ordering::Acquire)==3)}
        pub fn resource_limits(&self)->Limits {Limits {max_mmio_ranges:1}}
        pub fn add_mmio_mapping(&mut self,_:MmioMapping)->bool {crate::locked();if crate::MODE.load(crate::Ordering::Acquire)==2 {return false;}crate::RECORD.store(true,crate::Ordering::Release);true}
        pub fn remove_mmio_mapping(&mut self,_:u64,_:u64) {crate::locked();assert!(crate::ACKED.load(crate::Ordering::Acquire));assert!(!crate::MAPPED.load(crate::Ordering::Acquire));crate::RECORD.store(false,crate::Ordering::Release);}
    }
    pub fn process_has_kernel_authority(_:u64,_:&crate::KernelAuthority)->bool {crate::MODE.load(crate::Ordering::Acquire)!=7}
    pub fn with_process_mut<T>(_:u64,f:impl FnOnce(&mut Process)->T)->Option<T> {
        assert!(!crate::LOCKED.swap(true,crate::Ordering::AcqRel));let value=f(&mut Process);crate::LOCKED.store(false,crate::Ordering::Release);Some(value)
    }
}
mod mem {
    pub mod frame {pub fn is_allowed_mmio_range(_:u64,_:u64)->bool {crate::MODE.load(crate::Ordering::Acquire)!=8}}
    pub mod paging {
        pub enum MappingCache {Uncached}
        pub fn is_user_range_occupied_in_table(_:u64,_:u64,_:u64)->bool {crate::locked();crate::MODE.load(crate::Ordering::Acquire)==1}
        pub fn map_physical_range_to_user(_:u64,_:u64,_:u64,_:u64,_:MappingCache)->Result<(),()> {
            crate::locked();assert!(crate::RECORD.load(crate::Ordering::Acquire));crate::MAPPED.store(true,crate::Ordering::Release);
            if matches!(crate::MODE.load(crate::Ordering::Acquire),4|5) {Err(())} else {Ok(())}
        }
    }
    pub mod mapping_revocation_native {
        pub struct Native<'a>(&'a crate::task::Process);
        impl<'a> Native<'a> {pub unsafe fn for_process(p:&'a crate::task::Process,owned:bool)->Self {crate::locked();assert!(!owned);Self(p)}}
    }
    pub mod mapping_revocation {
        pub enum Error {InvalidRange,Allocation,Backend(u64)}
        pub fn revoke(ranges:impl IntoIterator<Item=(u64,u64,u64)>,_: &mut super::mapping_revocation_native::Native<'_>)->Result<(),Error> {
            crate::locked();assert_eq!(ranges.into_iter().collect::<Vec<_>>(),[(4096,0x10000,0x12000)]);
            assert!(crate::RECORD.load(crate::Ordering::Acquire));
            if crate::MODE.load(crate::Ordering::Acquire)==5 {return Err(Error::Backend((-5i64) as u64));}
            crate::ACKED.store(true,crate::Ordering::Release);crate::MAPPED.store(false,crate::Ordering::Release);Ok(())
        }
    }
}
"#,
    );
    program.push_str(&source[start..end]);
    program.push_str(r#"
fn main() {
    use syscall::types::*;
    for (mode,expected,record,mapped) in [(0,0,true,true),(1,EINVAL,false,false),(2,EINVAL,false,false),(3,ENOMEM,false,false),(4,ENOMEM,false,false),(5,(-5i64) as u64,true,true),(6,ENOMEM,false,false),(7,EACCES,false,false),(8,EPERM,false,false)] {
        MODE.store(mode,Ordering::Release);RECORD.store(false,Ordering::Release);MAPPED.store(false,Ordering::Release);ACKED.store(false,Ordering::Release);
        assert_eq!(map_physical_range(0x10000,0xf0000000,8192),expected);
        assert_eq!(RECORD.load(Ordering::Acquire),record);assert_eq!(MAPPED.load(Ordering::Acquire),mapped);assert!(!LOCKED.load(Ordering::Acquire));
    }
    assert_eq!(map_physical_range(1,0xf0000000,8192),EINVAL);
}
"#);
    let directory = std::env::temp_dir().join(format!(
        "mochios-mmio-lock-{}-{}",
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
