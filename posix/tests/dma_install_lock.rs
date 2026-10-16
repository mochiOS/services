use std::io::Write;
use std::process::{Command, Stdio};

#[test]
fn actual_dma_install_serializes_admission_mapping_and_retained_rollback_failure() {
    let source = include_str!("../../../core/src/syscall/dma.rs");
    let start = source.find("fn allocate_dma_virtual_range(").unwrap();
    let end = source[start..].find("pub fn alloc(").unwrap() + start;
    let mut program = String::from(
        r#"
use std::sync::atomic::{AtomicBool,AtomicUsize,Ordering};
use task::{DmaBuffer,ProcessId};
const EINVAL:u64=(-22i64) as u64;const ENOMEM:u64=(-12i64) as u64;
static LOCKED:AtomicBool=AtomicBool::new(false);static MODE:AtomicUsize=AtomicUsize::new(0);
static MAPS:AtomicUsize=AtomicUsize::new(0);static ACKED:AtomicBool=AtomicBool::new(false);
fn locked() {assert!(LOCKED.load(Ordering::Acquire));}
fn page_align_up(v:u64)->Option<u64> {v.checked_add(4095).map(|v|v&!4095)}
fn randomized_dma_base(_:ProcessId)->u64 {0x10000}
mod syscall {pub fn is_canonical_user_range(start:u64,size:u64)->bool {start.checked_add(size).is_some_and(|end|end<=0x800000000000)}}
mod task {
    pub type ProcessId=u64;
    pub struct DmaBuffer;
    impl DmaBuffer {pub fn new(handle:u64,virt:u64,size:u64,phys:u64,count:usize)->Self {crate::locked();assert_eq!((handle,virt,size,phys,count),(7,0x10000,8192,0x20000,2));Self}}
    pub struct Process {pub end:u64,pub record:bool}
    impl Process {
        pub fn page_table(&self)->Option<u64> {crate::locked();Some(if crate::MODE.load(crate::Ordering::Acquire)==7 {8192} else {4096})}
        pub fn dma_end(&self)->u64 {crate::locked();self.end}
        pub fn set_dma_end(&mut self,end:u64) {crate::locked();self.end=end}
        pub fn set_dma_start(&mut self,start:u64) {crate::locked();assert_eq!(start,0x10000)}
        pub fn find_mmio_mapping_by_addr(&self,_:u64,_:u64)->Option<()> {crate::locked();(crate::MODE.load(crate::Ordering::Acquire)==1).then_some(())}
        pub fn add_dma_buffer(&mut self,_:DmaBuffer)->bool {crate::locked();if crate::MODE.load(crate::Ordering::Acquire)==3 {return false;}self.record=true;true}
        pub fn remove_dma_buffer(&mut self,handle:u64) {crate::locked();assert!(crate::ACKED.load(crate::Ordering::Acquire));assert_eq!(handle,7);self.record=false;}
    }
}
mod mem {
    pub mod paging {
        pub fn is_user_range_occupied_in_table(_:u64,_:u64,_:u64)->bool {crate::locked();crate::MODE.load(crate::Ordering::Acquire)==2}
        pub fn map_page_in_table(table:u64,virt:u64,phys:u64,user:bool,write:bool)->Result<(),()> {
            crate::locked();let index=crate::MAPS.fetch_add(1,crate::Ordering::AcqRel);assert_eq!(table,4096);assert_eq!(virt,0x10000+index as u64*4096);assert_eq!(phys,0x20000+index as u64*4096);assert!(user&&write);
            let mode=crate::MODE.load(crate::Ordering::Acquire);if mode==4 || ((mode==5||mode==6)&&index==1) {Err(())} else {Ok(())}
        }
    }
    pub mod mapping_revocation_native {
        pub struct Native<'a>(pub &'a crate::task::Process);
        impl<'a> Native<'a> {pub unsafe fn for_process(process:&'a crate::task::Process,owned:bool)->Self {crate::locked();assert!(!owned);Self(process)}}
    }
    pub mod mapping_revocation {
        pub enum Error {InvalidRange,Allocation,Backend(crate::native_status::Error)}
        pub fn revoke(ranges:impl IntoIterator<Item=(u64,u64,u64)>,backend:&mut super::mapping_revocation_native::Native<'_>)->Result<(),Error> {
            crate::locked();assert!(backend.0.record);assert_eq!(ranges.into_iter().collect::<Vec<_>>(),[(4096,0x10000,0x12000)]);
            if crate::MODE.load(crate::Ordering::Acquire)==6 {return Err(Error::Backend(crate::native_status::Error::BackingFailure));}crate::ACKED.store(true,crate::Ordering::Release);Ok(())
        }
    }
}
"#,
    );
    program.push_str(&source[start..end]);
    program.push_str(r#"
fn main() {
    for mode in 0..9 {
        MODE.store(mode,Ordering::Release);MAPS.store(0,Ordering::Release);ACKED.store(false,Ordering::Release);LOCKED.store(true,Ordering::Release);
        let initial=if mode==8 {u64::MAX-4095} else {0x10000};
        let mut process=task::Process {end:initial,record:false};
        let result=install_dma_buffer(&mut process,1,4096,7,0x20000,8192,2);
        let actual=match result {Ok(start)=>(0,start),Err(InstallError::Unpublished(e))=>(1,e),Err(InstallError::Retained(e))=>(2,e)};
        assert_eq!(actual,match mode {0=>(0,0x10000),4|5=>(1,ENOMEM),6=>(2,crate::native_status::Error::BackingFailure.into_raw()),_=>(1,EINVAL)});
        assert_eq!(process.record,mode==0||mode==6);
        assert_eq!(process.end,if mode==0||mode==6 {0x12000} else {initial});
        assert_eq!(MAPS.load(Ordering::Acquire),match mode {0|5|6=>2,4=>1,_=>0});LOCKED.store(false,Ordering::Release);
    }
}
"#);
    program.push_str("\nmod native_status {\n");
    program.push_str(include_str!("../../../core/crates/abi/src/status.rs"));
    program.push_str("\n}\n");
    let directory = std::env::temp_dir().join(format!(
        "mochios-dma-install-{}-{}",
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
