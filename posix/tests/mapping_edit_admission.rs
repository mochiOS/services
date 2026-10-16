//! Execute the actual unmap/protection entrypoints against a VM backend which
//! records edits, allocations/planning and metadata publication boundaries.
use std::io::Write;
use std::process::{Command, Stdio};

#[test]
fn reserved_later_mapping_rejects_the_entire_edit_before_any_side_effect() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap();
    let process = include_str!("../../../core/src/syscall/process.rs");
    let start = process.find("pub fn memory_unmap(").unwrap();
    let end = start + process[start..].find("/// memory_sync").unwrap();
    let unmap = &process[start..end];
    let protection = include_str!("../../../core/src/syscall/memory.rs");
    let protection = protection
        .lines()
        .filter(|line| !line.starts_with("//!"))
        .collect::<Vec<_>>()
        .join("\n");
    let mut program = String::from(
        r#"
use std::{cell::{Cell,RefCell},sync::Arc};
const EINVAL:u64=(-22i64) as u64; const EAGAIN:u64=(-11i64) as u64;
const EIO:u64=(-5i64) as u64;
const EFAULT:u64=(-14i64) as u64; const ENOMEM:u64=(-12i64) as u64;
const ENOSYS:u64=(-38i64) as u64; const EPERM:u64=(-1i64) as u64;
const ESRCH:u64=(-3i64) as u64; const EACCES:u64=(-13i64) as u64; const SUCCESS:u64=0;
#[derive(Debug)] pub enum Kernel {Memory(result::Memory),InvalidParam}
mod result {
    #[derive(Debug)] pub enum Memory {Busy,NotMapped,OutOfMemory,PermissionDenied,InvalidAddress,AlignmentError}
    pub type Result<T> = core::result::Result<T,crate::Kernel>;
}
mod mnu_abi {pub const MEMORY_ACCESS_WRITE:u64=2;pub const MEMORY_ACCESS_EXECUTE:u64=4;pub const MEMORY_ACCESS_ALL:u64=7;}
thread_local! {
    static LOCKED:Cell<bool>=const {Cell::new(false)};
    static EDITS:Cell<usize>=const {Cell::new(0)};
    static SYNCS:Cell<usize>=const {Cell::new(0)};
    static PLANS:Cell<usize>=const {Cell::new(0)};
    static PLAN_FAILURE:Cell<Option<task::process::MemoryRangeError>>=const {Cell::new(None)};
    static METADATA:Cell<usize>=const {Cell::new(0)};
    static PROCESS:RefCell<task::Process>=RefCell::new(task::Process{regions:Vec::new()});
}
fn locked() {assert!(LOCKED.with(Cell::get));}
fn page_align_up(address:u64)->Option<u64> {address.checked_add(4095).map(|address|address&!4095)}
fn is_user_range(start:u64,length:u64)->bool {start>0&&start.checked_add(length).is_some_and(|end|end<=0x800000000000)}
fn current_thread_id()->Option<u64> {Some(1)}
mod task {
    use super::*;
    pub mod process {
        #[derive(Clone,Copy)] pub enum MemoryRangeError {InvalidRange,Allocation}
    }
    pub mod ids {pub type ProcessId=u64;}
    #[path="@RANGE@"] pub mod memory_range;
    pub struct Object {pub busy:bool,pub unavailable:bool}
    impl Object {
        pub fn memory_generation(&self)->Option<u64>{Some(1)}
        pub fn with_memory_generation<T>(&self, generation:Option<u64>, install:impl FnOnce()->Result<T,u64>)->Result<T,u64>{
            locked();assert_eq!(generation,Some(1));if self.unavailable {Err(EIO)} else if self.busy {Err(EAGAIN)} else {install()}
        }
        pub fn check_mapping_removal(&self)->Result<(),u64>{locked();if self.busy {Err(EAGAIN)} else {Ok(())}}
        pub fn flush_unmapped_range(&self,_:u64,_:u64)->Result<(),u64>{Ok(())}
    }
    #[derive(Clone)] pub struct MemoryRegion {pub start:u64,pub object:Option<Arc<Object>>,pub access:u64}
    impl MemoryRegion {
        pub fn start(&self)->u64{self.start} pub fn len(&self)->u64{4096} pub fn end(&self)->Option<u64>{Some(self.start+4096)}
        pub fn backing(&self)->&Self{self} pub fn file_object(&self)->Option<&Arc<Object>>{self.object.as_ref()}
        pub fn file_offset(&self)->u64{0} pub fn is_shared(&self)->bool{true} pub fn dirty_pages(&self)->&[u64]{&[]}
        pub fn permits_access(&self,_:u64)->bool{true}
        pub fn set_access(&mut self,_:u64,_:u64,access:u64)->bool{locked();METADATA.with(|value|value.set(value.get()+1));self.access=access;true}
    }
    pub struct Mapping;
    impl Mapping {pub fn virt_start(&self)->u64{0} pub fn len(&self)->u64{0}}
    pub struct Process {pub regions:Vec<MemoryRegion>}
    impl Process {
        pub fn page_table(&self)->Option<u64>{Some(4096)}
        pub fn memory_regions(&self)->&[MemoryRegion]{&self.regions}
        pub fn memory_regions_mut(&mut self)->&mut [MemoryRegion]{&mut self.regions}
        pub fn find_memory_region(&self,address:u64)->Option<&MemoryRegion>{self.regions.iter().find(|region|address>=region.start&&address<region.start+4096)}
        pub fn find_dma_buffer_by_addr(&self,_:u64,_:u64)->Option<&Mapping>{None}
        pub fn find_mmio_mapping_by_addr(&self,_:u64,_:u64)->Option<&Mapping>{None}
        pub fn remove_mmio_mapping(&mut self,_:u64,_:u64){}
        pub fn prepare_remove_memory_range(&self,start:u64,length:u64)->Result<(Vec<MemoryRegion>,Vec<MemoryRegion>),process::MemoryRangeError>{
            locked();PLANS.with(|value|value.set(value.get()+1));
            if let Some(error)=PLAN_FAILURE.with(Cell::get) {return Err(error);}
            let (removed,retained)=self.regions.iter().cloned().partition(|region|region.start>=start&&region.start<start+length);
            Ok((retained,removed))
        }
        pub fn set_memory_regions(&mut self,regions:Vec<MemoryRegion>){locked();METADATA.with(|value|value.set(value.get()+1));self.regions=regions;}
    }
    pub struct Thread;impl Thread {pub fn process_id(&self)->u64{7}}
    pub fn current_thread_id()->Option<u64>{Some(1)}
    pub fn with_thread<T>(id:u64,body:impl FnOnce(&Thread)->T)->Option<T>{assert_eq!(id,1);Some(body(&Thread))}
    pub fn with_process_mut<T>(id:u64,body:impl FnOnce(&mut Process)->T)->Option<T>{
        assert_eq!(id,7);LOCKED.with(|slot|assert!(!slot.replace(true)));
        let result=PROCESS.with(|process|body(&mut process.borrow_mut()));
        LOCKED.with(|slot|slot.set(false));Some(result)
    }
}
mod mem {
    #[path="@ADMISSION@"] pub mod mapping_admission;
    pub mod paging {
        pub fn has_user_page_entry_in_table(_:u64,_:u64)->bool{crate::locked();true}
        pub unsafe fn next_user_page_entry(_:u64,start:u64,end:u64)->Result<Option<u64>,crate::Kernel>{crate::locked();Ok((start<end).then_some(start))}
        pub fn protect_user_page_if_mapped(_:u64,_:u64,_:bool,_:bool,_:bool)->Result<bool,crate::Kernel>{
            crate::locked();crate::EDITS.with(|value|value.set(value.get()+1));Ok(true)
        }
    }
    pub mod tlb_shootdown {pub fn invalidate_all()->Result<(),()>{crate::locked();crate::SYNCS.with(|value|value.set(value.get()+1));Ok(())}}
    pub mod mapping_revocation_native {
        pub struct Native;impl Native {pub unsafe fn for_process(_: &crate::task::Process,owns:bool)->Self{crate::locked();assert!(owns);Self}}
    }
    pub mod mapping_revocation {
        pub enum Error<T>{InvalidRange,Allocation,Backend(T)}
        pub fn revoke(ranges:impl IntoIterator<Item=(u64,u64,u64)>,_:&mut super::mapping_revocation_native::Native)->Result<(),Error<u64>>{
            crate::locked();assert_eq!(ranges.into_iter().count(),1);crate::EDITS.with(|value|value.set(value.get()+1));Ok(())
        }
    }
}
mod syscall {
    pub(crate) use crate::{EINVAL,EAGAIN};
    pub mod types {pub(crate) use crate::{EACCES,EFAULT,EINVAL,ENOMEM,ESRCH,SUCCESS};}
    pub mod memory {
        use crate::mnu_abi;
"#,
    );
    program.push_str(&protection);
    program.push_str("\n}}\n");
    program.push_str(unmap);
    program.push_str(r#"
fn reset(busy:bool,unavailable:bool) {
    PROCESS.with(|process|process.borrow_mut().regions=vec![
        task::MemoryRegion{start:0x1000,object:None,access:3},
        task::MemoryRegion{start:0x2000,object:Some(Arc::new(task::Object{busy,unavailable})),access:3},
    ]);
    EDITS.with(|value|value.set(0));SYNCS.with(|value|value.set(0));
    PLANS.with(|value|value.set(0));METADATA.with(|value|value.set(0));
    PLAN_FAILURE.set(None);
}
fn main() {
    for protection in [false,true] {
        reset(true,false);
        let result=if protection {syscall::memory::protect(0x1000,8192,1)} else {memory_unmap(0x1000,8192)};
        assert_eq!(result,EAGAIN);assert_eq!(EDITS.with(Cell::get),0);assert_eq!(METADATA.with(Cell::get),0);
        assert_eq!(PLANS.with(Cell::get),0);assert_eq!(SYNCS.with(Cell::get),0);
        assert!(!LOCKED.with(Cell::get));
        PROCESS.with(|process|assert!(process.borrow().regions.iter().all(|region|region.access==3)));
        reset(true,false);
        let result=if protection {syscall::memory::protect(0x1000,4096,1)} else {memory_unmap(0x1000,4096)};
        assert_eq!(result,SUCCESS);assert_eq!(EDITS.with(Cell::get),1);
        reset(false,false);
        let result=if protection {syscall::memory::protect(0x1000,8192,1)} else {memory_unmap(0x1000,8192)};
        assert_eq!(result,SUCCESS);assert!(EDITS.with(Cell::get)>0);assert!(METADATA.with(Cell::get)>0);
        reset(false,true);
        let result=if protection {syscall::memory::protect(0x1000,8192,1)} else {memory_unmap(0x1000,8192)};
        if protection {
            assert_eq!(result,EIO);assert_eq!(EDITS.with(Cell::get),0);assert_eq!(METADATA.with(Cell::get),0);
            assert_eq!(PLANS.with(Cell::get),0);assert_eq!(SYNCS.with(Cell::get),0);
        } else {
            assert_eq!(result,SUCCESS);assert_eq!(EDITS.with(Cell::get),1);assert!(METADATA.with(Cell::get)>0);
        }
        reset(true,true);
        assert_eq!(memory_unmap(0x1000,8192),EAGAIN);
        assert_eq!(EDITS.with(Cell::get),0);assert_eq!(METADATA.with(Cell::get),0);
        assert_eq!(PLANS.with(Cell::get),0);assert_eq!(SYNCS.with(Cell::get),0);
    }
    for (error,expected) in [
        (task::process::MemoryRangeError::InvalidRange,EINVAL),
        (task::process::MemoryRangeError::Allocation,ENOMEM),
    ] {
        reset(false,false);
        PLAN_FAILURE.set(Some(error));
        assert_eq!(memory_unmap(0x1000,8192),expected);
        assert_eq!(PLANS.with(Cell::get),1);
        assert_eq!(EDITS.with(Cell::get),0);assert_eq!(SYNCS.with(Cell::get),0);
        assert_eq!(METADATA.with(Cell::get),0);assert!(!LOCKED.with(Cell::get));
        PROCESS.with_borrow(|process|assert_eq!(process.regions.len(),2));
    }
}
"#);
    program = program
        .replace(
            "@RANGE@",
            root.join("core/src/task/memory_range.rs").to_str().unwrap(),
        )
        .replace(
            "@ADMISSION@",
            root.join("core/src/mem/mapping_admission.rs")
                .to_str()
                .unwrap(),
        );
    let directory = std::env::temp_dir().join(format!(
        "mochios-edit-admission-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&directory).unwrap();
    let binary = directory.join("probe");
    let mut compiler = Command::new("rustc")
        .args(["--edition=2024", "-Awarnings", "-"])
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
        .write_all(program.as_bytes())
        .unwrap();
    let result = compiler.wait_with_output().unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let result = Command::new(&binary).output().unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn native_new_mapping_checks_backing_before_region_publication() {
    let source = include_str!("../../../core/src/syscall/process.rs");
    let body = source
        .split("let (object, file_offset, max_access) = match file_backing {")
        .nth(1)
        .unwrap();
    assert!(
        body.find("object.with_memory_generation(").unwrap()
            < body.find("MemoryRegion::file_backed(").unwrap()
    );
    assert!(
        body.find("object.with_memory_generation(").unwrap()
            < body.find("process.add_memory_region(").unwrap()
    );
}
