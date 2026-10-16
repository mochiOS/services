//! Run the production replacement transaction and metadata slicer on the host.
use std::io::Write;
use std::process::{Command, Stdio};
struct Temporary(std::path::PathBuf);
impl Drop for Temporary {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn replacement_checks_projected_usage_and_rolls_back_before_publication() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap();
    let source = include_str!("../../../core/src/task/process.rs");
    let mut program = String::from(
        r#"
#![allow(dead_code)]
extern crate alloc;
use alloc::sync::Arc;
use std::cell::{Cell,RefCell};
pub enum Kernel { Memory(result::Memory) }
pub mod result {
    pub enum Memory {InvalidAddress,Busy}
    pub type Result<T> = core::result::Result<T,crate::Kernel>;
}
extern crate self as mnu_abi;
#[path="@ROOT@/core/crates/abi/src/status.rs"] pub mod status;
pub const MEMORY_ACCESS_READ:u64=1; pub const MEMORY_ACCESS_WRITE:u64=2;
pub const MEMORY_ACCESS_EXECUTE:u64=4; pub const MEMORY_ACCESS_ALL:u64=7;
pub const MEMORY_MAP_SHARED:u64=2;
thread_local! {
    static PAGES:RefCell<Vec<u64>>=const {RefCell::new(Vec::new())};
    static EVENTS:RefCell<Vec<&'static str>>=const {RefCell::new(Vec::new())};
    static FAIL_SYNC:Cell<bool>=const {Cell::new(false)};
    static FAIL_WALK:Cell<bool>=const {Cell::new(false)};
    static HAS_ROOT:Cell<bool>=const {Cell::new(true)};
    static FAIL_ALLOCATION:Cell<Option<usize>>=const {Cell::new(None)};
    static ALLOCATION_FAILED:Cell<bool>=const {Cell::new(false)};
}
struct Allocator;
fn deny_allocation()->bool {
    FAIL_ALLOCATION.try_with(|slot|match slot.get() {
        None=>false,
        Some(0)=>{slot.set(None);ALLOCATION_FAILED.with(|failed|failed.set(true));true},
        Some(left)=>{slot.set(Some(left-1));false},
    }).unwrap_or(false)
}
unsafe impl std::alloc::GlobalAlloc for Allocator {
    unsafe fn alloc(&self,layout:std::alloc::Layout)->*mut u8 {
        if deny_allocation(){std::ptr::null_mut()}else{unsafe{std::alloc::System.alloc(layout)}}
    }
    unsafe fn realloc(&self,pointer:*mut u8,layout:std::alloc::Layout,size:usize)->*mut u8 {
        if deny_allocation(){std::ptr::null_mut()}else{unsafe{std::alloc::System.realloc(pointer,layout,size)}}
    }
    unsafe fn dealloc(&self,pointer:*mut u8,layout:std::alloc::Layout){unsafe{std::alloc::System.dealloc(pointer,layout)}}
}
#[global_allocator] static ALLOCATOR:Allocator=Allocator;
mod mem {
    pub mod vm_object {
        #[derive(Debug)] pub struct VmObject {pub busy:bool}
        impl VmObject {
            pub fn check_mapping_removal(&self)->Result<(),mnu_abi::status::Error> {if self.busy {Err(mnu_abi::status::Error::NotReady)} else {Ok(())}}
            pub fn memory_generation(&self)->Option<u64>{Some(1)}
            pub fn with_memory_generation_native<T>(&self,_:Option<u64>,f:impl FnOnce()->Result<T,mnu_abi::status::Error>)->Result<T,mnu_abi::status::Error>{self.check_mapping_removal()?;f()}
        }
    }
    #[path="@ROOT@/core/src/mem/mapping_usage.rs"] pub mod mapping_usage;
    #[path="@ROOT@/core/src/mem/mapping_revocation.rs"] pub mod mapping_revocation;
    #[path="@ROOT@/core/src/mem/mapping_admission.rs"] pub mod mapping_admission;
    #[path="@ROOT@/core/src/mem/mapping_replace.rs"] pub mod mapping_replace;
    pub mod paging {
        pub unsafe fn next_user_page_entry(_:u64,start:u64,end:u64)->Result<Option<u64>,u64> {
            if crate::FAIL_WALK.get(){return Err(1);}
            Ok(crate::PAGES.with_borrow(|pages| pages.iter().copied().filter(|&p|p>=start&&p<end).min()))
        }
    }
    pub mod mapping_revocation_native {
        pub struct Native<'a>(&'a crate::task::Process);
        impl<'a> Native<'a> {pub unsafe fn for_process(p:&'a crate::task::Process,owns:bool)->Self {assert!(owns);Self(p)}}
        impl super::mapping_revocation::Backend for Native<'_> {
            type Page=u64;type Error=crate::status::Error;
            fn next_page(&mut self,t:u64,s:u64,e:u64)->Result<Option<u64>,Self::Error>{unsafe{super::paging::next_user_page_entry(t,s,e)}.map_err(|_|crate::status::Error::InvalidAddress)}
            fn suspend(&mut self,_:u64,a:u64)->Result<Option<u64>,Self::Error>{crate::EVENTS.with_borrow_mut(|e|e.push("suspend"));Ok(Some(a))}
            fn restore(&mut self,_:u64){crate::EVENTS.with_borrow_mut(|e|e.push("restore"));}
            fn synchronize(&mut self)->Result<(),Self::Error>{crate::EVENTS.with_borrow_mut(|e|e.push("sync"));if crate::FAIL_SYNC.with(|v|v.get()){Err(crate::status::Error::BackingFailure)}else{Ok(())}}
            fn release(&mut self,a:u64){crate::EVENTS.with_borrow_mut(|e|e.push("release"));crate::PAGES.with_borrow_mut(|p|p.retain(|&p|p!=a));}
        }
    }
}
#[path="@ROOT@/core/src/task/memory_range.rs"] mod memory_range;
"#,
    );
    let start = source
        .find("#[derive(Clone, Debug)]\npub enum MemoryBacking")
        .unwrap();
    let end = source
        .find("#[derive(Clone, Debug)]\npub struct DmaBuffer")
        .unwrap();
    program.push_str(&source[start..end]);
    let start = source.find("impl MemoryRegion {").unwrap();
    let end = source
        .find("/// Stable native process lifecycle object retained by `ProcessHandle`s")
        .unwrap();
    program.push_str(&source[start..end]);
    program.push_str(r#"
mod task {
    pub use crate::MemoryRegion;
    use crate::MemoryRangeError;
    pub mod process { pub use crate::MemoryRangeError; }
    #[derive(Clone)] pub struct Borrowed;
    impl Borrowed {pub fn virt_start(&self)->u64{0x2000} pub fn end(&self)->Option<u64>{Some(0x3000)}}
    pub struct Process {pub memory_regions:Vec<MemoryRegion>, pub dma:bool,pub mmio:bool}
    impl Process {
        pub fn page_table(&self)->Option<u64>{crate::HAS_ROOT.get().then_some(4096)}
        pub fn find_dma_buffer_by_addr(&self,_:u64,_:u64)->Option<Borrowed>{self.dma.then_some(Borrowed)}
        pub fn find_mmio_mapping_by_addr(&self,_:u64,_:u64)->Option<Borrowed>{self.mmio.then_some(Borrowed)}
        pub fn memory_regions(&self)->&[MemoryRegion]{&self.memory_regions}
        pub fn mmio_mappings(&self)->&[Borrowed]{&[]}
        pub fn dma_buffers(&self)->&[Borrowed]{&[]}
        pub fn set_memory_regions(&mut self,v:Vec<MemoryRegion>){crate::EVENTS.with_borrow_mut(|e|e.push("publish"));self.memory_regions=v;}
"#);
    let start = source
        .find("    pub(crate) fn prepare_remove_memory_range(")
        .unwrap();
    let end = start
        + source[start..]
            .find("    pub fn has_kernel_authority(")
            .unwrap();
    program.push_str(&source[start..end]);
    program.push_str(r#"
    }
}
fn reset()->task::Process {
    PAGES.with_borrow_mut(|p|*p=vec![0x1000,0x2000,0x4000,0x9000]);
    EVENTS.with_borrow_mut(|events|{events.clear();events.reserve(16);}); FAIL_SYNC.set(false);
    FAIL_WALK.set(false);HAS_ROOT.set(true);
    let mut old=MemoryRegion::file_backed(0x1000,0x4000,3,2,
        Arc::new(mem::vm_object::VmObject{busy:false}),8192,true,true,3);
    assert!(old.set_access(0x4000,0x1000,1));
    for p in 0..4 {old.mark_dirty_page(p);}
    task::Process{memory_regions:vec![old],dma:false,mmio:false}
}
fn replacement()->MemoryRegion {MemoryRegion::anonymous(0x2000,0x2000,3,0,true,false)}
fn main() {
    use mem::mapping_replace::replace;
    let mut process=reset();
    let removed=replace(&mut process,replacement(),Some(5*4096)).unwrap();
    assert_eq!(removed.len(),1);
    assert_eq!(removed[0].backing().file_offset(),12288);
    assert_eq!(removed[0].dirty_pages(),[0,1]);
    assert_eq!(process.memory_regions.len(),3);
    let tail=process.memory_regions.iter().find(|r|r.start()==0x4000).unwrap();
    assert_eq!(tail.backing().file_offset(),20480);
    assert!(!tail.allows_write_at(0x4000));
    assert_eq!(tail.dirty_pages(),[0]);
    PAGES.with_borrow(|p|assert_eq!(p.as_slice(),[0x1000,0x4000,0x9000]));
    EVENTS.with_borrow(|e|assert_eq!(e.as_slice(),["suspend","sync","release","publish"]));
    for mode in 0..7 {
        let mut process=reset();
        process.dma=mode==0; process.mmio=mode==1;
        if mode==2 {process.memory_regions[0]=MemoryRegion::file_backed(0x1000,0x4000,3,2,Arc::new(mem::vm_object::VmObject{busy:true}),0,true,true,3);}
        FAIL_SYNC.set(mode==4);
        FAIL_WALK.set(mode==5);HAS_ROOT.set(mode!=6);
        let result=replace(&mut process,replacement(),Some(if mode==3 {4*4096}else{5*4096}));
        assert_eq!(result.unwrap_err(),match mode {
            0|1=>status::Error::AccessDenied,2|6=>status::Error::NotReady,
            3=>status::Error::ResourceUnavailable,4=>status::Error::BackingFailure,
            _=>status::Error::InvalidAddress,
        });
        assert_eq!(process.memory_regions.len(),1);
        assert_eq!(process.memory_regions[0].len(),0x4000);
        PAGES.with_borrow(|p|assert_eq!(p.as_slice(),[0x1000,0x2000,0x4000,0x9000]));
        EVENTS.with_borrow(|e|assert_eq!(e.as_slice(),if mode==4 {vec!["suspend","sync","restore"]}else{vec![]}));
    }
    let mut process=reset();
    PAGES.with_borrow_mut(Vec::clear);
    replace(&mut process,replacement(),Some(4*4096)).unwrap();
    EVENTS.with_borrow(|e|assert_eq!(e.as_slice(),["publish"]));
    let mut verified=0;
    for anonymous in [false,true] {
        let mut completed=false;
        for nth in 0..128 {
            let mut process=reset();
            if anonymous {
                *process.memory_regions[0].backing_mut()=MemoryBacking::Anonymous{
                    data:(0..0x4000).map(|index|(index/4096) as u8).collect(),writable:true,shared:false,
                };
            }
            ALLOCATION_FAILED.set(false);
            FAIL_ALLOCATION.set(Some(nth));
            let result=replace(&mut process,replacement(),None);
            FAIL_ALLOCATION.set(None);
            if !ALLOCATION_FAILED.with(Cell::get) {
                let removed=result.unwrap();
                if anonymous {
                    match removed[0].backing() {
                        MemoryBacking::Anonymous{data,..}=>assert!(data.len()==8192&&data.iter().enumerate().all(|(i,&b)|b==1+(i/4096) as u8)),
                        _=>panic!("anonymous backing changed type"),
                    }
                    for region in process.memory_regions.iter().filter(|region|region.start()!=0x2000) {
                        match region.backing() {
                            MemoryBacking::Anonymous{data,..}=>assert!(data.len()==4096&&data.iter().all(|&b|b==if region.start()==0x1000 {0}else{3})),
                            _=>panic!("retained backing changed type"),
                        }
                    }
                }
                completed=true;break;
            }
            assert_eq!(result.unwrap_err(),status::Error::ResourceUnavailable);
            assert_eq!(process.memory_regions.len(),1);
            let old=&process.memory_regions[0];
            assert_eq!((old.start(),old.len()),(0x1000,0x4000));
            assert_eq!(old.dirty_pages(),[0,1,2,3]);
            assert!(!old.allows_write_at(0x4000));
            assert!(old.allows_write_at(0x2000));
            match old.backing() {
                MemoryBacking::File{object,offset,..}=>{assert_eq!(Arc::strong_count(object),1);assert_eq!(*offset,8192);},
                MemoryBacking::Anonymous{data,..}=>assert!(data.len()==0x4000&&data.iter().enumerate().all(|(i,&b)|b==(i/4096) as u8)),
            }
            PAGES.with_borrow(|pages|assert_eq!(pages.as_slice(),[0x1000,0x2000,0x4000,0x9000]));
            EVENTS.with_borrow(|events|assert!(events.is_empty()));
            verified+=1;
        }
        assert!(completed);
    }
    assert!(verified>=12);
    println!("mapping-replace: verified {verified} individual allocation failures without VM edits or leaked backing references");
}
"#);
    let program = program.replace("@ROOT@", root.to_str().unwrap());
    let directory = std::env::temp_dir().join(format!(
        "mochios-replace-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&directory).unwrap();
    let cleanup = Temporary(directory.clone());
    let executable = directory.join("probe");
    let mut compiler = Command::new("rustc")
        .args(["--edition=2024", "-", "-o"])
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
    let compiled = compiler.wait_with_output().unwrap();
    assert!(
        compiled.status.success(),
        "{}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    let result = Command::new(&executable).output().unwrap();
    drop(cleanup);
    print!("{}", String::from_utf8_lossy(&result.stdout));
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
}
