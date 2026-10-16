//! Production resident-copy/COW helpers and interrupt COW dispatch, with only
//! physical copying, execution identity, locks and scheduling substituted.
use std::io::Write;
use std::process::{Command, Stdio};

#[test]
fn reserved_cow_and_full_span_usercopy_retry_after_unlock_and_revalidate_root() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap();
    let process = include_str!("../../../core/src/syscall/process.rs");
    let syscall = include_str!("../../../core/src/syscall/mod.rs");
    let function = |source: &str, name: &str| -> String {
        let start = source.find(name).unwrap();
        let end = start + source[start..].find("\n}\n").unwrap() + 3;
        source[start..end].to_owned()
    };
    let idt = include_str!("../../../core/src/interrupt/idt.rs");
    let start = idt
        .find("    let mut copy_on_write_failed = false;")
        .unwrap();
    let end = start + idt[start..].find("    let mut fault_cause =").unwrap();
    let mut program = String::from(
        r#"
use std::{cell::{Cell,RefCell},sync::{Arc,atomic::{AtomicBool,Ordering}}};
extern crate self as mnu_abi;
#[path="@STATUS@"] pub mod status;
#[path="@USERCOPY_ERROR@"] mod usercopy_error;
#[derive(Clone,Copy,Debug,PartialEq,Eq)] pub enum Kernel {Memory(result::Memory)}
mod result {
    #[derive(Clone,Copy,Debug,PartialEq,Eq)] pub enum Memory {Busy,InvalidAddress,PermissionDenied,OutOfMemory}
    pub type Result<T> = core::result::Result<T,crate::Kernel>;
}
mod security {pub fn current_process_id()->Option<u64>{Some(7)}}
mod syscall {pub const EINVAL:u64=(-22i64) as u64;pub const EAGAIN:u64=(-11i64) as u64;pub mod security {pub use crate::security::*;}}
thread_local! {
    static LOCKED:Cell<bool>=const {Cell::new(false)};
    static ROOT:Cell<Option<u64>>=const {Cell::new(Some(4096))};
    static DENIED:Cell<bool>=const {Cell::new(false)};
    static YIELDS:Cell<usize>=const {Cell::new(0)};
    static MODE:Cell<u8>=const {Cell::new(0)};
    static READS:Cell<usize>=const {Cell::new(0)};
    static WRITES:Cell<usize>=const {Cell::new(0)};
    static COWS:Cell<usize>=const {Cell::new(0)};
    static FAULTS:Cell<usize>=const {Cell::new(0)};
    static RESIDENT:Cell<bool>=const {Cell::new(false)};
    static LEAVES:Cell<usize>=const {Cell::new(0)};
    static FALLTHROUGH:Cell<usize>=const {Cell::new(0)};
    static DATA:RefCell<[u8;8192]>=const {RefCell::new([0x11;8192])};
    static PROCESS:RefCell<task::Process>=RefCell::new(task::Process{regions:Vec::new()});
}
fn locked(){assert!(LOCKED.with(Cell::get));}
mod task {
    use super::*;
    pub struct Object {pub busy:AtomicBool}
    impl Object {
        pub fn memory_generation(&self)->Option<u64>{Some(1)}
        pub fn with_memory_generation_native<T>(&self,generation:Option<u64>,install:impl FnOnce()->Result<T,status::Error>)->Result<T,status::Error>{
            locked();assert_eq!(generation,Some(1));if self.busy.load(Ordering::Acquire){Err(status::Error::NotReady)}else{install()}
        }
        pub fn check_mapping_removal(&self)->Result<(),status::Error>{self.with_memory_generation_native(Some(1),||Ok(()))}
    }
    pub struct MemoryRegion {pub start:u64,pub object:Option<Arc<Object>>}
    impl MemoryRegion {
        pub fn start(&self)->u64{self.start} pub fn end(&self)->Option<u64>{Some(self.start+4096)}
        pub fn backing(&self)->&Self{self} pub fn file_object(&self)->Option<&Arc<Object>>{self.object.as_ref()}
    }
    pub struct Process {pub regions:Vec<MemoryRegion>}
    impl Process {
        pub fn page_table(&self)->Option<u64>{ROOT.with(Cell::get)}
        pub fn memory_regions(&self)->&[MemoryRegion]{&self.regions}
    }
    pub fn with_process<T>(pid:u64,body:impl FnOnce(&Process)->T)->Option<T>{
        assert_eq!(pid,7);LOCKED.with(|value|assert!(!value.replace(true)));
        let result=PROCESS.with(|process|body(&process.borrow()));LOCKED.with(|value|value.set(false));Some(result)
    }
    pub fn with_process_mut<T>(pid:u64,body:impl FnOnce(&mut Process)->T)->Option<T>{
        assert_eq!(pid,7);LOCKED.with(|value|assert!(!value.replace(true)));
        let result=PROCESS.with(|process|body(&mut process.borrow_mut()));LOCKED.with(|value|value.set(false));Some(result)
    }
    pub fn yield_now(){
        assert!(!LOCKED.with(Cell::get));
        assert_eq!(READS.with(Cell::get)+WRITES.with(Cell::get)+COWS.with(Cell::get),0);
        DATA.with(|data|assert!(data.borrow().iter().all(|byte|*byte==0x11)));
        YIELDS.with(|value|value.set(value.get()+1));
        match MODE.with(Cell::get){
            1=>ROOT.with(|value|value.set(Some(8192))),
            2=>DENIED.with(|value|value.set(true)),
            _=>{}
        }
        if MODE.with(Cell::get)!=3||YIELDS.with(Cell::get)==3{
            PROCESS.with(|process|process.borrow().regions[1].object.as_ref().unwrap().busy.store(false,Ordering::Release));
        }
    }
}
mod mem {
    #[path="@ADMISSION@"] pub mod mapping_admission;
    pub mod paging {
        pub fn is_user_range_mapped_in_table(_:u64,_:u64,_:u64)->bool{crate::locked();crate::RESIDENT.with(std::cell::Cell::get)}
        pub fn is_user_range_writable_in_table(table:u64,address:u64,length:u64)->bool{is_user_range_mapped_in_table(table,address,length)}
        fn check(table:u64)->crate::result::Result<()>{
            crate::locked();assert_eq!(table,4096);
            if crate::DENIED.with(std::cell::Cell::get){Err(crate::Kernel::Memory(crate::result::Memory::PermissionDenied))}else{Ok(())}
        }
        pub fn copy_from_user_in_table(table:u64,address:u64,bytes:&mut [u8])->crate::result::Result<()>{
            check(table)?;assert_eq!(address,0x1000);crate::READS.with(|value|value.set(value.get()+1));bytes.fill(0x72);Ok(())
        }
        pub fn copy_to_user_in_table(table:u64,address:u64,bytes:&[u8])->crate::result::Result<()>{
            check(table)?;assert_eq!(address,0x1000);crate::WRITES.with(|value|value.set(value.get()+1));
            crate::DATA.with(|data|data.borrow_mut()[..bytes.len()].copy_from_slice(bytes));Ok(())
        }
        pub fn resolve_copy_on_write(table:u64,address:u64)->crate::result::Result<bool>{
            check(table)?;assert_eq!(address,0x2000);crate::COWS.with(|value|value.set(value.get()+1));Ok(true)
        }
    }
}
"#,
    );
    for (source, name) in [
        (process, "pub(crate) fn resolve_user_copy_on_write("),
        (syscall, "fn copy_out_of_current_root("),
        (syscall, "fn copy_into_current_root("),
        (syscall, "fn retry_usercopy<"),
        (syscall, "fn fault_in_user_range("),
    ] {
        program.push_str(&function(source, name));
    }
    program.push_str(r#"
mod x86_64 {pub mod structures {pub mod idt {
    pub struct PageFaultErrorCode;
    impl PageFaultErrorCode {pub const PROTECTION_VIOLATION:Self=Self;pub const CAUSED_BY_WRITE:Self=Self;pub fn contains(&self,_:Self)->bool{true}}
}}}
struct Address;impl Address {fn as_u64(&self)->u64{0x2000}}
macro_rules! warn {($($args:tt)*)=>{let _=format_args!($($args)*);};}
fn leave_to_user(entered:bool){assert!(entered);LEAVES.with(|value|value.set(value.get()+1));}
fn interrupt_cow(){
    let is_user_mode=true;let user_page_table=Some(4096);let entered_from_user=true;
    let faulting_addr=Address;let error_code=x86_64::structures::idt::PageFaultErrorCode;
"#);
    // The actual interrupt path resolves through the syscall module.
    program = program.replace(
        "@STATUS@",
        root.join("core/crates/abi/src/status.rs").to_str().unwrap(),
    );
    program = program.replace(
        "pub mod security {pub use crate::security::*;}",
        r#"pub mod security {pub use crate::security::*;}
pub mod process {
    pub(crate) use crate::resolve_user_copy_on_write;
    #[derive(Clone,Copy)] pub struct Fault(bool);impl Fault{
        pub fn is_retryable(self)->bool{self.0}
        pub fn cause(self)->mnu_abi::MemoryFaultCause{mnu_abi::MemoryFaultCause::AccessDenied}
    }
    pub fn handle_user_memory_fault(address:u64,_:bool,_:bool)->Result<(),Fault>{
        assert!(!crate::LOCKED.with(std::cell::Cell::get));assert_eq!(address,0x1000);
        crate::FAULTS.with(|count|count.set(count.get()+1));
        if crate::DENIED.with(std::cell::Cell::get){return Err(Fault(false));}
        if crate::FAULTS.with(std::cell::Cell::get)<=3{return Err(Fault(true));}
        crate::RESIDENT.with(|value|value.set(true));Ok(())
    }
}"#,
    );
    program.push_str(&idt[start..end]);
    program.push_str(r#"
    FALLTHROUGH.with(|value|value.set(value.get()+1));
}
fn reset(mode:u8){
    ROOT.with(|value|value.set(Some(4096)));DENIED.with(|value|value.set(false));MODE.with(|value|value.set(mode));
    YIELDS.with(|value|value.set(0));READS.with(|value|value.set(0));WRITES.with(|value|value.set(0));COWS.with(|value|value.set(0));
    LEAVES.with(|value|value.set(0));FALLTHROUGH.with(|value|value.set(0));DATA.with(|data|*data.borrow_mut()=[0x11;8192]);
    FAULTS.with(|value|value.set(0));RESIDENT.with(|value|value.set(false));
    PROCESS.with(|process|process.borrow_mut().regions=vec![
        task::MemoryRegion{start:0x1000,object:None},
        task::MemoryRegion{start:0x2000,object:Some(Arc::new(task::Object{busy:AtomicBool::new(true)}))},
    ]);
}
fn main(){
    for write in [false,true]{
        reset(0);assert_eq!(fault_in_user_range(4096,0x1000,4096,write),Ok(()));
        assert_eq!(YIELDS.with(Cell::get),3);assert_eq!(FAULTS.with(Cell::get),4);
        reset(1);assert_eq!(fault_in_user_range(4096,0x1000,4096,write),Err(status::Error::InvalidAddress));
        assert_eq!(YIELDS.with(Cell::get),1);assert_eq!(FAULTS.with(Cell::get),1);
        reset(2);assert_eq!(fault_in_user_range(4096,0x1000,4096,write),Err(status::Error::InvalidAddress));
        assert_eq!(YIELDS.with(Cell::get),1);assert_eq!(FAULTS.with(Cell::get),2);
    }
    for write in [false,true]{
        reset(3);let mut output=[0x22;8192];
        let result=if write{retry_usercopy(||copy_into_current_root(4096,0x1000,&output))}else{retry_usercopy(||copy_out_of_current_root(4096,0x1000,&mut output))};
        assert_eq!(result,Ok(()));assert_eq!(YIELDS.with(Cell::get),3);
        assert_eq!(READS.with(Cell::get)+WRITES.with(Cell::get),1);
        if write{DATA.with(|data|assert_eq!(*data.borrow(),[0x22;8192]));}else{assert_eq!(output,[0x72;8192]);}
        for mode in [1,2]{
            reset(mode);let mut output=[0x22;8192];
            let result=if write{retry_usercopy(||copy_into_current_root(4096,0x1000,&output))}else{retry_usercopy(||copy_out_of_current_root(4096,0x1000,&mut output))};
            assert_eq!(result,Err(Kernel::Memory(if mode==1{result::Memory::InvalidAddress}else{result::Memory::PermissionDenied})));
            assert_eq!(YIELDS.with(Cell::get),1);assert_eq!(READS.with(Cell::get)+WRITES.with(Cell::get),0);
            assert_eq!(output,[0x22;8192]);DATA.with(|data|assert_eq!(*data.borrow(),[0x11;8192]));
        }
    }
    reset(0);
    assert_eq!(resolve_user_copy_on_write(4096,0x2000),Err(Kernel::Memory(result::Memory::Busy)));
    assert_eq!(COWS.with(Cell::get),0);
    interrupt_cow();assert_eq!(YIELDS.with(Cell::get),1);assert_eq!(LEAVES.with(Cell::get),1);assert_eq!(COWS.with(Cell::get),0);
    assert_eq!(FALLTHROUGH.with(Cell::get),0);
    interrupt_cow();assert_eq!(LEAVES.with(Cell::get),2);assert_eq!(COWS.with(Cell::get),1);assert_eq!(FALLTHROUGH.with(Cell::get),0);
}
"#);
    program.push_str("\nuse crate::syscall::process;\nfn is_canonical_user_range(start:u64,length:u64)->bool{length!=0&&start.checked_add(length).is_some_and(|end|end<0x800000000000)}\n");
    let abi = include_str!("../../../core/crates/abi/src/lib.rs");
    let cause_start = abi.find("pub enum MemoryFaultCause {").unwrap();
    let cause_end = cause_start + abi[cause_start..].find("\n}").unwrap() + 2;
    program.push_str("\n#[derive(Clone,Copy)]\n");
    program.push_str(&abi[cause_start..cause_end]);
    program = program.replace(
        "@USERCOPY_ERROR@",
        root.join("core/src/syscall/usercopy_error.rs").to_str().unwrap(),
    );
    program = program.replace(
        "@ADMISSION@",
        root.join("core/src/mem/mapping_admission.rs")
            .to_str()
            .unwrap(),
    );
    let directory = std::env::temp_dir().join(format!(
        "mochios-resident-admission-{}-{}",
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
