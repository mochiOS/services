//! Execute the complete production spawn function with injected VM/task calls.
//! This verifies its failure/cleanup branches, not a real scheduler or page table.
#[allow(dead_code)]
#[path = "support/native_error_probe.rs"]
mod probe;

#[test]
fn spawn_failures_preserve_native_status_and_cleanup_ownership() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap();
    let mut program = String::from(
        "#![allow(dead_code,unused_variables,unused_attributes)]\nextern crate alloc;\n",
    );
    program.push_str(&format!(
        "extern crate self as mnu_abi;\n#[path={:?}]mod abi;\npub use abi::*;\nmod util {{#[path={:?}]pub mod object_snapshot;}}\n#[path={:?}]mod storage;\n#[path={:?}]mod bootstrap_stack;\n",
        root.join("core/crates/abi/src/lib.rs"),
        root.join("core/src/util/object_snapshot.rs"),
        root.join("core/src/syscall/exec/storage.rs"),
        root.join("core/src/syscall/exec/bootstrap_stack.rs")
    ));
    let exec = include_str!("../../../core/src/syscall/exec.rs");
    program.push_str(probe::between(
        exec,
        "struct InitialUserStack {",
        "struct ExecMeasurement {",
    ));
    program.push_str(probe::between(
        exec,
        "enum GuardedTable {",
        "fn mapping_error_native(",
    ));
    program.push_str(
        r#"
use std::{cell::Cell,sync::Arc};
use status::Error;
thread_local! {
    static STAGE:Cell<u8>=const {Cell::new(0)};
    static DESTROYS:Cell<usize>=const {Cell::new(0)};
    static MAPS:Cell<usize>=const {Cell::new(0)};
    static PROCESSES:Cell<usize>=const {Cell::new(0)};
    static CLOSES:Cell<usize>=const {Cell::new(0)};
    static FREES:Cell<usize>=const {Cell::new(0)};
    static RELEASES:Cell<usize>=const {Cell::new(0)};
    static FAIL_NEXT:Cell<bool>=const {Cell::new(false)};
}
struct Allocator;
unsafe impl std::alloc::GlobalAlloc for Allocator {
    unsafe fn alloc(&self,layout:std::alloc::Layout)->*mut u8 {
        if FAIL_NEXT.with(|state|state.replace(false)){std::ptr::null_mut()}else{unsafe{std::alloc::System.alloc(layout)}}
    }
    unsafe fn dealloc(&self,p:*mut u8,layout:std::alloc::Layout){unsafe{std::alloc::System.dealloc(p,layout)}}
}
#[global_allocator]static ALLOCATOR:Allocator=Allocator;
#[macro_export]macro_rules! warn {($($arg:tt)*)=>{{}};}
#[macro_export]macro_rules! debug {($($arg:tt)*)=>{{}};}
#[macro_export]macro_rules! info {($($arg:tt)*)=>{{}};}
type CapabilitySet=();type KernelAuthoritySet=();
struct InheritedHandleGrant;struct InheritedValueSpec;struct ExecMeasurement;
struct Sha256;impl Sha256 {fn digest(_:&[u8])->[u8;32]{[0;32]}}
enum ImageLaunch<'a>{Bootstrap,Created(&'a ())}
impl ImageLaunch<'_>{fn is_bootstrap(&self)->bool{matches!(self,Self::Bootstrap)}fn startup(&self)->Option<()>{if self.is_bootstrap(){None}else{Some(())}}}
struct ElfImageLayout {entry:u64,phdr_vaddr:u64,phentsize:u64,phnum:u64,deferred_zero_regions:Vec<task::MemoryRegion>}
fn next_aslr_seed(_:&str)->u64 {0}
fn aslr_offset_pages(_:u64,_:u64)->u64 {0}
fn resolve_exec_privilege(_:Option<task::PrivilegeLevel>)->task::PrivilegeLevel {task::PrivilegeLevel}
fn mapping_error_native(_:())->Error {Error::ResourceUnavailable}
fn claim_init_pid(id:u64)->bool{assert_eq!(id,7);STAGE.get()!=7}
fn release_init_pid(id:u64)->bool{assert_eq!(id,7);RELEASES.set(RELEASES.get()+1);true}
fn install_inherited_handles(_:&mut task::Process,_:&[InheritedHandleGrant])->Result<(),Error>{if STAGE.get()==12{Err(Error::AccessDenied)}else{Ok(())}}
fn install_inherited_values(_:&mut task::Process,_:&[InheritedValueSpec])->Result<(),Error>{if STAGE.get()==13{Err(Error::AlreadyExists)}else{Ok(())}}
fn map_elf_image(_:&[u8],table:u64,_:&mut ExecMeasurement)->Result<ElfImageLayout,Error>{
    assert_eq!(table,17);if STAGE.get()==2 {return Err(Error::InvalidArgument);}
    Ok(ElfImageLayout{entry:0x400000,phdr_vaddr:0x400040,phentsize:56,phnum:1,deferred_zero_regions:Vec::new()})
}
fn build_relocatable_user_stack(_:u64,_:(),_:u64,_:u64,_:u64,_:u64)->Result<InitialUserStack,Error>{bootstrap_stack::empty(0x800000,32)}
fn map_initial_tls(table:u64,_:u64)->Result<u64,Error>{assert_eq!(table,17);if STAGE.get()==5 {Err(Error::ResourceUnavailable)}else{Ok(0x600000)}}
mod config {
    pub struct Exec {pub stack_top_base:u64,pub stack_aslr_max_pages:u64,pub user_stack_size_pages:usize,pub brk_heap_base_min:u64,pub brk_heap_aslr_max_pages:u64,pub kernel_thread_stack_size:usize}
    pub struct Config{pub exec:Exec}
    pub fn kernel()->Config{Config{exec:Exec{stack_top_base:0x800000,stack_aslr_max_pages:0,user_stack_size_pages:32,brk_heap_base_min:0x900000,brk_heap_aslr_max_pages:0,kernel_thread_stack_size:16384}}}
}
mod kernel {pub fn early_serial(_:&str){}}
mod cpu {pub struct SmapSmepGuard;impl SmapSmepGuard{pub fn new()->Self{Self}}}
mod mem {
    pub mod detached_roots {pub struct Root;impl Root {pub fn published(&self)->bool{false}pub fn table(&self)->u64{17}}}
    pub mod paging {
        pub fn create_user_page_table()->Result<u64,()>{if crate::STAGE.get()==1{Err(())}else{Ok(17)}}
        pub fn destroy_user_page_table(table:u64)->Result<(),()>{assert_eq!(table,17);crate::DESTROYS.set(crate::DESTROYS.get()+1);Ok(())}
        pub fn map_and_copy_segment_to(table:u64,_:u64,_:u64,_:u64,_:&[u8],_:bool,_:bool)->Result<(),()>{
            assert_eq!(table,17);let call=crate::MAPS.get()+1;crate::MAPS.set(call);
            if matches!((crate::STAGE.get(),call),(3,1)|(4,2)|(11,3)){Err(())}else{Ok(())}
        }
    }
}
mod syscall {
    pub fn copy_from_user_native(_:u64,_:&mut [u8])->Result<(),crate::Error>{panic!("no usercopy in spawn backend")}
    pub mod handle {
        pub fn retain_created_process(_:&crate::task::Process)->Result<u64,crate::Error>{if crate::STAGE.get()==6{Err(crate::Error::NotReady)}else{Ok(91)}}
        pub fn close(raw:u64)->u64{assert_eq!(raw,91);crate::CLOSES.set(crate::CLOSES.get()+1);0}
    }
}
mod task {
    pub mod process{pub type ApplicationIdentity=();}
    #[derive(Clone,Copy)]pub struct Id;impl Id{pub fn as_u64(self)->u64{7}}
    pub struct PrivilegeLevel;pub struct MemoryRegion;pub struct Process;
    impl Process {
        pub fn try_new(_:&str,_:PrivilegeLevel,_:u8)->Result<Self,crate::Error>{
            if crate::STAGE.get()==14{Err(crate::Error::ResourceUnavailable)}else{Ok(Self)}
        }
        pub fn id(&self)->Id{Id}pub fn name(&self)->&str{"name"}
        pub fn set_image_digest(&mut self,_:[u8;32]){}pub fn set_application_identity(&mut self,_:()){}
        pub fn set_foreground(&mut self,_:bool){}pub fn set_capabilities_for_exec(&mut self,_:()){}
        pub fn set_kernel_authorities_for_exec(&mut self,_:()){}pub fn set_page_table(&mut self,table:u64){assert_eq!(table,17);}
        pub fn set_memory_regions(&mut self,_:Vec<MemoryRegion>){}pub fn set_stack_bottom(&mut self,_:u64){}
        pub fn set_stack_top(&mut self,_:u64){}pub fn set_exe_path(&mut self,identity:String){assert_eq!(identity,"opaque:target");}
        pub fn set_heap_start(&mut self,_:u64){}pub fn set_heap_end(&mut self,_:u64){}
    }
    pub fn add_process(_:Process)->Option<Id>{if crate::STAGE.get()==8{None}else{crate::PROCESSES.set(crate::PROCESSES.get()+1);Some(Id)}}
    pub fn remove_process(_:Id)->Option<Process>{assert_eq!(crate::PROCESSES.get(),1);crate::PROCESSES.set(0);Some(Process)}
    pub mod thread {pub fn allocate_kernel_stack_in_table(_:usize,table:u64)->Option<u64>{assert_eq!(table,17);if crate::STAGE.get()==9{None}else{Some(0x10000)}}}
    pub fn free_kernel_stack(stack:u64){assert_eq!(stack,0x10000);crate::FREES.set(crate::FREES.get()+1);}
    pub struct Thread;
    impl Thread {
        pub fn new_usermode(_:Id,_:&str,_:u64,_:u64,_:u64,stack:u64,_:usize)->Self{assert_eq!(stack,0x10000);Self}
        pub fn set_fs_base(&mut self,base:u64){assert_eq!(base,0x600000);}pub fn suspend(&mut self){}
    }
    pub fn add_thread(_:Thread)->Option<u64>{if crate::STAGE.get()==10{None}else{Some(8)}}
    pub fn peek_next_thread()->Option<u64>{None}
}
"#,
    );
    program.push_str(probe::between(
        exec,
        "fn exec_with_data(",
        "fn check_image_byte_ceiling(",
    ));
    program.push_str(
        r#"
fn reset(stage:u8){STAGE.set(stage);DESTROYS.set(0);MAPS.set(0);PROCESSES.set(0);CLOSES.set(0);FREES.set(0);RELEASES.set(0);}
fn main(){
    for native in [false,true] {
        for (stage,error) in [(1,Error::ResourceUnavailable),(2,Error::InvalidArgument),(3,Error::ResourceUnavailable),
            (4,Error::ResourceUnavailable),(5,Error::ResourceUnavailable),(8,Error::ResourceUnavailable),
            (9,Error::ResourceUnavailable),(10,Error::ResourceUnavailable),(12,Error::AccessDenied),
            (13,Error::AlreadyExists),(14,Error::ResourceUnavailable)] {
            reset(stage);let launch=if native{ImageLaunch::Created(&())}else{ImageLaunch::Bootstrap};
            assert_eq!(exec_with_data(&[],"name","opaque:target",None,None,None,None,&[],&[],launch,&mut ExecMeasurement),error.into_raw());
            assert_eq!(DESTROYS.get(),usize::from(stage!=1));assert_eq!(PROCESSES.get(),0);
            assert_eq!(CLOSES.get(),usize::from(native&&matches!(stage,8|9|10)));
            assert_eq!(RELEASES.get(),usize::from(!native&&matches!(stage,8|9|10)));
            assert_eq!(FREES.get(),usize::from(stage==10));
        }
        for stage in [0,11] {reset(stage);let launch=if native{ImageLaunch::Created(&())}else{ImageLaunch::Bootstrap};
            assert_eq!(exec_with_data(&[],"name","opaque:target",None,None,None,None,&[],&[],launch,&mut ExecMeasurement),if native{91}else{7});
            assert_eq!(DESTROYS.get(),0);assert_eq!(PROCESSES.get(),1);assert_eq!(CLOSES.get(),0);assert_eq!(RELEASES.get(),0);assert_eq!(FREES.get(),0);
        }
    }
    reset(6);assert_eq!(exec_with_data(&[],"name","opaque:target",None,None,None,None,&[],&[],ImageLaunch::Created(&()),&mut ExecMeasurement),Error::NotReady.into_raw());assert_eq!(DESTROYS.get(),1);assert_eq!(PROCESSES.get(),0);assert_eq!(CLOSES.get(),0);
    reset(7);assert_eq!(exec_with_data(&[],"name","opaque:target",None,None,None,None,&[],&[],ImageLaunch::Bootstrap,&mut ExecMeasurement),Error::AlreadyExists.into_raw());assert_eq!(DESTROYS.get(),1);assert_eq!(PROCESSES.get(),0);assert_eq!(RELEASES.get(),0);
    reset(0);FAIL_NEXT.set(true);
    let result=exec_with_data(&[],"name","opaque:target",None,None,None,None,&[],&[],ImageLaunch::Created(&()),&mut ExecMeasurement);
    assert!(!FAIL_NEXT.get());assert_eq!(result,Error::ResourceUnavailable.into_raw());assert_eq!(DESTROYS.get(),0);assert_eq!(MAPS.get(),0);assert_eq!(PROCESSES.get(),0);
}
"#,
    );
    probe::run(&program);
}
