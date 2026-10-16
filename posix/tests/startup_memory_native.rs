//! Execute real stack relocation and TLS preparation with controlled mappings.
#[allow(dead_code)]
#[path = "support/native_error_probe.rs"]
mod probe;

#[test]
fn startup_storage_is_exact_fallible_and_native() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap();
    let mut program = String::from("#![allow(dead_code,unused_attributes)]\nextern crate alloc;\n");
    program.push_str(&format!(
        "extern crate self as mnu_abi;\n#[path={:?}]mod abi;\npub use abi::*;\nmod util {{#[path={:?}]pub mod object_snapshot;}}\n",
        root.join("core/crates/abi/src/lib.rs"),
        root.join("core/src/util/object_snapshot.rs")
    ));
    let exec = include_str!("../../../core/src/syscall/exec.rs");
    program.push_str(probe::between(
        exec,
        "struct InitialUserStack {",
        "struct ExecMeasurement {",
    ));
    program.push_str(
        r#"
use std::cell::Cell;
use status::Error;
thread_local! {
    static FAIL:Cell<bool>=const {Cell::new(false)};
    static MAPS:Cell<usize>=const {Cell::new(0)};
    static MAP_ERROR:Cell<Option<Kernel>>=const {Cell::new(None)};
    static CONFIG:Cell<config::Configuration>=const {Cell::new(config::DEFAULT)};
}
struct Allocator;
unsafe impl std::alloc::GlobalAlloc for Allocator {
    unsafe fn alloc(&self,layout:std::alloc::Layout)->*mut u8 {
        if FAIL.with(|s|s.replace(false)){std::ptr::null_mut()}else{unsafe{std::alloc::System.alloc(layout)}}
    }
    unsafe fn dealloc(&self,p:*mut u8,layout:std::alloc::Layout){unsafe{std::alloc::System.dealloc(p,layout)}}
}
#[global_allocator]static ALLOCATOR:Allocator=Allocator;
#[macro_export]macro_rules! warn {($($arg:tt)*)=>{{}};}
mod config {
    #[derive(Clone,Copy)]pub struct Exec {pub tls_base_min:u64,pub tls_aslr_max_pages:u64,pub initial_tls_size:u64,pub stack_top_base:u64,pub stack_aslr_max_pages:u64,pub user_stack_size_pages:usize}
    #[derive(Clone,Copy)]pub struct Configuration {pub exec:Exec}
    pub const DEFAULT:Configuration=Configuration{exec:Exec{tls_base_min:0x600000,tls_aslr_max_pages:0,initial_tls_size:32,stack_top_base:0x800000,stack_aslr_max_pages:0,user_stack_size_pages:32}};
    pub fn kernel()->Configuration {crate::CONFIG.get()}
}
#[derive(Clone,Copy)]enum Kernel {Memory(result::Memory),InvalidParam}
mod result {#[derive(Clone,Copy)]pub enum Memory {OutOfMemory}}
fn aslr_offset_pages(_:u64,max:u64)->u64 {assert_eq!(max,0);0}
mod mem {pub mod paging {
    pub fn map_and_copy_segment_to(table:u64,address:u64,filesz:u64,memsz:u64,data:&[u8],write:bool,exec:bool)->Result<(),crate::Kernel> {
        assert_eq!(table,17);assert_eq!(address,0x600000);assert_eq!((filesz,memsz),(32,32));assert!(write);assert!(!exec);
        assert_eq!(&data[..8],&address.to_ne_bytes());assert!(data[8..].iter().all(|&b|b==0));
        crate::MAPS.set(crate::MAPS.get()+1);crate::MAP_ERROR.get().map_or(Ok(()),Err)
    }
}}
"#,
    );
    program.push_str(probe::between(
        exec,
        "fn mapping_error_native(",
        "#[inline]\nfn aslr_mix64",
    ));
    program.push_str(probe::between(
        exec,
        "pub(crate) fn map_initial_tls(",
        "fn exec_with_data(",
    ));
    program.push_str(
        r#"
fn main() {
    use process_image::{Relocation,RelocationKind as Kind};
    let relocations=[Kind::StackAddress,Kind::ElfProgramHeaders,Kind::ElfProgramHeaderSize,Kind::ElfProgramHeaderCount,Kind::ElfEntry,Kind::PageSize].map(|kind|Relocation{offset:(kind as u32-1)*8,kind});
    let mut stack=[0u8;48];stack[..8].copy_from_slice(&32u64.to_le_bytes());let mut bytes=[0;256];
    let length=process_image::encode(8,&stack,&relocations,&mut bytes).unwrap();let startup=process_image::decode(&bytes[..length]).unwrap();
    let prepared=build_relocatable_user_stack(0,startup,0x400040,56,2,0x400000).unwrap();
    assert_eq!((prepared.stack_base_vaddr,prepared.stack_end_vaddr,prepared.initial_rsp),(0x7e0000,0x800000,0x800000-40));
    assert!(prepared.page_data[..4096-48].iter().all(|&b|b==0));
    for (index,value) in [0x800000u64-48+32,0x400040,56,2,0x400000,4096].into_iter().enumerate() {
        let at=4096-48+index*8;assert_eq!(&prepared.page_data[at..at+8],&value.to_le_bytes());
    }
    FAIL.set(true);assert_eq!(build_relocatable_user_stack(0,startup,0,0,0,0).err(),Some(Error::ResourceUnavailable));assert!(!FAIL.get());
    for mode in 0..3 {
        let mut configuration=config::DEFAULT;
        match mode {0=>configuration.exec.user_stack_size_pages=usize::MAX,1=>configuration.exec.stack_top_base=4096,_=>{configuration.exec.stack_top_base=0;configuration.exec.user_stack_size_pages=0;}}
        CONFIG.set(configuration);assert_eq!(build_relocatable_user_stack(0,startup,0,0,0,0).err(),Some(Error::InvalidArgument));
    }
    CONFIG.set(config::DEFAULT);FAIL.set(true);assert_eq!(map_initial_tls(17,0),Err(Error::ResourceUnavailable));assert!(!FAIL.get());assert_eq!(MAPS.get(),0);
    for length in [0,1,7] {
        let mut configuration=config::DEFAULT;configuration.exec.initial_tls_size=length;CONFIG.set(configuration);
        assert_eq!(map_initial_tls(17,0),Err(Error::InvalidArgument));assert_eq!(MAPS.get(),0);
    }
    CONFIG.set(config::DEFAULT);
    for (error,expected) in [(Kernel::Memory(result::Memory::OutOfMemory),Error::ResourceUnavailable),(Kernel::InvalidParam,Error::InvalidArgument)] {
        MAP_ERROR.set(Some(error));assert_eq!(map_initial_tls(17,0),Err(expected));
    }
    MAP_ERROR.set(None);assert_eq!(map_initial_tls(17,0),Ok(0x600000));assert_eq!(MAPS.get(),3);
}
"#,
    );
    probe::run(&program);
}
