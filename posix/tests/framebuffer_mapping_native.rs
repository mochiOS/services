#[allow(dead_code)]
#[path = "support/native_error_probe.rs"]
mod probe;

#[test]
fn framebuffer_mapping_reports_native_failures_and_borrows_only_selected_storage() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap();
    let mut program = format!(
        "#![allow(dead_code)]\nextern crate self as mnu_abi;\n#[path={:?}]mod status;\n",
        root.join("core/crates/abi/src/status.rs"),
    );
    program.push_str(r#"
use status::Error;
use std::cell::Cell;
thread_local!{static MODE:Cell<u8>=const{Cell::new(0)};static CALLS:Cell<u8>=const{Cell::new(0)};}
mod capability{pub enum Capability{DisplayRead}}
mod syscall{pub mod security{
    pub fn caller_has_any_capability(_: &[crate::capability::Capability])->bool{crate::MODE.get()!=1}
    pub fn current_process_id()->Option<u64>{(crate::MODE.get()!=3).then_some(7)}
}}
mod mem{
    pub mod frame{pub fn is_allowed_mmio_range(_:u64,_:u64)->bool{crate::MODE.get()!=4}}
    pub mod paging{#[derive(Debug,PartialEq)]pub enum MappingCache{Uncached,WriteBack}}
}
mod platform{
    pub struct Info{pub shared_surface:bool,pub surface_address:u64,pub surface_size:u64}
    pub fn display_info()->Result<Info,()>{
        match crate::MODE.get(){
            2|4|7=>Err(()),5=>Ok(Info{shared_surface:true,surface_address:0x2001,surface_size:u64::MAX}),
            _=>Ok(Info{shared_surface:true,surface_address:0x2000,surface_size:4096})
        }
    }
}
mod util{pub mod vga{
    pub struct Info{pub addr:u64,pub size:usize}
    pub fn get_info()->Option<Info>{matches!(crate::MODE.get(),4|7).then_some(Info{addr:0xfec00080,size:1})}
}}
fn map_borrowed_range_for_process(pid:u64,address:u64,physical:u64,length:u64,cache:mem::paging::MappingCache)->u64{
    CALLS.set(CALLS.get()+1);assert_eq!((pid,address,length),(7,0x10000,4096));
    if MODE.get()==7{assert_eq!(physical,0xfec00000);assert_eq!(cache,mem::paging::MappingCache::Uncached);}
    else{assert_eq!(physical,0x2000);assert_eq!(cache,mem::paging::MappingCache::WriteBack);}
    if MODE.get()==6{Error::AlreadyExists.into_raw()}else{0}
}
"#);
    program.push_str(probe::between(
        include_str!("../../../core/src/syscall/mod.rs"),
        "pub fn map_framebuffer(",
        "/// Retry only a temporary backing reservation",
    ));
    program.push_str(
        r#"
fn main(){
    for (mode,expected) in [(0,0),(1,Error::AccessDenied.into_raw()),
        (2,Error::NotReady.into_raw()),(3,Error::NotReady.into_raw()),
        (4,Error::AccessDenied.into_raw()),(5,Error::BackingFailure.into_raw()),
        (6,Error::AlreadyExists.into_raw()),(7,0)]{
        MODE.set(mode);CALLS.set(0);assert_eq!(map_framebuffer(0x10000,8192),expected);
        assert_eq!(CALLS.get(),u8::from(matches!(mode,0|6|7)));
    }
    MODE.set(0);CALLS.set(0);
    for (address,length) in [(0,8192),(0x10001,8192),(0x10000,0),(0x10000,4097)]{
        assert_eq!(map_framebuffer(address,length),Error::InvalidArgument.into_raw());
    }
    assert_eq!(CALLS.get(),0);
}
"#,
    );
    probe::run(&program);
}
