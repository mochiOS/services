//! Production input readers and query entry points, with controlled usercopy,
//! allocation failure and task/authority lookup. No real IPC identity claim.
#[allow(dead_code)]
#[path = "support/native_error_probe.rs"]
mod probe;

#[test]
fn capability_input_is_fallible_bounded_and_preserves_native_copy_failures() {
    let source = include_str!("../../../core/src/syscall/capability.rs");
    let mut program = String::from(
        "#![allow(dead_code)]\nextern crate alloc;\nextern crate self as mnu_abi;\nmod status {\n",
    );
    program.push_str(include_str!("../../../core/crates/abi/src/status.rs"));
    program.push_str("}\nuse status::Error;\n");
    program.push_str(
        r#"
use std::{cell::Cell,alloc::{GlobalAlloc,Layout,System}};
thread_local! {
    static FAIL:Cell<bool>=const{Cell::new(false)};
    static ALLOCS:Cell<usize>=const{Cell::new(0)};
    static COPIES:Cell<usize>=const{Cell::new(0)};
    static COPY_ERROR:Cell<Option<Error>>=const{Cell::new(None)};
    static CONTEXT:Cell<bool>=const{Cell::new(true)};
    static SENDER:Cell<bool>=const{Cell::new(true)};
    static PROCESS:Cell<bool>=const{Cell::new(true)};
    static PLAIN:Cell<bool>=const{Cell::new(false)};
    static AUTHORITY:Cell<bool>=const{Cell::new(false)};
    static LOOKUPS:Cell<usize>=const{Cell::new(0)};
}
struct Allocator;
unsafe impl GlobalAlloc for Allocator {
    unsafe fn alloc(&self,l:Layout)->*mut u8 {
        ALLOCS.set(ALLOCS.get()+1);
        if FAIL.replace(false){return std::ptr::null_mut()}
        unsafe{System.alloc(l)}
    }
    unsafe fn dealloc(&self,p:*mut u8,l:Layout){unsafe{System.dealloc(p,l)}}
}
#[global_allocator]static ALLOCATOR:Allocator=Allocator;
mod util {pub mod object_snapshot {use alloc::vec::Vec;
"#,
    );
    program.push_str(probe::between(
        include_str!("../../../core/src/util/object_snapshot.rs"),
        "pub fn zeroed_native(",
        "pub fn read(",
    ));
    program.push_str(r#"
}}
fn copy_from_user_native(pointer:u64,bytes:&mut[u8])->Result<(),Error>{
    COPIES.set(COPIES.get()+1);
    if let Some(error)=COPY_ERROR.get(){return Err(error)}
    unsafe{std::ptr::copy_nonoverlapping(pointer as *const u8,bytes.as_mut_ptr(),bytes.len())};Ok(())
}
mod config {
    pub struct Config{pub capability:Limits} pub struct Limits{pub max_name_len:usize}
    pub fn kernel()->Config{Config{capability:Limits{max_name_len:32}}}
}
#[derive(Clone,Copy)]enum Capability {MemoryPhysMap,Other}
impl Capability {fn from_str(s:&str)->Option<Self>{match s{"memory.phys.map"=>Some(Self::MemoryPhysMap),"test.read"=>Some(Self::Other),_=>None}}}
#[derive(Clone,Copy)]struct KernelAuthority;
enum KernelCapability {PhysMap}
fn parse_kernel_authority_spec(s:&str)->Option<KernelAuthority>{(s=="kernel.phys.map").then_some(KernelAuthority)}
mod task {
    pub fn thread_to_process_id(id:u64)->Option<u64>{assert_eq!(id,19);crate::PROCESS.get().then_some(23)}
    pub mod process {
        pub fn process_has_capability(pid:u64,_:crate::Capability)->bool{assert_eq!(pid,23);crate::LOOKUPS.set(crate::LOOKUPS.get()+1);crate::PLAIN.get()}
        pub fn process_has_kernel_authority(pid:u64,_:&crate::KernelAuthority)->bool{assert_eq!(pid,23);crate::LOOKUPS.set(crate::LOOKUPS.get()+1);crate::AUTHORITY.get()}
        pub fn process_has_kernel_capability_authority(pid:u64,_:crate::KernelCapability)->bool{assert_eq!(pid,23);crate::AUTHORITY.get()}
    }
}
mod syscall {pub mod ipc {
    pub fn resolve_sender_thread_id(id:u64)->Option<u64>{assert_eq!(id,71);crate::SENDER.get().then_some(19)}
}}
fn current_process()->Option<u64>{CONTEXT.get().then_some(23)}
"#);
    program.push_str(probe::between(
        source,
        "#[derive(Clone, Copy)]",
        "/// 指定スレッド",
    ));
    program.push_str(probe::between(
        source,
        "pub fn check_thread_capability(",
        "pub fn clone_capability(",
    ));
    program.push_str(probe::between(
        source,
        "fn read_capability_spec_from_user(",
        "fn parse_capability_token(",
    ));
    program.push_str(probe::between(
        source,
        "fn parse_capability_token(",
        "fn intern_capability_token(",
    ));
    program.push_str(r#"
fn reset(){FAIL.set(false);ALLOCS.set(0);COPIES.set(0);COPY_ERROR.set(None);CONTEXT.set(true);SENDER.set(true);PROCESS.set(true);PLAIN.set(false);AUTHORITY.set(false);LOOKUPS.set(0);}
fn query_bytes(bytes:&[u8])->u64{query(bytes.as_ptr() as u64,bytes.len() as u64)}
fn check_bytes(bytes:&[u8])->u64{check_thread_capability(71,bytes.as_ptr() as u64,bytes.len() as u64)}
fn main(){
    reset();let name=b"test.read";
    assert_eq!(read_capability_name(name.as_ptr() as u64,9,32).unwrap(),"test.read");
    assert_eq!(ALLOCS.get(),1);assert_eq!(COPIES.get(),1); // UTF-8 conversion does not allocate again.
    for operation in [query as fn(u64,u64)->u64,|p,n|check_thread_capability(71,p,n)] {
        for (pointer,length,error) in [(0,0,Error::InvalidArgument),(0,9,Error::InvalidAddress),(u64::MAX-1,9,Error::InvalidAddress),(1,33,Error::LimitExceeded),(1,u64::MAX,Error::LimitExceeded)] {
            reset();assert_eq!(operation(pointer,length),error.into_raw());assert_eq!(ALLOCS.get(),0);assert_eq!(COPIES.get(),0);assert_eq!(LOOKUPS.get(),0);
        }
        reset();FAIL.set(true);assert_eq!(operation(name.as_ptr() as u64,9),Error::ResourceUnavailable.into_raw());assert!(!FAIL.get());assert_eq!(COPIES.get(),0);assert_eq!(LOOKUPS.get(),0);
        for error in [Error::InvalidAddress,Error::AccessDenied,Error::ResourceUnavailable,Error::BackingFailure,Error::NotReady] {
            reset();COPY_ERROR.set(Some(error));assert_eq!(operation(name.as_ptr() as u64,9),error.into_raw());assert_eq!(COPIES.get(),1);assert_eq!(LOOKUPS.get(),0);
        }
        for invalid in [b"unknown!!" as &[u8],&[0xff]] {reset();assert_eq!(operation(invalid.as_ptr() as u64,invalid.len() as u64),Error::InvalidArgument.into_raw());assert_eq!(LOOKUPS.get(),0);}
    }
    reset();assert_eq!(check_thread_capability(0,1,9),Error::InvalidArgument.into_raw());assert_eq!(ALLOCS.get(),0);
    reset();CONTEXT.set(false);assert_eq!(query_bytes(name),Error::NotReady.into_raw());assert_eq!(LOOKUPS.get(),0);
    for absent_process in [false,true] {reset();if absent_process{PROCESS.set(false)}else{SENDER.set(false)}assert_eq!(check_bytes(name),0);assert_eq!(LOOKUPS.get(),0);}
    for allowed in [false,true] {
        reset();PLAIN.set(allowed);assert_eq!(query_bytes(name),u64::from(allowed));assert_eq!(check_bytes(name),u64::from(allowed));
        reset();AUTHORITY.set(allowed);assert_eq!(query_bytes(b"kernel.phys.map"),u64::from(allowed));assert_eq!(check_bytes(b"kernel.phys.map"),u64::from(allowed));
    }
    reset();AUTHORITY.set(true);assert_eq!(query_bytes(b"memory.phys.map"),1);assert_eq!(check_bytes(b"memory.phys.map"),0); // Preserve existing caller-only implication.
    let spec=[b'x';8192];reset();assert_eq!(read_capability_spec_from_user(spec.as_ptr() as u64,8192).unwrap().len(),8192);assert_eq!(ALLOCS.get(),1);
    reset();assert_eq!(read_capability_spec_from_user(1,8193),Err(Error::LimitExceeded.into_raw()));assert_eq!(ALLOCS.get(),0);
    reset();FAIL.set(true);assert_eq!(read_capability_spec_from_user(spec.as_ptr() as u64,8192),Err(Error::ResourceUnavailable.into_raw()));assert_eq!(COPIES.get(),0);
}
"#);
    probe::run(&program);
}
