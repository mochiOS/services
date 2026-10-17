//! Production restriction entry point, parsers and authority containers. Only
//! process-table locking, registry access and usercopy are host substitutes.
#[allow(dead_code)]
#[path = "support/native_error_probe.rs"]
mod probe;

#[test]
fn restriction_is_atomic_on_allocation_failure_and_never_increases_authority() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap();
    let mut program = format!(
        "#![allow(dead_code)]\nextern crate alloc;\nextern crate self as mnu_abi;\n#[path={:?}]mod abi;\npub use abi::*;\nuse status::Error;\nuse alloc::{{string::{{String,ToString}},vec::Vec}};\nuse std::cell::{{Cell,RefCell}};\n",
        root.join("core/crates/abi/src/lib.rs"),
    );
    program.push_str(r#"
thread_local! {
    static FAIL_AFTER:Cell<Option<usize>>=const{Cell::new(None)};
    static REGISTRY:RefCell<DynamicCapabilityRegistry>=const{RefCell::new(DynamicCapabilityRegistry{names:Vec::new()})};
    static PROCESS:RefCell<Option<Process>>=const{RefCell::new(None)};
    static CONTEXT:Cell<bool>=const{Cell::new(true)};
    static COPY_ERROR:Cell<Option<Error>>=const{Cell::new(None)};
    static COPY_ERROR_AT:Cell<usize>=const{Cell::new(1)};
    static LOCKED:Cell<bool>=const{Cell::new(false)};
    static COPIES:Cell<usize>=const{Cell::new(0)};
}
struct Allocator;
unsafe impl std::alloc::GlobalAlloc for Allocator {
    unsafe fn alloc(&self,l:std::alloc::Layout)->*mut u8 {
        if FAIL_AFTER.with(|s|match s.get(){Some(0)=>{s.set(None);true},Some(n)=>{s.set(Some(n-1));false},None=>false}){return std::ptr::null_mut()}
        unsafe{std::alloc::System.alloc(l)}
    }
    unsafe fn dealloc(&self,p:*mut u8,l:std::alloc::Layout){unsafe{std::alloc::System.dealloc(p,l)}}
}
#[global_allocator]static ALLOCATOR:Allocator=Allocator;
fn with_dynamic_registry<R>(f:impl FnOnce(&mut DynamicCapabilityRegistry)->R)->R{REGISTRY.with_borrow_mut(f)}
"#);
    let capability = include_str!("../../../core/src/capability/mod.rs");
    for (start, end) in [
        (
            "/// kernel が直接強制する低レベル権限",
            "/// mnu が直接強制する権限",
        ),
        ("/// mnu が直接強制する権限", "static DYNAMIC_CAPABILITIES:"),
        ("fn valid_capability_name(", "/// `parent` が、"),
    ] {
        program.push_str(probe::between(capability, start, end));
    }
    program.push_str(&capability[capability.find("/// `parent` が、").unwrap()..]);
    program.push_str(r#"
pub mod capability {pub use crate::abi::capability::*;pub use crate::{CapabilitySet,KernelAuthoritySet,capability_implies};}
struct Process{caps:CapabilitySet,authorities:KernelAuthoritySet}
impl Process {
    fn capabilities_mut(&mut self)->&mut CapabilitySet{&mut self.caps}
    fn kernel_authorities_mut(&mut self)->&mut KernelAuthoritySet{&mut self.authorities}
}
mod task {
    pub fn with_process_mut<R>(id:u64,f:impl FnOnce(&mut crate::Process)->R)->Option<R>{
        assert_eq!(id,23);assert!(!crate::LOCKED.replace(true));
        let result=crate::PROCESS.with_borrow_mut(|p|p.as_mut().map(f));crate::LOCKED.set(false);result
    }
}
mod config {pub struct Config{pub capability:Limits}pub struct Limits{pub max_name_len:usize}pub fn kernel()->Config{Config{capability:Limits{max_name_len:256}}}}
fn current_process()->Option<u64>{CONTEXT.get().then_some(23)}
fn copy_from_user_native(pointer:u64,bytes:&mut[u8])->Result<(),Error>{
    assert!(!LOCKED.get());COPIES.set(COPIES.get()+1);
    if COPIES.get()==COPY_ERROR_AT.get(){if let Some(e)=COPY_ERROR.get(){return Err(e)}}
    unsafe{std::ptr::copy_nonoverlapping(pointer as *const u8,bytes.as_mut_ptr(),bytes.len())};Ok(())
}
mod util {pub mod object_snapshot {use alloc::vec::Vec;
"#);
    program.push_str(probe::between(
        include_str!("../../../core/src/util/object_snapshot.rs"),
        "pub fn zeroed_native(",
        "pub fn read(",
    ));
    program.push_str("}}\n");
    let syscall = include_str!("../../../core/src/syscall/capability.rs");
    for (start, end) in [
        ("#[derive(Clone, Copy)]", "/// 指定スレッド"),
        ("pub fn restrict_capability(", "fn current_process("),
        (
            "fn read_capability_spec_from_user(",
            "fn parse_scoped_path_grant(",
        ),
        ("fn parse_capability_token(", "fn intern_capability_token("),
        ("fn read_capability_token_from_user(", "#[cfg(test)]"),
    ] {
        program.push_str(probe::between(syscall, start, end));
    }
    program.push_str(r#"
fn set(parent:&str,also:Option<&str>){
    FAIL_AFTER.set(None);CONTEXT.set(true);COPY_ERROR.set(None);COPY_ERROR_AT.set(1);COPIES.set(0);
    let mut caps=CapabilitySet::empty();let mut authorities=KernelAuthoritySet::empty();
    for name in [Some(parent),also].into_iter().flatten(){if let Some(a)=parse_kernel_authority_spec(name){authorities.insert(a)}else{caps.insert(Capability::from_str(name).unwrap())}}
    // Force capacity == length: a replacement must reuse the removed slot.
    PROCESS.set(Some(Process{caps:caps.try_clone().unwrap(),authorities:authorities.try_clone().unwrap()}));
}
fn contains(name:&str)->bool{PROCESS.with_borrow(|p|{let p=p.as_ref().unwrap();if let Some(a)=parse_kernel_authority_spec(name){p.authorities.contains_exact(&a)}else{p.caps.contains_exact(Capability::from_str(name).unwrap())}})}
fn count()->usize{PROCESS.with_borrow(|p|{let p=p.as_ref().unwrap();p.caps.len()+p.authorities.len()})}
fn restrict(parent:&str,child:&str)->u64{restrict_capability(parent.as_ptr() as u64,parent.len() as u64,child.as_ptr() as u64,child.len() as u64)}
fn main(){
    for (parent,child) in [("fs.read.all","fs.read.tmp"),("memory.phys.map@4096:8192","memory.phys.map@4096:4096")] {
        for failure in 0..2 {
            set(parent,None);FAIL_AFTER.set(Some(failure));assert_eq!(restrict(parent,child),Error::ResourceUnavailable.into_raw());assert!(FAIL_AFTER.get().is_none());assert!(contains(parent));assert!(!contains(child));assert_eq!(count(),1);assert!(!LOCKED.get());
        }
        set(parent,None);FAIL_AFTER.set(Some(2));assert_eq!(restrict(parent,child),SUCCESS);assert_eq!(FAIL_AFTER.replace(None),Some(0));assert!(!contains(parent));assert!(contains(child));assert_eq!(count(),1);
        set(parent,None);FAIL_AFTER.set(Some(2));assert_eq!(restrict(parent,parent),SUCCESS);assert_eq!(FAIL_AFTER.replace(None),Some(0));assert!(contains(parent));assert_eq!(count(),1);
        set(parent,Some(child));FAIL_AFTER.set(Some(2));assert_eq!(restrict(parent,child),SUCCESS);assert_eq!(FAIL_AFTER.replace(None),Some(0));assert!(!contains(parent));assert!(contains(child));assert_eq!(count(),1);
        set(child,None);assert_eq!(restrict(parent,child),Error::AccessDenied.into_raw());assert!(contains(child));assert_eq!(count(),1);
        set(child,None);assert_eq!(restrict(child,parent),Error::AccessDenied.into_raw());assert!(contains(child));assert!(!contains(parent));assert_eq!(count(),1);
        for error in [Error::InvalidAddress,Error::BackingFailure,Error::ResourceUnavailable,Error::NotReady] {
            for at in [1,2]{set(parent,None);COPY_ERROR.set(Some(error));COPY_ERROR_AT.set(at);assert_eq!(restrict(parent,child),error.into_raw());assert_eq!(COPIES.get(),at);assert!(contains(parent));assert_eq!(count(),1);}
        }
        set(parent,None);CONTEXT.set(false);assert_eq!(restrict(parent,child),Error::NotReady.into_raw());assert_eq!(COPIES.get(),0);assert!(contains(parent));
        set(parent,None);PROCESS.set(None);assert_eq!(restrict(parent,child),Error::NotReady.into_raw());
    }
    set("fs.read.all",None);assert_eq!(restrict("fs.read.all","memory.phys.map@4096:4096"),Error::InvalidArgument.into_raw());assert!(contains("fs.read.all"));assert_eq!(count(),1);
    for invalid in ["unknown.capability", "bad..name"]{set("fs.read.all",None);assert_eq!(restrict("fs.read.all",invalid),Error::InvalidArgument.into_raw());assert!(contains("fs.read.all"));}
    set("memory.phys.map@4096:4096",None);assert_eq!(restrict("memory.phys.map@4096:4096","memory.phys.map@8192:4096"),Error::AccessDenied.into_raw());assert!(contains("memory.phys.map@4096:4096"));
}
"#);
    probe::run(&program);
}
