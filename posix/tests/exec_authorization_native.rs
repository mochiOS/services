//! Actual request parsing, authorization decision and publication. Task tables
//! and capability storage are controlled backends, not real IPC/scheduler tests.
#[allow(dead_code)]
#[path = "support/native_error_probe.rs"]
mod probe;

#[test]
fn native_authorization_preserves_sender_selection_attenuation_and_failures() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap();
    let mut program = String::from("#![allow(dead_code,unused_attributes)]\nextern crate alloc;\n");
    program.push_str(&format!(
        "extern crate self as mnu_abi;\n#[path={:?}]mod abi;\npub use abi::*;\nuse exec::*;\nmod util {{#[path={:?}]pub mod object_snapshot;}}\n#[path={:?}]mod storage;\n",
        root.join("core/crates/abi/src/lib.rs"),
        root.join("core/src/util/object_snapshot.rs"),
        root.join("core/src/syscall/exec/storage.rs")
    ));
    program.push_str(
        r#"
use std::{cell::{Cell,RefCell},sync::atomic::{AtomicUsize,Ordering}};
use status::Error;
thread_local! {
    static FAIL_AFTER:Cell<Option<usize>>=const {Cell::new(None)};
    static ALLOC_CALLS:Cell<usize>=const {Cell::new(0)};
    static DIGEST_PRESENT:Cell<bool>=const {Cell::new(true)};
    static APP_PRESENT:Cell<bool>=const {Cell::new(true)};
    static CLONE_FAIL:Cell<u8>=const {Cell::new(0)};
    static INHERITING:Cell<bool>=const {Cell::new(false)};
    static MANAGE:Cell<bool>=const {Cell::new(true)};
    static THREAD:Cell<bool>=const {Cell::new(true)};
    static OWNER:Cell<bool>=const {Cell::new(true)};
    static PRESENT:Cell<bool>=const {Cell::new(true)};
    static WRITABLE:Cell<bool>=const {Cell::new(true)};
    static GRANTED:Cell<u64>=const {Cell::new(3)};
    static AUTHORITY:Cell<u64>=const {Cell::new(1)};
    static WRITES:Cell<usize>=const {Cell::new(0)};
    static TARGET:Cell<u64>=const {Cell::new(23)};
    static COPIES:Cell<usize>=const {Cell::new(0)};
    static COPY_ERROR:Cell<Option<Error>>=const {Cell::new(None)};
    static IDENTITY:RefCell<Vec<u8>>=const {RefCell::new(Vec::new())};
    static CAPS:RefCell<Vec<u8>>=const {RefCell::new(Vec::new())};
}
static LIVE:AtomicUsize=AtomicUsize::new(0);
struct Allocator;
unsafe impl std::alloc::GlobalAlloc for Allocator {
    unsafe fn alloc(&self,layout:std::alloc::Layout)->*mut u8 {
        ALLOC_CALLS.set(ALLOC_CALLS.get()+1);
        if FAIL_AFTER.with(|s|match s.get(){Some(0)=>{s.set(None);true},Some(n)=>{s.set(Some(n-1));false},None=>false}) {return std::ptr::null_mut();}
        let p=unsafe{std::alloc::System.alloc(layout)};if !p.is_null(){LIVE.fetch_add(1,Ordering::Relaxed);}p
    }
    unsafe fn dealloc(&self,p:*mut u8,layout:std::alloc::Layout){LIVE.fetch_sub(1,Ordering::Relaxed);unsafe{std::alloc::System.dealloc(p,layout)}}
}
#[global_allocator]static ALLOCATOR:Allocator=Allocator;
pub mod capability {
    pub use crate::abi::capability::*;
    #[derive(Clone,Copy)]pub enum Capability {CapabilitiesManage,ProcessSpawn,MemoryPhysMap,Read,Existing}
    impl Capability {
        pub fn try_intern(name:&str)->Result<Self,crate::Error>{Self::intern(name).ok_or(crate::Error::InvalidArgument)}
        pub fn intern(name:&str)->Option<Self>{match name{"process.spawn"=>Some(Self::ProcessSpawn),"memory.phys.map"=>Some(Self::MemoryPhysMap),"fs.read.all"=>Some(Self::Read),_=>None}}
        pub fn from_str(name:&str)->Option<Self>{if name=="custom.existing"{Some(Self::Existing)}else{Self::intern(name)}}
        fn bit(self)->u64{match self {Self::ProcessSpawn=>1,Self::Read=>2,Self::Existing=>4,_=>8}}
    }
    pub struct CapabilitySet(pub u64);
    impl CapabilitySet {
        pub fn try_clone(&self)->Result<Self,crate::Error>{if crate::CLONE_FAIL.get()==2{Err(crate::Error::ResourceUnavailable)}else{Ok(Self(self.0))}}
        pub fn empty()->Self{Self(0)}pub fn try_insert(&mut self,c:Capability)->Result<(),crate::Error>{self.0|=c.bit();Ok(())}
        pub fn contains(&self,c:Capability)->bool{self.0&c.bit()!=0}pub fn is_subset_of(&self,other:&Self)->bool{self.0&!other.0==0}
    }
    pub struct KernelAuthoritySet(pub u64);
    impl KernelAuthoritySet {pub fn empty()->Self{Self(0)}pub fn try_insert(&mut self,_:())->Result<(),crate::Error>{self.0=1;Ok(())}pub fn is_subset_of(&self,other:&Self)->bool{self.0&!other.0==0}}
    pub fn parse_kernel_authority_spec(spec:&str)->Option<()>{(spec=="memory.phys.map@0x1000:4096").then_some(())}
}
use capability::{Capability,CapabilitySet,KernelAuthoritySet,parse_kernel_authority_spec};
mod syscall {
    use crate::*;
    pub mod security {
        pub fn caller_has_any_capability(_:&[crate::Capability])->bool{crate::MANAGE.get()}
        pub fn current_process_id()->Option<u64>{crate::OWNER.get().then_some(19)}
    }
    pub mod ipc {pub fn resolve_sender_thread_id(endpoint:u64)->Option<u64>{(endpoint==123).then_some(41)}}
    pub fn copy_from_user_native(pointer:u64,output:&mut [u8])->Result<(),Error>{
        COPIES.set(COPIES.get()+1);if let Some(error)=COPY_ERROR.get(){return Err(error);}
        if (100..111).contains(&pointer){assert_eq!(output.len(),1);output[0]=b"opaque:key\0"[(pointer-100)as usize];}
        else if pointer==200 {output.fill(0);IDENTITY.with_borrow(|s|output[..s.len()].copy_from_slice(s));}
        else if pointer==300 {CAPS.with_borrow(|s|output.copy_from_slice(s));}
        else if pointer==111 {output[0]=0xff;}
        else if pointer==112 {output[0]=0;}
        else if pointer==u64::MAX {output[0]=b'x';}
        else {return Err(Error::InvalidAddress);}Ok(())
    }
"#,
    );
    program.push_str(probe::between(
        include_str!("../../../core/src/syscall/mod.rs"),
        "pub fn read_user_cstring(",
        "pub fn map_physical_range(",
    ));
    program.push_str(
        r#"
}
mod task {
    #[derive(Clone,Copy)]pub struct ThreadId(pub u64);impl ThreadId{pub fn from_u64(raw:u64)->Self{Self(raw)}}
    pub fn current_thread_id()->Option<ThreadId>{crate::THREAD.get().then_some(ThreadId(23))}
    pub struct Thread;impl Thread{pub fn process_id(&self)->u64{31}}
    pub fn with_thread<T>(id:ThreadId,body:impl FnOnce(&Thread)->T)->Option<T>{assert_eq!(id.0,41);crate::THREAD.get().then(||body(&Thread))}
    pub type ProcessId=u64;
    pub mod process {
        pub enum ApplicationProvenance{BuiltIn,VerifiedPackage,Development}
        pub struct ApplicationIdentity;
        impl ApplicationIdentity{pub fn try_clone(&self)->Result<Self,crate::Error>{if crate::CLONE_FAIL.get()==1{Err(crate::Error::ResourceUnavailable)}else{Ok(Self)}}pub fn new(package:String,developer:String,_:[u8;32],_:ApplicationProvenance)->Self{assert_eq!((package.as_str(),developer.as_str()),("app.example","developer.example"));Self}}
        #[derive(Clone,Copy,PartialEq)]pub enum PendingExecKind{ImageReplace,Spawn,SpawnInherit}
        pub struct PendingExecSecurity{pub path:String,pub authorized_thread:super::ThreadId,pub executable_digest:[u8;32],pub capabilities:crate::CapabilitySet,pub kernel_authorities:crate::KernelAuthoritySet,pub identity:ApplicationIdentity,pub kind:PendingExecKind,pub execution_class:crate::ExecutionClass}
    }
    pub struct Process{caps:crate::CapabilitySet,authorities:crate::KernelAuthoritySet}
    impl Process{
        pub fn image_digest(&self)->Option<[u8;32]>{crate::DIGEST_PRESENT.get().then_some([0x6b;32])}
        pub fn application_identity(&self)->Option<&process::ApplicationIdentity>{crate::APP_PRESENT.get().then_some(&process::ApplicationIdentity)}
        pub fn capabilities(&self)->&crate::CapabilitySet{&self.caps}pub fn kernel_authorities(&self)->&crate::KernelAuthoritySet{&self.authorities}
        pub fn authorize_next_exec(&mut self,a:process::PendingExecSecurity){if crate::INHERITING.get(){assert_eq!(a.capabilities.0,crate::GRANTED.get());assert_eq!(a.kernel_authorities.0,0);assert_eq!(a.execution_class,crate::ExecutionClass::Unprivileged);}assert_eq!(a.path,"opaque:key");assert_eq!(a.authorized_thread.0,crate::TARGET.get());assert_eq!(a.executable_digest,if a.kind==process::PendingExecKind::SpawnInherit {[0x6b;32]}else{[0;32]});crate::WRITES.set(crate::WRITES.get()+1);}
    }
    fn process()->Process{Process{caps:crate::CapabilitySet(crate::GRANTED.get()),authorities:crate::KernelAuthoritySet(crate::AUTHORITY.get())}}
    pub fn with_process<T>(id:u64,body:impl FnOnce(&Process)->T)->Option<T>{assert!(id==19||id==31);crate::PRESENT.get().then(||body(&process()))}
    pub fn with_process_mut<T>(id:u64,body:impl FnOnce(&mut Process)->T)->Option<T>{assert!(id==19||id==31);crate::WRITABLE.get().then(||body(&mut process()))}
}
"#,
    );
    let exec = include_str!("../../../core/src/syscall/exec.rs");
    for (start, end) in [
        (
            "fn read_nul_identity_fields(",
            "fn caller_has_process_spawn_capability(",
        ),
        (
            "fn parse_requested_exec_grants(",
            "fn export_inherited_handles(",
        ),
        (
            "fn valid_security_identity(",
            "pub(crate) fn launch_bootstrap_image(",
        ),
    ] {
        program.push_str(probe::between(exec, start, end));
    }
    program.push_str(
        r#"
fn reset(kind:&str,caps:&[u8])->u64 {
    DIGEST_PRESENT.set(true);APP_PRESENT.set(true);CLONE_FAIL.set(0);INHERITING.set(false);FAIL_AFTER.set(None);COPY_ERROR.set(None);MANAGE.set(true);THREAD.set(true);OWNER.set(true);PRESENT.set(true);WRITABLE.set(true);GRANTED.set(3);AUTHORITY.set(1);WRITES.set(0);TARGET.set(23);COPIES.set(0);
    let fields=format!("{APPLICATION_PACKAGE_ID_PREFIX}app.example\0{APPLICATION_DEVELOPER_ID_PREFIX}developer.example\0{APPLICATION_SUBJECT_KEY_ID_PREFIX}{}\0{APPLICATION_PROVENANCE_PREFIX}built-in\0{EXECUTABLE_DIGEST_PREFIX}{}\0{EXEC_AUTHORIZATION_KIND_PREFIX}{kind}\0{EXEC_AUTHORIZATION_CLASS_PREFIX}unprivileged\0\0","0".repeat(64),"0".repeat(64));
    IDENTITY.with_borrow_mut(|s|*s=fields.into_bytes());CAPS.with_borrow_mut(|s|*s=caps.to_vec());caps.len() as u64
}
fn check(endpoint:u64,length:u64,expected:u64){let live=LIVE.load(Ordering::Relaxed);assert_eq!(authorize_exec_syscall(endpoint,100,200,300,length),expected);assert_eq!(LIVE.load(Ordering::Relaxed),live);}
fn inherit_fields(){ INHERITING.set(true);
 let fields=format!("{EXECUTABLE_DIGEST_PREFIX}{}\0{EXEC_AUTHORIZATION_KIND_PREFIX}{EXEC_AUTHORIZATION_KIND_IMAGE_REPLACE_INHERIT}\0{EXEC_AUTHORIZATION_CLASS_PREFIX}unprivileged\0\0","0".repeat(64));
 IDENTITY.with_borrow_mut(|s|*s=fields.into_bytes());
}
fn main(){
    reset("spawn",b"");INHERITING.set(true);
    IDENTITY.with_borrow_mut(|s|*s=format!("{EXEC_AUTHORIZATION_KIND_PREFIX}{EXEC_AUTHORIZATION_KIND_SPAWN_INHERIT}\0{EXEC_AUTHORIZATION_CLASS_PREFIX}unprivileged\0\0").into_bytes());
    check(0,0,0);assert_eq!(WRITES.get(),1);
    TARGET.set(41);check(123,0,0);assert_eq!(WRITES.get(),2);TARGET.set(23);
    DIGEST_PRESENT.set(false);check(0,0,Error::AccessDenied.into_raw());assert_eq!(WRITES.get(),2);DIGEST_PRESENT.set(true);
    IDENTITY.with_borrow_mut(|s|{let t=s.len();s.splice(t-1..t-1,format!("{EXECUTABLE_DIGEST_PREFIX}{}\0","0".repeat(64)).bytes());});
    check(0,0,Error::InvalidArgument.into_raw());assert_eq!(WRITES.get(),2);
    reset("spawn",b"");inherit_fields();GRANTED.set(0xffff_fffd);check(0,0,0);assert_eq!(WRITES.get(),1);
    reset("spawn",b"");inherit_fields();APP_PRESENT.set(false);check(0,0,Error::AccessDenied.into_raw());assert_eq!(WRITES.get(),0);
    for failure in [1,2]{reset("spawn",b"");inherit_fields();CLONE_FAIL.set(failure);check(0,0,Error::ResourceUnavailable.into_raw());assert_eq!(WRITES.get(),0);}
    reset("spawn",b"");inherit_fields();TARGET.set(41);check(123,0,0);assert_eq!(WRITES.get(),1);
    reset("spawn",b"");inherit_fields();GRANTED.set(2);check(0,0,Error::AccessDenied.into_raw());assert_eq!(WRITES.get(),0);
    reset("spawn",b"");inherit_fields();check(99,0,Error::InvalidArgument.into_raw());assert_eq!(WRITES.get(),0);
    reset("spawn",b"");inherit_fields();check(0,1,Error::InvalidArgument.into_raw());assert_eq!(WRITES.get(),0);
    reset("spawn",b"");inherit_fields();IDENTITY.with_borrow_mut(|s|{let t=String::from_utf8(s.clone()).unwrap().replace("unprivileged","privileged");*s=t.into_bytes()});check(0,0,Error::InvalidArgument.into_raw());assert_eq!(WRITES.get(),0);
    reset("image-replace-inherit",b"");check(0,0,Error::InvalidArgument.into_raw());assert_eq!(WRITES.get(),0);
    let n=reset("spawn",b"process.spawn\0");MANAGE.set(false);check(0,n,Error::AccessDenied.into_raw());assert_eq!(COPIES.get(),0);assert_eq!(WRITES.get(),0);
    for error in [Error::InvalidAddress,Error::BackingFailure,Error::ResourceUnavailable]{let n=reset("spawn",b"");COPY_ERROR.set(Some(error));check(0,n,error.into_raw());assert_eq!(WRITES.get(),0);}
    for field in ["unknown=bad","__MNU_EXEC_AUTH_KIND=bad"]{let n=reset("spawn",b"");IDENTITY.with_borrow_mut(|s|*s=field.as_bytes().to_vec());check(0,n,Error::InvalidArgument.into_raw());assert_eq!(WRITES.get(),0);}
    for missing in 0..4{let n=reset("spawn",b"");match missing{0=>THREAD.set(false),1=>OWNER.set(false),2=>PRESENT.set(false),_=>WRITABLE.set(false)};check(0,n,Error::NotReady.into_raw());assert_eq!(WRITES.get(),0);}
    let n=reset("spawn",b"");check(99,n,Error::InvalidArgument.into_raw());assert_eq!(WRITES.get(),0);
    for caps in [b"custom.unknown".as_slice(),b"memory.phys.map"]{let n=reset("spawn",caps);check(0,n,Error::InvalidArgument.into_raw());assert_eq!(WRITES.get(),0);}
    let n=reset("spawn",b"");GRANTED.set(0);check(0,n,Error::AccessDenied.into_raw());assert_eq!(WRITES.get(),0);
    for caps in [b"fs.read.all".as_slice(),b"memory.phys.map@0x1000:4096"]{let n=reset("image-replace",caps);GRANTED.set(0);AUTHORITY.set(0);check(0,n,Error::AccessDenied.into_raw());assert_eq!(WRITES.get(),0);}
    let n=reset("image-replace",b"custom.existing");GRANTED.set(4);check(0,n,0);assert_eq!(WRITES.get(),1);
    let n=reset("spawn",b"process.spawn");TARGET.set(41);check(123,n,0);assert_eq!(WRITES.get(),1);
    let n=reset("spawn",b"process.spawn");ALLOC_CALLS.set(0);check(0,n,0);let allocations=ALLOC_CALLS.get();assert!(allocations>10);
    for allocation in 0..allocations{WRITES.set(0);FAIL_AFTER.set(Some(allocation));check(0,n,Error::ResourceUnavailable.into_raw());assert_eq!(FAIL_AFTER.get(),None);assert_eq!(WRITES.get(),0);}
    assert_eq!(syscall::read_user_cstring(0,1),Err(Error::InvalidArgument));assert_eq!(syscall::read_user_cstring(100,0),Err(Error::InvalidArgument));assert_eq!(syscall::read_user_cstring(100,3),Err(Error::InvalidArgument));
    assert_eq!(syscall::read_user_cstring(111,2),Err(Error::InvalidArgument));
    COPIES.set(0);assert_eq!(syscall::read_user_cstring(u64::MAX,2),Err(Error::InvalidAddress));assert_eq!(COPIES.get(),1);
    assert_eq!(syscall::read_user_cstring(100,usize::MAX),Err(Error::ResourceUnavailable));
}
"#,
    );
    probe::run(&program);
}
