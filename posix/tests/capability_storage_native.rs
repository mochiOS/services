//! Actual capability registration and authority storage; only registry locking
//! is replaced with a host-local borrow. No scheduler/interrupt claim is made.
#[allow(dead_code)]
#[path = "support/native_error_probe.rs"]
mod probe;

#[test]
fn registration_and_authority_insertion_publish_only_after_fallible_preparation() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap();
    let mut program = String::from("#![allow(dead_code,unused_attributes)]\nextern crate alloc;\n");
    program.push_str(&format!(
        "extern crate self as mnu_abi;\n#[path={:?}]mod abi;\npub use abi::*;\n",
        root.join("core/crates/abi/src/lib.rs")
    ));
    program.push_str(
        r#"
use std::{cell::{Cell,RefCell},sync::atomic::{AtomicUsize,Ordering}};
use status::Error;
thread_local! {
    static FAIL_AFTER:Cell<Option<usize>>=const {Cell::new(None)};
    static REGISTRY:RefCell<DynamicCapabilityRegistry>=const {RefCell::new(DynamicCapabilityRegistry{names:Vec::new()})};
}
static LIVE:AtomicUsize=AtomicUsize::new(0);
struct Allocator;
unsafe impl std::alloc::GlobalAlloc for Allocator {
    unsafe fn alloc(&self,layout:std::alloc::Layout)->*mut u8 {
        if FAIL_AFTER.with(|s|match s.get(){Some(0)=>{s.set(None);true},Some(n)=>{s.set(Some(n-1));false},None=>false}) {return std::ptr::null_mut();}
        let p=unsafe{std::alloc::System.alloc(layout)};if !p.is_null(){LIVE.fetch_add(1,Ordering::Relaxed);}p
    }
    unsafe fn dealloc(&self,p:*mut u8,layout:std::alloc::Layout){LIVE.fetch_sub(1,Ordering::Relaxed);unsafe{std::alloc::System.dealloc(p,layout)}}
}
#[global_allocator]static ALLOCATOR:Allocator=Allocator;
fn with_dynamic_registry<R>(body:impl FnOnce(&mut DynamicCapabilityRegistry)->R)->R {REGISTRY.with_borrow_mut(body)}
"#,
    );
    let source = include_str!("../../../core/src/capability/mod.rs");
    for (start, end) in [
        (
            "/// kernel が直接強制する低レベル権限",
            "/// mnu が直接強制する権限",
        ),
        ("/// mnu が直接強制する権限", "static DYNAMIC_CAPABILITIES:"),
        ("fn valid_capability_name(", "/// `parent` が、"),
    ] {
        program.push_str(probe::between(source, start, end));
    }
    program.push_str(&source[source.find("/// `parent` が、").unwrap()..]);
    program.push_str(probe::between(
        include_str!("../../../core/src/syscall/exec.rs"),
        "fn parse_requested_exec_grants(",
        "fn export_inherited_handles(",
    ));
    program.push_str(
        r#"
mod task {
    #[derive(Clone,Copy,Debug)]pub struct ThreadId(pub u64);
    #[derive(Clone,Copy,PartialEq)]pub enum PrivilegeLevel{User,Service}
    pub mod process {
        use crate::{CapabilitySet,KernelAuthoritySet};
        // Match the kernel module's single-parameter Result alias context.
        type Result<T> = core::result::Result<T, ()>;
        #[derive(Clone,Copy,Debug,PartialEq,Eq)]pub enum ApplicationProvenance{BuiltIn,VerifiedPackage,Development}
"#,
    );
    program.push_str(probe::between(
        include_str!("../../../core/src/task/process.rs"),
        "#[derive(Clone, Debug, PartialEq, Eq)]\npub struct ApplicationIdentity",
        "/// プロセス構造体",
    ));
    program.push_str(
        r#"
    }
    pub struct Process{pub identity:Option<process::ApplicationIdentity>,pub digest:Option<[u8;32]>,pub caps:crate::CapabilitySet,pub authorities:crate::KernelAuthoritySet}
    impl Process {
        pub fn application_identity(&self)->Option<&process::ApplicationIdentity>{self.identity.as_ref()}
        pub fn image_digest(&self)->Option<[u8;32]>{self.digest}
        pub fn capabilities(&self)->&crate::CapabilitySet{&self.caps}
        pub fn kernel_authorities(&self)->&crate::KernelAuthoritySet{&self.authorities}
        pub fn privilege(&self)->PrivilegeLevel{PrivilegeLevel::User}
    }
}
use task::{Process,PrivilegeLevel};use task::process;
pub mod capability {pub use crate::abi::capability::*;pub use crate::{CapabilitySet,KernelAuthoritySet};}
"#,
    );
    program.push_str(&format!(
        "#[path={:?}]mod origin;\n",
        root.join("core/src/task/image_origin.rs")
    ));
    program.push_str(
        r#"
fn clear(){FAIL_AFTER.set(None);REGISTRY.with_borrow_mut(|r|r.names=Vec::new());}
fn main(){
    {
        let scoped=Capability::try_intern("device.storage.scoped").unwrap();
        let writable=Capability::try_intern("device.storage.scoped.write").unwrap();
        assert!(!capability_implies(writable,Capability::DeviceStorage));
        assert!(!capability_implies(scoped,writable));
        let mut granted=CapabilitySet::empty();
        granted.try_insert(scoped).unwrap();
        granted.try_insert(Capability::FsReadAll).unwrap();
        granted.try_insert(Capability::FsWriteAll).unwrap();
        assert!(granted.contains(scoped));
        assert!(!granted.contains(Capability::DeviceStorage));
        assert!(!capability_implies(scoped,Capability::DeviceStorage));
        let metadata=capability::metadata("device.storage.scoped").unwrap();
        assert_eq!(metadata.classification,capability::CapabilityClassification::Privileged);
        assert!(!metadata.delegable);
        assert!(!metadata.user_grantable);
        let (requested,authorities)=parse_requested_exec_grants(&["device.storage.scoped".into()]).unwrap();
        assert!(requested.contains(scoped));
        assert!(!requested.contains(Capability::DeviceStorage));
        assert!(authorities.is_empty());
    }
    for invalid in ["","Bad.Name","bad..name","trailing."] {
        assert_eq!(Capability::try_intern(invalid),Err(Error::InvalidArgument));
    }
    clear();FAIL_AFTER.set(Some(0));assert_eq!(Capability::try_intern("process.spawn"),Ok(Capability::ProcessSpawn));
    assert_eq!(FAIL_AFTER.get(),Some(0));FAIL_AFTER.set(None);
    for allocation in 0..2 {
        clear();let live=LIVE.load(Ordering::Relaxed);FAIL_AFTER.set(Some(allocation));
        assert_eq!(Capability::try_intern("custom.permission"),Err(Error::ResourceUnavailable));
        assert_eq!(FAIL_AFTER.get(),None);assert_eq!(LIVE.load(Ordering::Relaxed),live);
        assert!(REGISTRY.with_borrow(|r|r.names.is_empty()));assert_eq!(Capability::from_str("custom.permission"),None);
        assert_eq!(Capability::try_intern("custom.permission"),Ok(Capability::Dynamic(0)));
        FAIL_AFTER.set(Some(0));assert_eq!(Capability::try_intern("custom.permission"),Ok(Capability::Dynamic(0)));
        assert_eq!(FAIL_AFTER.get(),Some(0));FAIL_AFTER.set(None);assert_eq!(REGISTRY.with_borrow(|r|r.names.len()),1);
    }
    clear();FAIL_AFTER.set(Some(0));assert_eq!(Capability::intern("custom.permission"),None);assert!(REGISTRY.with_borrow(|r|r.names.is_empty()));
    REGISTRY.with_borrow_mut(|r|{r.names=vec![String::new();4096];r.names[7]="existing.permission".into();});
    assert_eq!(Capability::try_intern("overflow.permission"),Err(Error::LimitExceeded));
    assert_eq!(Capability::try_intern("existing.permission"),Ok(Capability::Dynamic(7)));clear();
    let first=parse_kernel_authority_spec("memory.phys.map@0x1000:4096").unwrap();
    let second=parse_kernel_authority_spec("memory.phys.map@0x3000:4096").unwrap();
    let mut set=KernelAuthoritySet::empty();FAIL_AFTER.set(Some(0));assert_eq!(set.try_insert(first),Err(Error::ResourceUnavailable));assert!(set.is_empty());
    set.try_insert(first).unwrap();assert_eq!(set.len(),1);
    FAIL_AFTER.set(Some(0));assert_eq!(set.try_insert(first),Ok(()));assert_eq!(FAIL_AFTER.get(),Some(0));FAIL_AFTER.set(None);
    set.authorities.shrink_to_fit();FAIL_AFTER.set(Some(0));assert_eq!(set.try_insert(second),Err(Error::ResourceUnavailable));
    assert!(set.contains_exact(&first));assert!(!set.contains_exact(&second));assert_eq!(set.len(),1);
    set.try_insert(second).unwrap();assert_eq!(set.len(),2);
    let mut caps=CapabilitySet::empty();FAIL_AFTER.set(Some(0));assert_eq!(caps.try_insert(Capability::ProcessSpawn),Err(Error::ResourceUnavailable));assert!(caps.is_empty());
    caps.try_insert(Capability::ProcessSpawn).unwrap();FAIL_AFTER.set(Some(0));assert_eq!(caps.try_insert(Capability::ProcessSpawn),Ok(()));assert_eq!(FAIL_AFTER.get(),Some(0));FAIL_AFTER.set(None);
    caps.caps.shrink_to_fit();FAIL_AFTER.set(Some(0));assert_eq!(caps.try_insert(Capability::FsReadAll),Err(Error::ResourceUnavailable));assert_eq!(caps.iter().collect::<Vec<_>>(),[Capability::ProcessSpawn]);
    // Compare mixed insertion/removal and ordering with the previous backing.
    let mut oracle=std::collections::BTreeSet::new();let mut sorted=CapabilitySet::empty();
    for step in 0..2000u32 {
        let cap=if step%3==0 {Capability::ProcessSpawn}else{Capability::Dynamic((step*17)%257)};
        if step%5==0 {assert_eq!(sorted.remove(cap),oracle.remove(&cap));}else if step%2==0{sorted.insert(cap);oracle.insert(cap);}else{sorted.try_insert(cap).unwrap();oracle.insert(cap);}
        assert_eq!(sorted.iter().collect::<Vec<_>>(),oracle.iter().copied().collect::<Vec<_>>());assert_eq!(sorted.contains_exact(cap),oracle.contains(&cap));assert_eq!(sorted.len(),oracle.len());
    }
    let mut parent=CapabilitySet::empty();parent.try_insert(Capability::FsReadAll).unwrap();
    let mut child=CapabilitySet::empty();child.try_insert(Capability::FsReadTmp).unwrap();child.try_insert(Capability::FsReadRemovable).unwrap();
    assert!(child.is_subset_of(&parent));assert!(!parent.contains(Capability::FsWriteTmp));
    child.try_insert(Capability::Dynamic(100)).unwrap();assert!(!child.is_subset_of(&parent));parent.try_insert(Capability::Unsandboxed).unwrap();assert!(child.is_subset_of(&parent));
    let requests=vec!["process.spawn".to_string(),"memory.phys.map@0x1000:4096".to_string()];
    for allocation in 0..2 {let live=LIVE.load(Ordering::Relaxed);FAIL_AFTER.set(Some(allocation));assert_eq!(parse_requested_exec_grants(&requests).err(),Some(Error::ResourceUnavailable));assert_eq!(FAIL_AFTER.get(),None);assert_eq!(LIVE.load(Ordering::Relaxed),live);}
    let (caps,authorities)=parse_requested_exec_grants(&requests).unwrap();assert!(caps.contains_exact(Capability::ProcessSpawn));assert_eq!(caps.len(),1);assert!(authorities.contains_exact(&first));assert_eq!(authorities.len(),1);
    let mut process=Process{identity:Some(process::ApplicationIdentity::new("app.example".into(),"developer".into(),[7;32],process::ApplicationProvenance::BuiltIn)),digest:Some([9;32]),caps:caps.try_clone().unwrap(),authorities:authorities.try_clone().unwrap()};
    for allocation in 0..4 {let live=LIVE.load(Ordering::Relaxed);FAIL_AFTER.set(Some(allocation));assert_eq!(origin::ImageOrigin::capture(&process).err(),Some(Error::ResourceUnavailable));assert_eq!(FAIL_AFTER.get(),None);assert_eq!(LIVE.load(Ordering::Relaxed),live);assert!(process.caps.contains_exact(Capability::ProcessSpawn));assert!(process.authorities.contains_exact(&first));}
    let captured=origin::ImageOrigin::capture(&process).unwrap().unwrap();
    let mut authorization=process::PendingExecSecurity{path:String::new(),authorized_thread:task::ThreadId(23),executable_digest:[9;32],capabilities:process.caps.try_clone().unwrap(),kernel_authorities:process.authorities.try_clone().unwrap(),identity:process.identity.as_ref().unwrap().try_clone().unwrap(),kind:process::PendingExecKind::Spawn,execution_class:mnu_abi::exec::ExecutionClass::Unprivileged};
    process.caps.remove(Capability::ProcessSpawn);process.authorities.remove_exact(&first);process.identity=None;process.digest=None;
    assert!(captured.permits(&authorization));authorization.capabilities.try_insert(Capability::FsReadAll).unwrap();assert!(!captured.permits(&authorization));
    FAIL_AFTER.set(Some(0));assert!(origin::ImageOrigin::capture(&process).unwrap().is_none());assert_eq!(FAIL_AFTER.get(),Some(0));FAIL_AFTER.set(None);
    FAIL_AFTER.set(Some(0));assert!(CapabilitySet::empty().try_clone().unwrap().is_empty());assert!(KernelAuthoritySet::empty().try_clone().unwrap().is_empty());assert_eq!(FAIL_AFTER.get(),Some(0));FAIL_AFTER.set(None);
}
"#,
    );
    probe::run(&program);
}
