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
#[derive(Default)]struct KernelAuthoritySet{authorities:Vec<KernelAuthority>}
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
    program.push_str(&source[source.find("impl KernelAuthoritySet {").unwrap()..]);
    program.push_str(
        r#"
fn clear(){FAIL_AFTER.set(None);REGISTRY.with_borrow_mut(|r|r.names=Vec::new());}
fn main(){
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
}
"#,
    );
    probe::run(&program);
}
