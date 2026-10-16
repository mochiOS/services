//! Execute both export paths with real tables, rights and immutable snapshots.
#[allow(dead_code)]
#[path = "support/native_error_probe.rs"]
mod probe;

#[test]
fn native_exports_attenuate_exact_references_and_release_partial_grants_on_failure() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap();
    let table = include_str!("../../../core/src/task/handle_table.rs");
    let exec = include_str!("../../../core/src/syscall/exec.rs");
    let mut program = String::from(
        r#"
#![allow(dead_code)]
extern crate alloc;
extern crate self as mnu_abi;
use std::{cell::{Cell,RefCell},sync::{Arc,atomic::{AtomicBool,Ordering}}};
static FAIL_NEXT:AtomicBool=AtomicBool::new(false);
struct Allocator;
unsafe impl std::alloc::GlobalAlloc for Allocator {
    unsafe fn alloc(&self,layout:std::alloc::Layout)->*mut u8 {
        if FAIL_NEXT.swap(false,Ordering::Relaxed) {return std::ptr::null_mut();}
        unsafe {std::alloc::System.alloc(layout)}
    }
    unsafe fn dealloc(&self,p:*mut u8,layout:std::alloc::Layout) {
        unsafe {std::alloc::System.dealloc(p,layout)}
    }
}
#[global_allocator]static ALLOCATOR:Allocator=Allocator;
#[derive(Debug)]pub struct HandleInfo {pub handle:u32,pub reserved:u32,pub rights:u64}
"#,
    );
    program.push_str(&format!(
        "#[path={:?}]pub mod status;\n#[path={:?}]pub mod handle_snapshot;\n",
        root.join("core/crates/abi/src/status.rs"),
        root.join("core/crates/abi/src/handle_snapshot.rs")
    ));
    program.push_str(
        r#"
use status::Error;
mod task {
    pub mod handle_table {
        use alloc::{boxed::Box,collections::BTreeMap,sync::Arc};
        pub const PROCESS_MAX_OBJECT_HANDLES:usize=4096;
        #[derive(Clone)]pub enum KernelObject {Resource(Arc<u64>),HandleSnapshot(Arc<super::handle_snapshot::HandleSnapshot>)}
        impl std::fmt::Debug for KernelObject {
            fn fmt(&self,f:&mut std::fmt::Formatter<'_>)->std::fmt::Result {f.write_str("object")}
        }
"#,
    );
    program.push_str(probe::between(
        table,
        "#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]",
        "/// Kernel object identity",
    ));
    program.push_str(probe::between(
        table,
        "#[derive(Clone, Debug)]\npub struct ObjectHandleEntry",
        "#[cfg(test)]",
    ));
    program.push_str("}\n");
    program.push_str(&format!(
        "#[path={:?}]pub mod handle_snapshot;\n",
        root.join("core/src/task/handle_snapshot.rs")
    ));
    program.push_str(
        r#"
    pub use handle_table::{ObjectHandle,HandleRights,ObjectHandleEntry,KernelObject};
    pub type ProcessId=u64;
    pub struct Process {pub table:Box<handle_table::ObjectHandleTable>}
    impl Process {
        pub fn new()->Self {Self{table:handle_table::ObjectHandleTable::new_boxed()}}
        pub fn object_handles(&self)->&handle_table::ObjectHandleTable {assert!(crate::LOCKED.get());&self.table}
    }
    pub fn with_process<T>(id:u64,body:impl FnOnce(&Process)->T)->Option<T> {
        if id!=19 || !crate::PRESENT.get() {return None;}
        assert!(!crate::LOCKED.replace(true));
        let result=crate::PROCESS.with_borrow(body);assert!(crate::LOCKED.replace(false));Some(result)
    }
}
thread_local! {
    static CONTEXT:Cell<Option<u64>>=const {Cell::new(Some(19))};
    static PRESENT:Cell<bool>=const {Cell::new(true)};
    static LOCKED:Cell<bool>=const {Cell::new(false)};
    static PROCESS:RefCell<task::Process>=RefCell::new(task::Process::new());
}
use task::{ObjectHandle,HandleRights,ObjectHandleEntry,KernelObject};
mod syscall {
    pub mod security {pub fn current_process_id()->Option<u64> {crate::CONTEXT.get()}}
    pub mod handle {use crate::task::{ObjectHandle,HandleRights,KernelObject};
"#,
    );
    program.push_str(probe::between(
        include_str!("../../../core/src/syscall/handle.rs"),
        "pub(crate) fn object_native(",
        "pub(crate) fn object(",
    ));
    program.push_str("}}\n");
    program.push_str(probe::between(
        exec,
        "#[derive(Clone, Copy, Debug, PartialEq, Eq)]\nstruct InheritedHandleSpec",
        "#[derive(Clone, Copy, Debug, PartialEq, Eq)]\nstruct InheritedValueSpec",
    ));
    program.push_str("mod production {use crate::{InheritedHandleSpec,InheritedHandleGrant};\n");
    program.push_str(probe::between(
        exec,
        "fn export_inherited_handles(",
        "fn install_inherited_handles(",
    ));
    program.push_str("mod captured_handles {\n");
    program.push_str(include_str!(
        "../../../core/src/syscall/exec/captured_handles.rs"
    ));
    program.push_str(
        r#"
    }
    pub fn live(owner:Option<u64>,specs:&[InheritedHandleSpec])->Result<Vec<InheritedHandleGrant>,crate::Error> {export_inherited_handles(owner,specs)}
    pub fn captured(handle:u64,specs:&[InheritedHandleSpec])->Result<Vec<InheritedHandleGrant>,crate::Error> {captured_handles::export(handle,specs)}
}
fn spec(source:u32,rights:HandleRights)->InheritedHandleSpec {
    InheritedHandleSpec{key:u64::MAX,source:ObjectHandle::from_raw(source).unwrap(),target:41,rights}
}
fn object(entry:&ObjectHandleEntry)->&Arc<u64> {match entry.object() {KernelObject::Resource(value)=>value,_=>panic!("wrong object")}}
fn main() {
    let original=Arc::new(17);let private=Arc::new(29);
    let full=HandleRights::READ.union(HandleRights::WRITE).union(HandleRights::TRANSFER);
    PROCESS.with_borrow_mut(|p|{
        for (raw,rights) in [(7,full),(8,HandleRights::READ.union(HandleRights::DUPLICATE)),(10,HandleRights::CONTROL)] {
            let resource=if raw==8 {private.clone()} else {original.clone()};
            assert!(p.table.insert_at(ObjectHandle::from_raw(raw).unwrap(),ObjectHandleEntry::new(KernelObject::Resource(resource),rights)));
        }
    });
    let snapshot=PROCESS.with_borrow(|p|Arc::new(p.table.capture().unwrap()));
    PROCESS.with_borrow_mut(|p|{
        assert!(p.table.insert_at(ObjectHandle::from_raw(31).unwrap(),ObjectHandleEntry::new(KernelObject::HandleSnapshot(snapshot.clone()),HandleRights::CONTROL)));
        assert!(p.table.insert_at(ObjectHandle::from_raw(32).unwrap(),ObjectHandleEntry::new(KernelObject::HandleSnapshot(snapshot.clone()),HandleRights::READ)));
    });
    assert_eq!(Arc::strong_count(&private),2,"nontransferable metadata cannot pin a resource");
    let read=[spec(7,HandleRights::READ)];
    for captured in [false,true] {
        let export=|specs:&[InheritedHandleSpec]| if captured {production::captured(31,specs)} else {production::live(Some(19),specs)};
        for rights in [HandleRights::empty(),HandleRights::READ,HandleRights::WRITE] {
            let before=Arc::strong_count(&original);
            let grants=export(&[spec(7,rights)]).unwrap();
            assert_eq!(grants.len(),1);assert_eq!((grants[0].key,grants[0].target),(u64::MAX,41));
            assert_eq!(grants[0].entry.rights(),rights);assert!(Arc::ptr_eq(object(&grants[0].entry),&original));
            assert_eq!(Arc::strong_count(&original),before+1);drop(grants);
            assert_eq!(Arc::strong_count(&original),before);
        }
        // Every failure follows an already-exported good reference. Its
        // temporary owner must be dropped, not installed or returned partially.
        for (last,error) in [(spec(9,HandleRights::empty()),Error::InvalidArgument),
            (spec(8,HandleRights::empty()),Error::AccessDenied),
            (spec(8,HandleRights::READ),Error::AccessDenied),
            (spec(7,HandleRights::CONTROL),Error::AccessDenied),
            (spec(7,HandleRights::DUPLICATE),Error::AccessDenied)] {
            let before=Arc::strong_count(&original);let pins=Arc::strong_count(&snapshot);
            assert!(matches!(export(&[read[0],last]),Err(actual) if actual==error));
            assert_eq!(Arc::strong_count(&original),before);assert_eq!(Arc::strong_count(&snapshot),pins);
        }
        let before=Arc::strong_count(&original);let pins=Arc::strong_count(&snapshot);
        FAIL_NEXT.store(true,Ordering::Relaxed);
        assert!(matches!(export(&read),Err(Error::ResourceUnavailable)));
        assert!(!FAIL_NEXT.load(Ordering::Relaxed));
        assert_eq!(Arc::strong_count(&original),before);assert_eq!(Arc::strong_count(&snapshot),pins);
    }
    for raw in [0,1u64<<32,(1u64<<32)|31,u64::MAX,99,10] {
        assert!(matches!(production::captured(raw,&read),Err(Error::InvalidArgument)));
    }
    assert!(matches!(production::captured(32,&read),Err(Error::AccessDenied)));
    assert!(matches!(production::live(None,&read),Err(Error::NotReady)));
    assert!(matches!(production::live(Some(20),&read),Err(Error::NotReady)));
    PRESENT.set(false);
    assert!(matches!(production::live(Some(19),&read),Err(Error::NotReady)));
    assert!(matches!(production::captured(31,&read),Err(Error::NotReady)));PRESENT.set(true);
    CONTEXT.set(None);assert!(matches!(production::captured(31,&read),Err(Error::NotReady)));CONTEXT.set(Some(19));
    // Empty live export needs neither a process nor an allocation. Snapshot
    // export still requires possession and CONTROL even for an empty plan.
    FAIL_NEXT.store(true,Ordering::Relaxed);assert!(production::live(None,&[]).unwrap().is_empty());
    assert!(FAIL_NEXT.swap(false,Ordering::Relaxed));
    assert!(matches!(production::captured(32,&[]),Err(Error::AccessDenied)));
    let replacement=Arc::new(47);
    PROCESS.with_borrow_mut(|p|{
        assert!(p.table.close(ObjectHandle::from_raw(7).unwrap()));
        assert!(p.table.insert_at(ObjectHandle::from_raw(7).unwrap(),ObjectHandleEntry::new(KernelObject::Resource(replacement.clone()),full)));
    });
    let old=production::captured(31,&read).unwrap();let live=production::live(Some(19),&read).unwrap();
    assert!(Arc::ptr_eq(object(&old[0].entry),&original));assert!(Arc::ptr_eq(object(&live[0].entry),&replacement));
    drop(old);drop(live);drop(snapshot);
    PROCESS.with_borrow_mut(|p|{p.table.retain(|_|false);});
    assert_eq!(Arc::strong_count(&original),1);assert_eq!(Arc::strong_count(&replacement),1);assert_eq!(Arc::strong_count(&private),1);
}
"#,
    );
    probe::run(&program);
}
