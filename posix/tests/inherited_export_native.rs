//! Execute export and installation with real tables, snapshots and contexts.
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
    use alloc::sync::Arc;
    pub mod handle_table {
        use alloc::{boxed::Box,collections::BTreeMap,sync::Arc};
        pub const PROCESS_MAX_OBJECT_HANDLES:usize=4096;
        #[derive(Clone)]pub enum KernelObject {Resource(Arc<u64>),Process(Arc<u64>),HandleSnapshot(Arc<super::handle_snapshot::HandleSnapshot>)}
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
    program.push_str("pub mod launch_context {\n");
    let context = include_str!("../../../core/src/task/launch_context.rs");
    program.push_str(
        &context[..context
            .find("    /// Prepare a replacement off to the side.")
            .unwrap()],
    );
    program.push_str("}}\n");
    program.push_str(
        r#"
    pub use handle_table::{ObjectHandle,HandleRights,ObjectHandleEntry,KernelObject};
    pub type ProcessId=u64;
    pub struct Process {pub table:Box<handle_table::ObjectHandleTable>,launch:Box<launch_context::LaunchContext>,published:bool,pub fail_context:bool,pub token:Arc<u64>}
    impl Process {
        pub fn new()->Self {let mut process=Self::unpublished();process.published=true;process}
        pub fn unpublished()->Self {Self{table:handle_table::ObjectHandleTable::new_boxed(),launch:launch_context::LaunchContext::new_boxed(),published:false,fail_context:false,token:Arc::new(999)}}
        pub fn process_object(&self)->Arc<u64> {self.token.clone()}
        pub fn object_handles(&self)->&handle_table::ObjectHandleTable {assert!(!self.published || crate::LOCKED.get());&self.table}
        pub fn object_handles_mut(&mut self)->&mut handle_table::ObjectHandleTable {assert!(!self.published || crate::LOCKED.get());&mut self.table}
        pub fn launch_context(&self)->&launch_context::LaunchContext {&self.launch}
        pub fn launch_context_mut(&mut self)->&mut launch_context::LaunchContext {
            assert!(!self.published || crate::LOCKED.get());
            if self.fail_context {self.fail_context=false;crate::FAIL_NEXT.store(true,crate::Ordering::Relaxed);}
            &mut self.launch
        }
    }
    pub fn with_process<T>(id:u64,body:impl FnOnce(&Process)->T)->Option<T> {
        if id!=19 || !crate::PRESENT.get() {return None;}
        assert!(!crate::LOCKED.replace(true));
        let result=crate::PROCESS.with_borrow(body);assert!(crate::LOCKED.replace(false));Some(result)
    }
    pub fn with_process_mut<T>(id:u64,body:impl FnOnce(&mut Process)->T)->Option<T> {
        if id!=19 || !crate::PRESENT.get() {return None;}
        assert!(!crate::LOCKED.replace(true));
        let result=crate::PROCESS.with_borrow_mut(body);assert!(crate::LOCKED.replace(false));Some(result)
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
    pub mod handle {use crate::task::{ObjectHandle,HandleRights,KernelObject,ObjectHandleEntry};const SUCCESS:u64=0;
"#,
    );
    program.push_str(probe::between(
        include_str!("../../../core/src/syscall/handle.rs"),
        "pub(crate) fn object_native(",
        "pub(crate) fn object(",
    ));
    let handle_source = include_str!("../../../core/src/syscall/handle.rs");
    program.push_str(probe::between(
        handle_source,
        "pub fn close(",
        "pub fn duplicate(",
    ));
    program.push_str(probe::between(
        handle_source,
        "const PROCESS_HANDLE_RIGHTS:",
        "fn insert_process_handle(",
    ));
    program.push_str("}\npub fn retain(target:&crate::task::Process)->Result<u64,crate::Error>{handle::retain_created_process(target)}\n}\n");
    program.push_str(probe::between(
        exec,
        "struct CreatedProcessHandle(",
        "impl UserPageTableGuard {",
    ));
    program.push_str(probe::between(
        exec,
        "#[derive(Clone, Copy, Debug, PartialEq, Eq)]\nstruct InheritedHandleSpec",
        "struct InitialUserStack",
    ));
    program.push_str("mod production {use crate::{InheritedHandleSpec,InheritedHandleGrant,InheritedValueSpec};\n");
    program.push_str(probe::between(
        exec,
        "fn export_inherited_handles(",
        "fn install_inherited_handles(",
    ));
    program.push_str(probe::between(
        exec,
        "fn install_inherited_handles(",
        "fn valid_security_identity(",
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
    pub fn install_handles(process:&mut crate::task::Process,grants:&[InheritedHandleGrant])->Result<(),crate::Error> {install_inherited_handles(process,grants)}
    pub fn install_values(process:&mut crate::task::Process,values:&[InheritedValueSpec])->Result<(),crate::Error> {install_inherited_values(process,values)}
}
fn spec(source:u32,rights:HandleRights)->InheritedHandleSpec {
    InheritedHandleSpec{key:u64::MAX,source:ObjectHandle::from_raw(source).unwrap(),target:41,rights}
}
fn object(entry:&ObjectHandleEntry)->&Arc<u64> {match entry.object() {KernelObject::Resource(value)=>value,_=>panic!("wrong object")}}
fn retention_cases() {
    let target=task::Process::unpublished();let before=Arc::strong_count(&target.token);
    CONTEXT.set(None);assert_eq!(syscall::retain(&target),Err(Error::NotReady));CONTEXT.set(Some(19));
    assert_eq!(Arc::strong_count(&target.token),before);
    PRESENT.set(false);assert_eq!(syscall::retain(&target),Err(Error::NotReady));PRESENT.set(true);
    assert_eq!(Arc::strong_count(&target.token),before);
    let filler=Arc::new(123);
    PROCESS.with_borrow_mut(|p|{
        for raw in 1..=task::handle_table::PROCESS_MAX_OBJECT_HANDLES as u32 {
            assert!(p.table.insert_at(ObjectHandle::from_raw(raw).unwrap(),ObjectHandleEntry::new(KernelObject::Resource(filler.clone()),HandleRights::empty())));
        }
    });
    FAIL_NEXT.store(true,Ordering::Relaxed);
    assert_eq!(syscall::retain(&target),Err(Error::ResourceUnavailable));
    assert!(FAIL_NEXT.swap(false,Ordering::Relaxed),"full-table rejection must not allocate");
    assert_eq!(Arc::strong_count(&target.token),before);
    PROCESS.with_borrow_mut(|p|p.table.retain(|_|false));assert_eq!(Arc::strong_count(&filler),1);
    drop(target);
    for handoff in [false,true] {
        let target=task::Process::unpublished();let weak=Arc::downgrade(&target.token);
        let raw=syscall::retain(&target).unwrap();let selector=ObjectHandle::from_raw(raw as u32).unwrap();
        PROCESS.with_borrow(|p|{
            assert_eq!(p.table.describe().len(),1,"retention installs only the new reference");
            let entry=p.table.get(selector).unwrap();
            assert_eq!(entry.rights(),HandleRights::WAIT.union(HandleRights::SIGNAL).union(HandleRights::DUPLICATE).union(HandleRights::TRANSFER));
            match entry.object() {KernelObject::Process(object)=>assert!(Arc::ptr_eq(object,&target.token)),_=>panic!("wrong target")}
        });
        drop(target);assert!(weak.upgrade().is_some());
        let mut guard=CreatedProcessHandle(Some(raw));
        if handoff {assert_eq!(guard.0.take(),Some(raw));}
        drop(guard);
        if handoff {
            assert!(weak.upgrade().is_some(),"handoff must not close a published reference");
            assert_eq!(syscall::handle::close(raw),0);
        }
        assert!(weak.upgrade().is_none(),"a failed creation guard must release its reference");
        PROCESS.with_borrow(|p|assert_eq!(p.table.describe().len(),0));
    }
}
fn grant(key:u64,target:u32,entry:&ObjectHandleEntry)->InheritedHandleGrant {InheritedHandleGrant{key,target,entry:entry.clone()}}
fn install_plan(grants:&[InheritedHandleGrant],values:&[InheritedValueSpec],fail_context:bool)->Result<task::Process,Error> {
    let mut destination=task::Process::unpublished();destination.fail_context=fail_context;
    production::install_handles(&mut destination,grants)?;
    production::install_values(&mut destination,values)?;
    Ok(destination)
}
fn install_cases(entry:&ObjectHandleEntry) {
    let resource=object(entry);let baseline=Arc::strong_count(resource);
    // Automatic placement is deliberately serialized first. Explicit slot 1
    // must still be reserved before that automatic allocation takes slot 2.
    let grants=[grant(10,0,entry),grant(11,1,&ObjectHandleEntry::new(KernelObject::Resource(resource.clone()),HandleRights::empty()))];
    let values=[InheritedValueSpec{key:10,value:Error::NotFound.into_raw()},InheritedValueSpec{key:u64::MAX,value:u64::MAX}];
    let destination=install_plan(&grants,&values,false).unwrap();
    assert_eq!(destination.launch_context().get(10),ObjectHandle::from_raw(2));
    assert_eq!(destination.launch_context().get(11),ObjectHandle::from_raw(1));
    assert_eq!(destination.launch_context().value(10),Some(Error::NotFound.into_raw()));
    assert_eq!(destination.launch_context().value(u64::MAX),Some(u64::MAX));
    assert_eq!(destination.table.describe().len(),2,"never implicitly copy the creator table");
    assert_eq!(destination.table.get(ObjectHandle::from_raw(1).unwrap()).unwrap().rights(),HandleRights::empty());
    assert_eq!(destination.table.get(ObjectHandle::from_raw(2).unwrap()).unwrap().rights(),entry.rights());
    drop(destination);let pins=Arc::strong_count(resource);
    for (failed,expected) in [
        ([grant(1,1,entry),grant(2,4097,entry)],Error::InvalidArgument),
        ([grant(1,1,entry),grant(2,1,entry)],Error::AlreadyExists),
        ([grant(1,1,entry),grant(1,2,entry)],Error::AlreadyExists),
    ] {
        let before=Arc::strong_count(resource);
        assert!(matches!(install_plan(&failed,&[],false),Err(error) if error==expected));
        assert_eq!(Arc::strong_count(resource),before,"drop every partial destination reference");
    }
    assert_eq!(Arc::strong_count(resource),pins);
    assert!(matches!(install_plan(&grants,&[],true),Err(Error::ResourceUnavailable)));
    assert!(!FAIL_NEXT.load(Ordering::Relaxed));assert_eq!(Arc::strong_count(resource),pins);
    // The same failure for scalar storage also drops previously installed Handles.
    let mut destination=task::Process::unpublished();
    production::install_handles(&mut destination,&grants).unwrap();destination.fail_context=true;
    assert_eq!(production::install_values(&mut destination,&values),Err(Error::ResourceUnavailable));
    assert!(!FAIL_NEXT.load(Ordering::Relaxed));drop(destination);assert_eq!(Arc::strong_count(resource),pins);
    let duplicate=[InheritedValueSpec{key:7,value:1},InheritedValueSpec{key:7,value:2}];
    assert!(matches!(install_plan(&grants,&duplicate,false),Err(Error::AlreadyExists)));
    assert_eq!(Arc::strong_count(resource),pins);
    // Duplicate keys must not install an orphan selector or replace rights.
    let mut destination=task::Process::unpublished();
    production::install_handles(&mut destination,&grants[..1]).unwrap();
    assert_eq!(production::install_handles(&mut destination,&[grant(10,3,entry)]),Err(Error::AlreadyExists));
    assert_eq!(destination.table.describe().len(),1);drop(destination);
    // Full table exhaustion differs from a duplicate explicit target.
    let mut destination=task::Process::unpublished();
    for raw in 1..=task::handle_table::PROCESS_MAX_OBJECT_HANDLES as u32 {
        assert!(destination.table.insert_at(ObjectHandle::from_raw(raw).unwrap(),entry.clone()));
    }
    assert_eq!(production::install_handles(&mut destination,&[grant(1,0,entry)]),Err(Error::ResourceUnavailable));
    assert_eq!(production::install_handles(&mut destination,&[grant(1,1,entry)]),Err(Error::AlreadyExists));
    drop(destination);assert_eq!(Arc::strong_count(resource),pins);
    let mut context=task::launch_context::LaunchContext::new_boxed();
    let handle=ObjectHandle::from_raw(7).unwrap();
    FAIL_NEXT.store(true,Ordering::Relaxed);assert_eq!(context.install(0,handle),Err(Error::ResourceUnavailable));
    assert_eq!(context.get(0),None);
    FAIL_NEXT.store(true,Ordering::Relaxed);assert_eq!(context.install_value(0,42),Err(Error::ResourceUnavailable));
    assert_eq!(context.value(0),None);
    for key in 0..256 {context.install(key,handle).unwrap();context.install_value(key,key).unwrap();}
    assert_eq!(context.install(256,handle),Err(Error::ResourceUnavailable));
    assert_eq!(context.install_value(256,1),Err(Error::ResourceUnavailable));
    FAIL_NEXT.store(true,Ordering::Relaxed);assert_eq!(context.install(0,handle),Err(Error::AlreadyExists));
    assert!(FAIL_NEXT.swap(false,Ordering::Relaxed));
    FAIL_NEXT.store(true,Ordering::Relaxed);assert_eq!(context.install_value(0,99),Err(Error::AlreadyExists));
    assert!(FAIL_NEXT.swap(false,Ordering::Relaxed));assert_eq!(context.value(0),Some(0));
    drop(grants);assert_eq!(Arc::strong_count(resource),baseline);
}
fn main() {
    let original=Arc::new(17);let private=Arc::new(29);
    let full=HandleRights::READ.union(HandleRights::WRITE).union(HandleRights::TRANSFER);
    PROCESS.with_borrow_mut(|p|{
        for (raw,rights) in [(7,full),(8,HandleRights::READ.union(HandleRights::DUPLICATE)),(10,HandleRights::CONTROL)] {
            let resource=if raw==8 {private.clone()} else {original.clone()};
            assert!(p.table.insert_at(ObjectHandle::from_raw(raw).unwrap(),ObjectHandleEntry::new(KernelObject::Resource(resource),rights)));
        }
    });
    // Native lookup returns the retained object and its exact rights from one
    // table access; asking for READ must not attenuate or invent other bits.
    let before=Arc::strong_count(&original);
    let (retained,rights)=syscall::handle::object_with_rights_native(7,HandleRights::READ).unwrap();
    assert_eq!(rights,full);assert_eq!(Arc::strong_count(&original),before+1);
    match &retained {KernelObject::Resource(resource)=>assert!(Arc::ptr_eq(resource,&original)),_=>panic!("wrong object")}
    drop(retained);assert_eq!(Arc::strong_count(&original),before);
    assert!(matches!(syscall::handle::object_with_rights_native(7,HandleRights::CONTROL),Err(Error::AccessDenied)));
    assert!(matches!(syscall::handle::object_with_rights_native(99,HandleRights::READ),Err(Error::InvalidArgument)));
    CONTEXT.set(None);assert!(matches!(syscall::handle::object_with_rights_native(7,HandleRights::READ),Err(Error::NotReady)));CONTEXT.set(Some(19));
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
    install_cases(&old[0].entry);
    PROCESS.with_borrow(|p|assert_eq!(p.launch_context().get(10),None));
    drop(old);drop(live);drop(snapshot);
    PROCESS.with_borrow_mut(|p|{p.table.retain(|_|false);});
    assert_eq!(Arc::strong_count(&original),1);assert_eq!(Arc::strong_count(&replacement),1);assert_eq!(Arc::strong_count(&private),1);
    retention_cases();
}
"#,
    );
    probe::run(&program);
}
