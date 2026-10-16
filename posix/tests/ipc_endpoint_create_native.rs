#[allow(dead_code)]
#[path = "support/native_error_probe.rs"]
mod probe;

#[test]
fn endpoint_creation_uses_native_errors_and_grants_only_existing_capability_authority() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap();
    let mut program = format!(
        r#"
#![allow(dead_code,unused_imports)]
extern crate alloc;
extern crate self as mnu_abi;
#[path={status:?}]pub mod status;
#[path={wire:?}]pub mod handle_snapshot;
use status::Error;
use std::cell::{{Cell,RefCell}};
#[derive(Debug)]pub struct HandleInfo{{pub handle:u32,pub reserved:u32,pub rights:u64}}
thread_local!{{
    static CONTEXT:Cell<bool>=const{{Cell::new(true)}};
    static THREAD:Cell<bool>=const{{Cell::new(true)}};
    static ENDPOINT:Cell<bool>=const{{Cell::new(true)}};
    static PROCESS:Cell<bool>=const{{Cell::new(true)}};
    static REGISTRY:Cell<bool>=const{{Cell::new(true)}};
    static CAPS:Cell<u8>=const{{Cell::new(0)}};
    static LOCKED:Cell<bool>=const{{Cell::new(false)}};
    static ENSURES:Cell<usize>=const{{Cell::new(0)}};
    static OWNER:RefCell<task::Process>=RefCell::new(task::Process{{table:task::handle_table::ObjectHandleTable::new_boxed()}});
}}
mod capability{{#[derive(Clone,Copy)]pub enum Capability{{IpcClient,IpcServer}}}}
mod task{{
    #[derive(Clone,Copy)]pub struct Id(u64);
    impl Id{{pub fn as_u64(self)->u64{{self.0}}pub fn from_u64(value:u64)->Self{{Self(value)}}}}
    pub type ProcessId=Id;
    pub mod handle_table{{
        use alloc::{{boxed::Box,vec::Vec,sync::Arc}};
        pub const PROCESS_MAX_OBJECT_HANDLES:usize=4096;
        #[derive(Clone,Debug)]pub enum KernelObject{{IpcEndpoint{{thread_id:u64,slot:u16,generation:u64}}}}
"#,
        status = root.join("core/crates/abi/src/status.rs"),
        wire = root.join("core/crates/abi/src/handle_snapshot.rs"),
    );
    let table = include_str!("../../../core/src/task/handle_table.rs");
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
    program.push_str(&format!(r#"
    }}
    #[path={snapshot:?}]pub mod handle_snapshot;
    pub struct Process{{pub table:Box<handle_table::ObjectHandleTable>}}
    impl Process{{pub fn object_handles_mut(&mut self)->&mut handle_table::ObjectHandleTable{{
        assert!(crate::LOCKED.get());&mut self.table
    }}}}
    pub fn current_thread_id()->Option<Id>{{crate::CONTEXT.get().then_some(Id(19))}}
    pub fn thread_to_process_id(id:u64)->Option<Id>{{assert_eq!(id,19);crate::THREAD.get().then_some(Id(42))}}
    pub fn with_process_mut<T>(id:Id,body:impl FnOnce(&mut Process)->T)->Option<T>{{
        assert_eq!(id.as_u64(),42);if !crate::PROCESS.get(){{return None;}}
        assert!(!crate::LOCKED.replace(true));let result=crate::OWNER.with_borrow_mut(body);
        crate::LOCKED.set(false);Some(result)
    }}
    pub mod process{{pub fn process_has_capability(pid:super::Id,cap:crate::capability::Capability)->bool{{
        assert_eq!(pid.as_u64(),42);
        crate::CAPS.get()&match cap{{crate::capability::Capability::IpcClient=>1,crate::capability::Capability::IpcServer=>2}}!=0
    }}}}
}}
use task::handle_table::{{KernelObject,ObjectHandleEntry,HandleRights}};
"#,snapshot=root.join("core/src/task/handle_snapshot.rs")));
    let ipc = include_str!("../../../core/src/syscall/ipc.rs");
    program.push_str(probe::between(
        ipc,
        "#[derive(Debug, Clone, Copy, PartialEq, Eq)]\npub struct IpcEndpoint",
        "#[derive(Clone, Copy, Debug)]\nstruct EndpointRecord",
    ));
    program.push_str(probe::between(
        ipc,
        "pub fn endpoint_rights_for_process(",
        "fn with_endpoints_mut",
    ));
    program.push_str(
        r#"
fn endpoint_for_thread(id:u64)->Option<IpcEndpoint>{
    assert_eq!(id,19);ENDPOINT.get().then_some(IpcEndpoint{thread_id:19,slot:3,generation:7})
}
fn ensure_endpoint_for_thread(id:u64)->Option<u64>{
    assert_eq!(id,19);ENSURES.set(ENSURES.get()+1);REGISTRY.get().then_some(5001)
}
"#,
    );
    program.push_str(probe::between(
        ipc,
        "pub fn create(",
        "pub(crate) fn endpoint_wait_ready(",
    ));
    program.push_str(r#"
fn count()->usize{OWNER.with_borrow(|p|p.table.describe().len())}
fn main(){
    for flags in [1,u64::MAX]{
        assert_eq!(create(flags,0),Error::InvalidArgument.into_raw());
        assert_eq!(create_handle(flags,0),Error::InvalidArgument.into_raw());
        assert_eq!(count(),0);assert_eq!(ENSURES.get(),0);
    }
    CONTEXT.set(false);
    assert_eq!(create(0,0),Error::NotReady.into_raw());
    assert_eq!(create_handle(0,0),Error::NotReady.into_raw());assert_eq!(ENSURES.get(),0);
    CONTEXT.set(true);
    for missing in 0..3{
        THREAD.set(missing!=0);ENDPOINT.set(missing!=1);PROCESS.set(missing!=2);
        assert_eq!(create_handle(0,0),Error::NotReady.into_raw());assert_eq!(count(),0);assert!(!LOCKED.get());
    }
    THREAD.set(true);ENDPOINT.set(true);PROCESS.set(true);
    REGISTRY.set(false);assert_eq!(create(0,0),Error::ResourceUnavailable.into_raw());
    REGISTRY.set(true);assert_eq!(create(0,u64::MAX),5001);
    for caps in 0..4{
        CAPS.set(caps);let raw=create_handle(0,u64::MAX);assert!(raw>0&&raw<=4096);
        let handle=task::handle_table::ObjectHandle::from_raw(raw as u32).unwrap();
        OWNER.with_borrow_mut(|p|{
            let entry=p.table.get(handle).unwrap();
            let mut expected=HandleRights::DUPLICATE.union(HandleRights::TRANSFER);
            if caps&1!=0{expected=expected.union(HandleRights::SEND);}
            if caps&2!=0{expected=expected.union(HandleRights::RECEIVE).union(HandleRights::WAIT);}
            assert_eq!(entry.rights(),expected);
            let KernelObject::IpcEndpoint{thread_id,slot,generation}=entry.object();
            assert_eq!((*thread_id,*slot,*generation),(19,3,7));assert!(p.table.close(handle));
        });assert_eq!(count(),0);
    }
    // Fill the actual fixed-capacity table, not a mock failure branch.
    OWNER.with_borrow_mut(|p|for _ in 0..4096{
        assert!(p.table.insert(ObjectHandleEntry::new(
            KernelObject::IpcEndpoint{thread_id:19,slot:3,generation:7},HandleRights::empty())).is_some());
    });
    assert_eq!(create_handle(0,0),Error::ResourceUnavailable.into_raw());assert_eq!(count(),4096);
    assert!(!LOCKED.get());
}
"#);
    probe::run(&program);
}
