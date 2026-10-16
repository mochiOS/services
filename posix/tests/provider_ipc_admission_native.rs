#[allow(dead_code)]
#[path = "support/native_error_probe.rs"]
mod probe;

#[test]
fn provider_calls_use_native_admission_errors_and_real_attenuated_table_exports() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap();
    let mut program = format!(
        r#"
#![allow(dead_code)]
extern crate alloc;
extern crate self as mnu_abi;
#[path={status:?}]pub mod status;
#[path={wire:?}]pub mod handle_snapshot;
use status::Error;
use std::{{cell::{{Cell,RefCell}},sync::Arc}};
#[derive(Debug)]pub struct HandleInfo{{pub handle:u32,pub reserved:u32,pub rights:u64}}
thread_local!{{
    static CONTEXT:Cell<bool>=const{{Cell::new(true)}};
    static PRESENT:Cell<bool>=const{{Cell::new(true)}};
    static VALID:Cell<bool>=const{{Cell::new(true)}};
    static SENDER:Cell<bool>=const{{Cell::new(true)}};
    static LOCKED:Cell<bool>=const{{Cell::new(false)}};
    static CALLS:Cell<usize>=const{{Cell::new(0)}};
    static RESULT:Cell<Result<usize,u64>>=const{{Cell::new(Ok(3))}};
    static RIGHTS:Cell<Option<HandleRights>>=const{{Cell::new(None)}};
    static PROCESS:RefCell<task::Process>=RefCell::new(task::Process{{table:task::handle_table::ObjectHandleTable::new_boxed()}});
}}
mod task{{
    pub mod handle_table{{
        use alloc::{{boxed::Box,vec::Vec,sync::Arc}};
        pub const PROCESS_MAX_OBJECT_HANDLES:usize=4096;
        #[derive(Clone,Debug)]pub struct KernelObject(pub Arc<u64>);
"#,
        status = root.join("core/crates/abi/src/status.rs"),
        wire = root.join("core/crates/abi/src/handle_snapshot.rs"),
    );
    let delivery_flag = include_str!("../../../core/crates/abi/src/lib.rs")
        .lines()
        .find(|line| line.starts_with("pub const IPC_DELIVERY_NATIVE_OBJECT:"))
        .unwrap();
    // Insert at crate scope, before task's inline handle table module.
    program = program.replacen("mod task{", &format!("{delivery_flag}\nmod task{{"), 1);
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
    pub type ProcessId=u64;
    pub struct Process{{pub table:Box<handle_table::ObjectHandleTable>}}
    impl Process{{pub fn object_handles(&self)->&handle_table::ObjectHandleTable{{
        assert!(crate::LOCKED.get());&self.table
    }}}}
    pub fn with_process<T>(id:u64,body:impl FnOnce(&Process)->T)->Option<T>{{
        assert_eq!(id,7);if !crate::PRESENT.get(){{return None;}}
        assert!(!crate::LOCKED.replace(true));
        let result=crate::PROCESS.with_borrow(body);crate::LOCKED.set(false);Some(result)
    }}
}}
use task::handle_table::{{ObjectHandle,HandleRights,ObjectHandleEntry,KernelObject}};
mod syscall{{pub mod security{{pub fn current_process_id()->Option<u64>{{crate::CONTEXT.get().then_some(7)}}}}}}
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
struct IpcEndpoint{{thread_id:u64,slot:u16,generation:u64}}
struct ObjectHandleAttachments{{handles:[Option<ObjectHandleEntry>;4],count:usize,delivery_flags:u32}}
impl ObjectHandleAttachments{{fn empty()->Self{{Self{{handles:core::array::from_fn(|_|None),count:0,delivery_flags:0}}}}}}
fn endpoint_is_valid(endpoint:IpcEndpoint)->bool{{
    assert_eq!(endpoint,IpcEndpoint{{thread_id:99,slot:3,generation:123}});VALID.get()
}}
fn ensure_endpoint_for_thread(id:u64)->Option<u64>{{assert_eq!(id,99);SENDER.get().then_some(987)}}
fn call_endpoint_with_attachments_from_kernel(
    endpoint:IpcEndpoint,sender:u64,request:&[u8],reply:&mut[u8],attachments:ObjectHandleAttachments
)->Result<usize,u64>{{
    assert!(!LOCKED.get());assert!(endpoint_is_valid(endpoint));assert_eq!(sender,987);
    assert_eq!(request,b"request");assert_eq!(reply.len(),16);
    assert_eq!(attachments.delivery_flags,IPC_DELIVERY_NATIVE_OBJECT);
    match RIGHTS.get(){{
        Some(rights)=>{{assert_eq!(attachments.count,1);let entry=attachments.handles[0].as_ref().unwrap();
            assert_eq!(entry.rights(),rights);let KernelObject(object)=entry.object();assert_eq!(**object,42);
            assert_eq!(Arc::strong_count(object),3);
        }}
        None=>{{assert_eq!(attachments.count,0);assert!(attachments.handles.iter().all(Option::is_none));}}
    }}
    CALLS.set(CALLS.get()+1);RESULT.get()
}}
"#, snapshot=root.join("core/src/task/handle_snapshot.rs")));
    let ipc = include_str!("../../../core/src/syscall/ipc.rs");
    program.push_str(probe::between(
        ipc,
        "fn export_object_handle(",
        "fn install_received_object_handles(",
    ));
    program.push_str(probe::between(
        ipc,
        "pub(crate) fn call_provider_from_kernel(",
        "fn call_endpoint_from_kernel(",
    ));
    program.push_str(probe::between(
        ipc,
        "pub(crate) fn call_provider_with_handle_from_kernel(",
        "fn call_endpoint_with_attachments_from_kernel(",
    ));
    program.push_str(r#"
fn main(){
    let endpoint=IpcEndpoint{thread_id:99,slot:3,generation:123};
    let object=Arc::new(42);
    let (transfer,read_only)=PROCESS.with_borrow_mut(|p|(
        p.table.insert(ObjectHandleEntry::new(KernelObject(object.clone()),
            HandleRights::READ.union(HandleRights::TRANSFER))).unwrap(),
        p.table.insert(ObjectHandleEntry::new(KernelObject(Arc::new(51)),HandleRights::READ)).unwrap()
    ));
    let mut reply=[0u8;16];
    let missing=ObjectHandle::from_raw(4096).unwrap();
    for present in [false,true]{
        PRESENT.set(present);
        let result=export_object_handle(7,missing,HandleRights::READ);
        assert_eq!(result.unwrap_err(),if present{Error::InvalidArgument}else{Error::NotReady}.into_raw());
    }
    let empty=HandleRights::from_bits(0).unwrap();
    for (handle,requested) in [(read_only,HandleRights::READ),(read_only,empty),
        (transfer,HandleRights::WRITE),(transfer,HandleRights::READ.union(HandleRights::WRITE))]{
        assert_eq!(export_object_handle(7,handle,requested).unwrap_err(),Error::AccessDenied.into_raw());
        assert!(!LOCKED.get());assert_eq!(Arc::strong_count(&object),2);
    }
    for requested in [HandleRights::READ,empty]{
        RIGHTS.set(Some(requested));
        assert_eq!(call_provider_with_handle_from_kernel(endpoint,b"request",&mut reply,transfer,requested),Ok(3));
        assert_eq!(Arc::strong_count(&object),2);
        RESULT.set(Err(Error::BackingFailure.into_raw()));
        assert_eq!(call_provider_with_handle_from_kernel(endpoint,b"request",&mut reply,transfer,requested),Err(Error::BackingFailure.into_raw()));
        assert_eq!(Arc::strong_count(&object),2);RESULT.set(Ok(3));
    }
    let before=CALLS.get();
    VALID.set(false);CONTEXT.set(false);
    assert_eq!(call_provider_with_handle_from_kernel(endpoint,b"request",&mut reply,transfer,HandleRights::READ),Err(Error::NotFound.into_raw()));
    assert_eq!(call_provider_from_kernel(endpoint,b"request",&mut reply),Err(Error::NotFound.into_raw()));
    VALID.set(true);
    assert_eq!(call_provider_with_handle_from_kernel(endpoint,b"request",&mut reply,transfer,HandleRights::READ),Err(Error::NotReady.into_raw()));
    CONTEXT.set(true);SENDER.set(false);
    assert_eq!(call_provider_from_kernel(endpoint,b"request",&mut reply),Err(Error::NotReady.into_raw()));
    assert_eq!(call_provider_with_handle_from_kernel(endpoint,b"request",&mut reply,transfer,HandleRights::READ),Err(Error::NotReady.into_raw()));
    assert_eq!(Arc::strong_count(&object),2);assert_eq!(CALLS.get(),before);SENDER.set(true);
    RIGHTS.set(None);
    for error in [Error::InvalidArgument,Error::InvalidAddress,Error::AccessDenied,Error::NotReady,
        Error::BackingFailure,Error::ResourceUnavailable,Error::NotFound,Error::AlreadyExists,
        Error::LimitExceeded,Error::PeerClosed]{
        RESULT.set(Err(error.into_raw()));
        assert_eq!(call_provider_from_kernel(endpoint,b"request",&mut reply),Err(error.into_raw()));
    }
    RESULT.set(Ok(3));assert_eq!(call_provider_from_kernel(endpoint,b"request",&mut reply),Ok(3));
    assert_eq!(CALLS.get(),15);assert!(!LOCKED.get());
}
"#);
    probe::run(&program);
}
