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
    static COPY:Cell<[u8;72]>=const{{Cell::new([0;72])}};
    static COPY_ERROR:Cell<Option<Error>>=const{{Cell::new(None)}};
    static COPY_CALLS:Cell<usize>=const{{Cell::new(0)}};
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
    let abi = include_str!("../../../core/crates/abi/src/lib.rs");
    let capacity = abi
        .lines()
        .find(|line| line.starts_with("pub const IPC_MAX_OBJECT_HANDLES:"))
        .unwrap();
    let wire = probe::between(
        abi,
        "#[repr(C)]\n#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]\npub struct IpcObjectHandle {",
        "/// `StorageControl`",
    );
    // Insert real wire declarations at crate scope before the table module.
    program = program.replacen(
        "mod task{",
        &format!(
            "{capacity}\n{wire}\nconst MAX_OBJECT_HANDLES:usize=IPC_MAX_OBJECT_HANDLES;\nmod task{{"
        ),
        1,
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
mod syscall{{
    pub fn copy_from_user_native(pointer:u64,output:&mut[u8])->Result<(),crate::Error>{{
        assert_eq!(pointer,4096);crate::COPY_CALLS.set(crate::COPY_CALLS.get()+1);
        if let Some(error)=crate::COPY_ERROR.get(){{return Err(error);}}
        output.copy_from_slice(&crate::COPY.get());Ok(())
    }}
    pub mod security{{pub fn current_process_id()->Option<u64>{{crate::CONTEXT.get().then_some(7)}}}}
}}
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
struct IpcEndpoint{{thread_id:u64,slot:u16,generation:u64}}
#[derive(Debug)]struct ObjectHandleAttachments{{handles:[Option<ObjectHandleEntry>;4],count:usize,delivery_flags:u32}}
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
        "fn decode_outgoing_object_handles(",
        "fn export_object_handle(",
    ));
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
    assert_eq!(core::mem::size_of::<IpcObjectHandles>(),72);
    let before=COPY_CALLS.get();
    assert_eq!(decode_outgoing_object_handles(0).unwrap_err(),Error::InvalidAddress.into_raw());
    assert_eq!(COPY_CALLS.get(),before);
    for error in [Error::InvalidAddress,Error::ResourceUnavailable,Error::BackingFailure]{
        COPY_ERROR.set(Some(error));assert_eq!(decode_outgoing_object_handles(4096).unwrap_err(),error.into_raw());
    }
    COPY_ERROR.set(None);
    fn bytes(items:&[(u32,u64)])->[u8;72]{
        let mut bytes=[0u8;72];bytes[..4].copy_from_slice(&(items.len()as u32).to_le_bytes());
        for (index,(handle,rights)) in items.iter().enumerate(){
            let start=8+index*16;bytes[start..start+4].copy_from_slice(&handle.to_le_bytes());
            bytes[start+8..start+16].copy_from_slice(&rights.to_le_bytes());
        }bytes
    }
    for flags in [IPC_DELIVERY_NATIVE_OBJECT,IPC_DELIVERY_ENDPOINT_HANDLE,u32::MAX]{
        let mut wire=bytes(&[(transfer.raw(),HandleRights::READ.bits())]);wire[4..8].copy_from_slice(&flags.to_le_bytes());COPY.set(wire);
        assert_eq!(decode_outgoing_object_handles(4096).unwrap_err(),Error::InvalidArgument.into_raw());
        assert_eq!(Arc::strong_count(&object),2);
    }
    for (second,bits,expected) in [(4096,HandleRights::READ.bits(),Error::InvalidArgument),
        (transfer.raw(),HandleRights::WRITE.bits(),Error::AccessDenied),
        (read_only.raw(),HandleRights::READ.bits(),Error::AccessDenied),
        (0,0,Error::InvalidArgument),(transfer.raw(),1u64<<61,Error::InvalidArgument)]{
        COPY.set(bytes(&[(transfer.raw(),HandleRights::READ.bits()),(second,bits)]));
        assert_eq!(decode_outgoing_object_handles(4096).unwrap_err(),expected.into_raw());
        assert_eq!(Arc::strong_count(&object),2,"partial export leaked a reference");
    }
    let mut wire=bytes(&[(transfer.raw(),1)]);wire[12..16].copy_from_slice(&1u32.to_le_bytes());COPY.set(wire);
    assert_eq!(decode_outgoing_object_handles(4096).unwrap_err(),Error::InvalidArgument.into_raw());
    wire[..4].copy_from_slice(&5u32.to_le_bytes());COPY.set(wire);
    assert_eq!(decode_outgoing_object_handles(4096).unwrap_err(),Error::InvalidArgument.into_raw());
    COPY.set(bytes(&[(transfer.raw(),HandleRights::READ.bits())]));CONTEXT.set(false);
    assert_eq!(decode_outgoing_object_handles(4096).unwrap_err(),Error::NotReady.into_raw());CONTEXT.set(true);
    for requested in [HandleRights::READ,HandleRights::from_bits(0).unwrap(),HandleRights::TRANSFER]{
        COPY.set(bytes(&[(transfer.raw(),requested.bits())]));let before=COPY_CALLS.get();
        let attachments=decode_outgoing_object_handles(4096).unwrap();assert_eq!(COPY_CALLS.get(),before+1);
        assert_eq!(attachments.count,1);assert_eq!(attachments.delivery_flags,0);
        assert_eq!(attachments.handles[0].as_ref().unwrap().rights(),requested);
        assert_eq!(Arc::strong_count(&object),3);drop(attachments);assert_eq!(Arc::strong_count(&object),2);
    }
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
