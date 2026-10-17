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
    static RECEIVER:Cell<bool>=const{{Cell::new(true)}};
    static OUTPUT:Cell<[u8;72]>=const{{Cell::new([0;72])}};
    static OUTPUT_ERROR:Cell<Option<Error>>=const{{Cell::new(None)}};
    static OUTPUT_CALLS:Cell<usize>=const{{Cell::new(0)}};
    static RACE:Cell<bool>=const{{Cell::new(false)}};
    static PUBLISH_AFTER_COPY:Cell<bool>=const{{Cell::new(false)}};
    static RACED_HANDLE:Cell<Option<ObjectHandle>>=const{{Cell::new(None)}};
    static FAIL_ALLOCATION:Cell<bool>=const{{Cell::new(false)}};
    static PROCESS:RefCell<task::Process>=RefCell::new(task::Process{{table:task::handle_table::ObjectHandleTable::new_boxed()}});
}}
struct TestAllocator;
unsafe impl std::alloc::GlobalAlloc for TestAllocator{{
    unsafe fn alloc(&self,layout:std::alloc::Layout)->*mut u8{{
        if FAIL_ALLOCATION.try_with(|flag|flag.replace(false)).unwrap_or(false){{return std::ptr::null_mut();}}
        unsafe{{std::alloc::System.alloc(layout)}}
    }}
    unsafe fn dealloc(&self,pointer:*mut u8,layout:std::alloc::Layout){{unsafe{{std::alloc::System.dealloc(pointer,layout)}}}}
}}
#[global_allocator]static TEST_ALLOCATOR:TestAllocator=TestAllocator;
mod task{{
    pub mod handle_table{{
        use alloc::{{boxed::Box,vec::Vec,sync::Arc}};
        pub const PROCESS_MAX_OBJECT_HANDLES:usize=4096;
        #[derive(Clone,Debug)]pub struct KernelObject(pub Arc<u64>);
        impl Drop for KernelObject{{fn drop(&mut self){{
            if Arc::strong_count(&self.0)==1{{assert!(!crate::LOCKED.get(),"final object reference dropped under process lock");}}
        }}}}
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
    }}
    pub fn object_handles_mut(&mut self)->&mut handle_table::ObjectHandleTable{{
        assert!(crate::LOCKED.get());&mut self.table
    }}}}
    pub fn thread_to_process_id(id:u64)->Option<u64>{{assert_eq!(id,101);crate::RECEIVER.get().then_some(7)}}
    pub fn with_process<T>(id:u64,body:impl FnOnce(&Process)->T)->Option<T>{{
        assert_eq!(id,7);if !crate::PRESENT.get(){{return None;}}
        assert!(!crate::LOCKED.replace(true));
        let result=crate::PROCESS.with_borrow(body);crate::LOCKED.set(false);Some(result)
    }}
    pub fn with_process_mut<T>(id:u64,body:impl FnOnce(&mut Process)->T)->Option<T>{{
        assert_eq!(id,7);if !crate::PRESENT.get(){{return None;}}
        assert!(!crate::LOCKED.replace(true));
        let result=crate::PROCESS.with_borrow_mut(body);crate::LOCKED.set(false);Some(result)
    }}
}}
use task::handle_table::{{ObjectHandle,HandleRights,ObjectHandleEntry,KernelObject}};
mod syscall{{
    pub mod ipc{{pub mod lifetime{{pub fn remove_waiter(_:crate::ThreadId){{assert!(!crate::LOCKED.get());}}}}}}
    pub mod address_wait{{pub fn remove_waiter(_:crate::ThreadId){{assert!(!crate::LOCKED.get());}}}}
    pub mod time{{pub fn disarm_thread_deadline(_:crate::ThreadId){{assert!(!crate::LOCKED.get());}}}}
    pub fn copy_from_user_native(pointer:u64,output:&mut[u8])->Result<(),crate::Error>{{
        assert_eq!(pointer,4096);crate::COPY_CALLS.set(crate::COPY_CALLS.get()+1);
        if let Some(error)=crate::COPY_ERROR.get(){{return Err(error);}}
        output.copy_from_slice(&crate::COPY.get());Ok(())
    }}
    pub fn copy_to_user_native(pointer:u64,bytes:&[u8])->Result<(),crate::Error>{{
        assert_eq!(pointer,8192);assert!(!crate::LOCKED.get());
        crate::OUTPUT_CALLS.set(crate::OUTPUT_CALLS.get()+1);
        if crate::RACE.get(){{
            let count=u32::from_le_bytes(bytes[..4].try_into().unwrap())as usize;
            crate::PROCESS.with_borrow_mut(|process|{{
                let visible=process.table.describe().len();
                let snapshot=process.table.capture().unwrap();assert_eq!(snapshot.len(),visible);
                let clone=process.table.clone();assert_eq!(clone.describe().len(),visible);
                for index in 0..count{{
                    let start=8+16*index;let handle=crate::ObjectHandle::from_raw(u32::from_le_bytes(bytes[start..start+4].try_into().unwrap())).unwrap();
                    assert!(process.table.get(handle).is_none(),"authority published before output copy");
                    assert!(!process.table.close(handle),"unpublished selector was closable");
                    assert!(process.table.duplicate_restricted(handle,crate::HandleRights::READ).is_none());
                    assert!(process.table.export_restricted(handle,crate::HandleRights::READ).is_none());
                    let entry=crate::ObjectHandleEntry::new(crate::KernelObject(crate::Arc::new(77)),crate::HandleRights::READ);
                    assert!(!process.table.insert_at(handle,entry),"reserved selector was replaceable");
                }}
                // A concurrently installed unrelated object must survive any
                // later receive rollback, including reuse after cancellation.
                if !crate::PUBLISH_AFTER_COPY.get(){{
                    let unrelated=process.table.insert(crate::ObjectHandleEntry::new(crate::KernelObject(crate::Arc::new(91)),crate::HandleRights::READ)).unwrap();
                    crate::RACED_HANDLE.set(Some(unrelated));
                }}
            }});
        }}
        if let Some(error)=crate::OUTPUT_ERROR.get(){{return Err(error);}}
        crate::OUTPUT.set(bytes.try_into().unwrap());Ok(())
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
        "fn install_received_object_handles(",
        "#[derive(Debug)]\nstruct ObjectHandleAttachments",
    ));
    program.push_str(probe::between(
        ipc,
        "pub(crate) fn call_provider_from_kernel(",
        "/// Attach only handles from the authenticated caller's own table, through the",
    ));
    program.push_str(probe::between(
        ipc,
        "pub(crate) fn call_provider_with_handle_from_kernel(",
        "fn call_endpoint_with_attachments_from_kernel(",
    ));
    program.push_str(r#"
#[derive(Clone,Copy)]struct ThreadId(u64);impl ThreadId{fn as_u64(self)->u64{self.0}}
mod process{pub use crate::task::with_process_mut;pub fn remove_process_exit_waiters(_:crate::ThreadId){assert!(!crate::LOCKED.get());}}
mod thread_cleanup{use crate::ThreadId;type ProcessId=u64;
"#);
    program.push_str(probe::between(
        include_str!("../../../core/src/task/thread.rs"),
        "fn clear_thread_wait_registrations(",
        "fn retire_thread_endpoint(",
    ));
    program.push_str(
        "pub fn run(owner:u64){clear_thread_wait_registrations(ThreadId(owner),7);}\n}\n",
    );
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
    fn incoming(object:&Arc<u64>,count:usize)->ObjectHandleAttachments{
        let mut value=ObjectHandleAttachments::empty();value.count=count;
        value.delivery_flags=IPC_DELIVERY_NATIVE_OBJECT;
        for index in 0..count.min(4){
            let rights=match index{0=>HandleRights::READ,1=>HandleRights::empty(),_=>HandleRights::TRANSFER};
            value.handles[index]=Some(ObjectHandleEntry::new(KernelObject(object.clone()),rights));
        }value
    }
    let baseline=PROCESS.with_borrow(|p|p.table.describe().len());
    // Missing entries must be rejected before the first valid one is inserted.
    for malformed in [false,true]{
        let mut attachments=incoming(&object,if malformed{5}else{3});
        if !malformed{attachments.handles[1]=None;}
        let before=OUTPUT_CALLS.get();
        assert_eq!(install_received_object_handles(101,attachments,8192),Err(Error::BackingFailure.into_raw()));
        assert_eq!(OUTPUT_CALLS.get(),before);assert_eq!(Arc::strong_count(&object),2);
        assert_eq!(PROCESS.with_borrow(|p|p.table.describe().len()),baseline);
    }
    for receiver in [false,true]{
        RECEIVER.set(receiver);PRESENT.set(!receiver);
        assert_eq!(install_received_object_handles(101,incoming(&object,3),8192),Err(Error::NotReady.into_raw()));
        assert_eq!(Arc::strong_count(&object),2);
    }
    RECEIVER.set(true);PRESENT.set(true);
    for free in 0..3{
        let mut fillers=Vec::new();let dummy=Arc::new(77);
        PROCESS.with_borrow_mut(|p|while p.table.describe().len()<4096-free{
            fillers.push(p.table.insert(ObjectHandleEntry::new(KernelObject(dummy.clone()),HandleRights::READ)).unwrap());
        });
        let before=OUTPUT_CALLS.get();
        assert_eq!(install_received_object_handles(101,incoming(&object,3),8192),Err(Error::ResourceUnavailable.into_raw()));
        assert_eq!(OUTPUT_CALLS.get(),before);assert_eq!(Arc::strong_count(&object),2);
        PROCESS.with_borrow_mut(|p|{
            assert_eq!(p.table.describe().len(),4096-free);
            for handle in fillers{assert!(p.table.close(handle));}
            assert_eq!(p.table.describe().len(),baseline);
        });
    }
    for error in [Error::InvalidAddress,Error::ResourceUnavailable,Error::BackingFailure]{
        OUTPUT_ERROR.set(Some(error));
        assert_eq!(install_received_object_handles(101,incoming(&object,3),8192),Err(error.into_raw()));
        assert_eq!(Arc::strong_count(&object),2);
        assert_eq!(PROCESS.with_borrow(|p|p.table.describe().len()),baseline);
    }
    OUTPUT_ERROR.set(None);
    RACE.set(true);OUTPUT_ERROR.set(Some(Error::InvalidAddress));
    assert_eq!(install_received_object_handles(101,incoming(&object,3),8192),Err(Error::InvalidAddress.into_raw()));
    let raced=RACED_HANDLE.take().unwrap();PROCESS.with_borrow_mut(|p|{{assert!(p.table.get(raced).is_some());assert!(p.table.close(raced));}});
    assert_eq!(Arc::strong_count(&object),2);assert_eq!(PROCESS.with_borrow(|p|p.table.describe().len()),baseline);
    OUTPUT_ERROR.set(None);PUBLISH_AFTER_COPY.set(true);
    assert_eq!(install_received_object_handles(101,incoming(&object,3),8192),Ok(()));
    let output=OUTPUT.get();assert_eq!(u32::from_le_bytes(output[..4].try_into().unwrap()),3);
    assert_eq!(u32::from_le_bytes(output[4..8].try_into().unwrap()),IPC_DELIVERY_NATIVE_OBJECT);
    for index in 0..3{
        let start=8+16*index;
        let handle=ObjectHandle::from_raw(u32::from_le_bytes(output[start..start+4].try_into().unwrap())).unwrap();
        let rights=u64::from_le_bytes(output[start+8..start+16].try_into().unwrap());
        let expected=match index{0=>HandleRights::READ,1=>HandleRights::empty(),_=>HandleRights::TRANSFER};
        assert_eq!(rights,expected.bits());assert_eq!(&output[start+4..start+8],&[0;4]);
        PROCESS.with_borrow_mut(|p|{assert_eq!(p.table.get(handle).unwrap().rights(),expected);assert!(p.table.close(handle));});
    }
    assert_eq!(&output[56..],&[0;16]);assert_eq!(Arc::strong_count(&object),2);
    assert_eq!(PROCESS.with_borrow(|p|p.table.describe().len()),baseline);
    // Publication itself must not allocate, even if unrelated visible
    // insertions happen while the receiving operation is copying its result.
    {
        let mut table=task::handle_table::ObjectHandleTable::new();
        let mut tickets=Vec::new();
        for _ in 0..4{tickets.push(table.reserve(101,ObjectHandleEntry::new(KernelObject(object.clone()),HandleRights::READ)).unwrap());}
        for _ in 0..20{table.insert(ObjectHandleEntry::new(KernelObject(object.clone()),HandleRights::READ)).unwrap();}
        FAIL_ALLOCATION.set(true);for ticket in tickets{assert!(table.publish_reserved(ticket));}
        assert!(FAIL_ALLOCATION.replace(false),"publication allocated storage");assert_eq!(table.describe().len(),24);
    }
    // A canceled ticket cannot cancel or publish a newer reservation which
    // reuses precisely the same selector. Pending selectors count toward the
    // capacity bound but are never get/close/capture/clone-visible.
    {
        let mut table=task::handle_table::ObjectHandleTable::new();
        let old=table.reserve(101,ObjectHandleEntry::new(KernelObject(object.clone()),HandleRights::READ)).unwrap();
        assert_eq!(table.clone().describe().len(),0);assert_eq!(table.capture().unwrap().len(),0);
        assert!(table.cancel_reserved(old).is_some());
        for _ in 0..4095{table.insert(ObjectHandleEntry::new(KernelObject(object.clone()),HandleRights::READ)).unwrap();}
        let current=table.reserve(101,ObjectHandleEntry::new(KernelObject(object.clone()),HandleRights::READ)).unwrap();
        assert_eq!(old.handle(),current.handle());assert_ne!(old,current);assert!(!table.is_reserved(old));assert!(table.is_reserved(current));
        assert!(table.cancel_reserved(old).is_none());assert!(!table.publish_reserved(old));
        assert!(table.insert(ObjectHandleEntry::new(KernelObject(object.clone()),HandleRights::READ)).is_none());
        assert!(table.reserve(103,ObjectHandleEntry::new(KernelObject(object.clone()),HandleRights::READ)).is_err());
        assert!(table.get(current.handle()).is_none());assert!(!table.close(current.handle()));
        assert!(table.take_reservation_for(102).is_none());assert!(table.is_reserved(current));
        assert!(table.take_reservation_for(101).is_some());assert!(!table.is_reserved(current));
        assert!(table.insert_at(current.handle(),ObjectHandleEntry::new(KernelObject(object.clone()),HandleRights::READ)));
        assert!(table.cancel_reserved(current).is_none());assert!(table.get(current.handle()).is_some());
    }
    // Both Vec allocations are fallible. Failure returns the original owned
    // reference; no selector or authority is left published or reserved.
    for pending_allocation in [false,true]{
        let mut table=task::handle_table::ObjectHandleTable::new();
        if pending_allocation{let handle=table.insert(ObjectHandleEntry::new(KernelObject(object.clone()),HandleRights::READ)).unwrap();assert!(table.close(handle));}
        let entry=ObjectHandleEntry::new(KernelObject(object.clone()),HandleRights::READ);
        FAIL_ALLOCATION.set(true);assert!(table.reserve(101,entry).is_err());assert!(!FAIL_ALLOCATION.get());
        assert_eq!(table.describe().len(),0);assert!(table.take_reservation_for(101).is_none());
    }
    assert_eq!(Arc::strong_count(&object),2);
    // Thread teardown runs the production cleanup after queue removal. It
    // releases only that thread's reservations, outside the process lock.
    {
        let abandoned=Arc::new(991);let weak=Arc::downgrade(&abandoned);
        let own=PROCESS.with_borrow_mut(|p|p.table.reserve(101,ObjectHandleEntry::new(KernelObject(abandoned),HandleRights::READ)).unwrap());
        let other=PROCESS.with_borrow_mut(|p|p.table.reserve(102,ObjectHandleEntry::new(KernelObject(object.clone()),HandleRights::READ)).unwrap());
        let cloned=PROCESS.with_borrow(|p|p.table.clone());let captured=PROCESS.with_borrow(|p|p.table.capture().unwrap());
        thread_cleanup::run(101);assert!(weak.upgrade().is_none());
        PROCESS.with_borrow(|p|{assert!(!p.table.is_reserved(own));assert!(p.table.is_reserved(other));});
        thread_cleanup::run(102);drop(cloned);drop(captured);assert_eq!(Arc::strong_count(&object),2);
    }
}
"#);
    probe::run(&program);
}
