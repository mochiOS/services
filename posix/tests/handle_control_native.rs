#[allow(dead_code)]
#[path = "support/native_error_probe.rs"]
mod probe;

#[test]
fn control_uses_native_admission_fallible_storage_and_opaque_provider_status() {
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
#[path={provider:?}]pub mod provider;
mod util{{#[path={storage:?}]pub mod object_snapshot;}}
use status::Error;
use std::cell::Cell;
thread_local!{{
    static ALLOCATION:Cell<Option<usize>>=const{{Cell::new(None)}};
    static ADMISSION:Cell<Option<Error>>=const{{Cell::new(None)}};
    static INPUT_ERROR:Cell<Option<Error>>=const{{Cell::new(None)}};
    static OUTPUT_ERROR:Cell<Option<Error>>=const{{Cell::new(None)}};
    static TRANSPORT_ERROR:Cell<u64>=const{{Cell::new(0)}};
    static PROVIDER_STATUS:Cell<i64>=const{{Cell::new(0)}};
    static MODE:Cell<u8>=const{{Cell::new(0)}};
    static CALLS:Cell<usize>=const{{Cell::new(0)}};
    static INPUT_COPIES:Cell<usize>=const{{Cell::new(0)}};
    static OUTPUT_COPIES:Cell<usize>=const{{Cell::new(0)}};
    static CODE:Cell<u64>=const{{Cell::new(0)}};
    static QUERY:Cell<bool>=const{{Cell::new(false)}};
}}
struct Allocator;
fn fail()->bool{{ALLOCATION.try_with(|slot|match slot.get(){{
    Some(0)=>true,Some(n)=>{{slot.set(Some(n-1));false}},None=>false
}}).unwrap_or(false)}}
unsafe impl std::alloc::GlobalAlloc for Allocator{{
    unsafe fn alloc(&self,l:std::alloc::Layout)->*mut u8{{if fail(){{core::ptr::null_mut()}}else{{unsafe{{std::alloc::System.alloc(l)}}}}}}
    unsafe fn realloc(&self,p:*mut u8,l:std::alloc::Layout,n:usize)->*mut u8{{if fail(){{core::ptr::null_mut()}}else{{unsafe{{std::alloc::System.realloc(p,l,n)}}}}}}
    unsafe fn dealloc(&self,p:*mut u8,l:std::alloc::Layout){{unsafe{{std::alloc::System.dealloc(p,l)}}}}
}}
#[global_allocator]static ALLOCATOR:Allocator=Allocator;
#[derive(Debug,PartialEq)]struct HandleRights(u8);
impl HandleRights{{const CONTROL:Self=Self(1);const READ:Self=Self(2);}}
struct ProviderObject{{endpoint_thread_id:u64,endpoint_slot:u16,endpoint_generation:u64,object_id:u64}}
enum KernelObject{{Provider(ProviderObject),MemoryUpdate(u8),Other}}
fn object_native(raw:u64,right:HandleRights)->Result<KernelObject,Error>{{
    assert_eq!(right,if QUERY.get(){{HandleRights::READ}}else{{HandleRights::CONTROL}});
    if let Some(error)=ADMISSION.get(){{return Err(error);}}
    match raw{{7=>Ok(KernelObject::Provider(ProviderObject{{endpoint_thread_id:99,endpoint_slot:7,endpoint_generation:123,object_id:17}})),
        8=>Ok(KernelObject::MemoryUpdate(5)),9=>Ok(KernelObject::Other),_=>Err(Error::InvalidArgument)}}
}}
mod memory_update{{pub fn control(update:&u8,code:u64,input:u64,il:u64,output:u64,ol:u64)->u64{{
    assert_eq!((*update,code,input,il,output,ol),(5,42,11,2,12,3));43
}}}}
mod syscall{{
    pub fn copy_from_user_native(pointer:u64,bytes:&mut[u8])->Result<(),crate::Error>{{
        crate::INPUT_COPIES.set(crate::INPUT_COPIES.get()+1);
        if let Some(error)=crate::INPUT_ERROR.get(){{return Err(error);}}
        assert_eq!(pointer,11);bytes.fill(0x5a);Ok(())
    }}
    pub fn copy_to_user_native(pointer:u64,bytes:&[u8])->Result<(),crate::Error>{{
        crate::OUTPUT_COPIES.set(crate::OUTPUT_COPIES.get()+1);
        if let Some(error)=crate::OUTPUT_ERROR.get(){{return Err(error);}}
        assert_eq!((pointer,bytes),(12,&b"abc"[..]));Ok(())
    }}
    pub mod ipc{{
        #[derive(Debug,PartialEq)]pub struct IpcEndpoint{{pub thread_id:u64,pub slot:u16,pub generation:u64}}
        pub fn call_provider_from_kernel(endpoint:IpcEndpoint,request:&[u8],reply:&mut[u8])->Result<usize,u64>{{
            use crate::*;
            assert_eq!(endpoint,IpcEndpoint{{thread_id:99,slot:7,generation:123}});
            CALLS.set(CALLS.get()+1);
            let (header,data)=provider::RequestHeader::decode(request).unwrap();
            assert_eq!((header.opcode,header.object_id,header.basis),(if QUERY.get(){{provider::OP_QUERY}}else{{provider::OP_CONTROL}},17,CODE.get()));
            assert!(data.iter().all(|byte|*byte==0x5a));
            if TRANSPORT_ERROR.get()!=0{{return Err(TRANSPORT_ERROR.get());}}
            let status=PROVIDER_STATUS.get();
            let payload=if status!=0||MODE.get()==4{{&[][..]}}else{{&b"abc"[..]}};
            provider::ResponseHeader{{opcode:header.opcode,status,object_id:17,
                value:if MODE.get()==1{{4}}else{{payload.len()as u64}},data_length:payload.len()as u32}}
                .encode(payload,reply).map_err(|_|Error::BackingFailure.into_raw())
        }}
    }}
}}
"#,
        status = root.join("core/crates/abi/src/status.rs"),
        provider = root.join("core/crates/abi/src/provider.rs"),
        storage = root.join("core/src/util/object_snapshot.rs"),
    );
    probe::constants(
        &mut program,
        include_str!("../../../core/crates/abi/src/lib.rs"),
        &["HANDLE_SEEK_START", "HANDLE_SEEK_CURRENT", "HANDLE_SEEK_END"],
    );
    let source = include_str!("../../../core/src/syscall/handle.rs");
    program.push_str(probe::between(
        source,
        "pub fn control(",
        "pub fn options_get(",
    ));
    program.push_str(probe::between(
        source,
        "fn provider_endpoint(",
        "/// Reads from a provider object",
    ));
    program.push_str(r#"
fn invoke()->u64{if QUERY.get(){query(7,CODE.get(),11,2,12,3)}else{control(7,CODE.get(),11,2,12,3)}}
fn main(){
 for query_mode in [false,true]{QUERY.set(query_mode);
    for code in [0,42,u64::MAX]{CODE.set(code);assert_eq!(invoke(),3);}
    for error in [Error::LimitExceeded,Error::InvalidAddress,Error::ResourceUnavailable,
        Error::BackingFailure,Error::InvalidArgument,Error::AccessDenied,Error::NotReady,
        Error::AlreadyExists,Error::NotFound,Error::PeerClosed]{
        let before=CALLS.get();ADMISSION.set(Some(error));assert_eq!(invoke(),error.into_raw());ADMISSION.set(None);
        assert_eq!(CALLS.get(),before);
        INPUT_ERROR.set(Some(error));assert_eq!(invoke(),error.into_raw());INPUT_ERROR.set(None);
        assert_eq!(CALLS.get(),before);
        TRANSPORT_ERROR.set(error.into_raw());assert_eq!(invoke(),error.into_raw());TRANSPORT_ERROR.set(0);
        OUTPUT_ERROR.set(Some(error));assert_eq!(invoke(),error.into_raw());OUTPUT_ERROR.set(None);
    }
    for status in [-1,-11,-95,-4095]{
        let before=OUTPUT_COPIES.get();PROVIDER_STATUS.set(status);assert_eq!(invoke(),status as u64);
        assert_eq!(OUTPUT_COPIES.get(),before);PROVIDER_STATUS.set(0);
    }
    for allocation in 0..3{
        let before=CALLS.get();ALLOCATION.set(Some(allocation));let result=invoke();ALLOCATION.set(None);
        assert_eq!(result,Error::ResourceUnavailable.into_raw());assert_eq!(CALLS.get(),before);
    }
    let before=CALLS.get();
    let operation=if query_mode{query}else{control};
    for extent in [provider::MAX_DATA_LEN as u64+1,u64::MAX]{
        assert_eq!(operation(7,0,11,extent,12,3),Error::LimitExceeded.into_raw());
        assert_eq!(operation(7,0,11,2,12,extent),Error::LimitExceeded.into_raw());
    }
    assert_eq!(operation(0,0,0,0,0,0),Error::InvalidArgument.into_raw());
    assert_eq!(operation(9,0,0,0,0,0),Error::InvalidArgument.into_raw());
    assert_eq!(CALLS.get(),before);
    let before=OUTPUT_COPIES.get();MODE.set(1);assert_eq!(invoke(),Error::BackingFailure.into_raw());
    assert_eq!(OUTPUT_COPIES.get(),before);MODE.set(0);
    // Empty payloads must not dereference null pointers. The native update
    // object retains its distinct native control implementation.
    MODE.set(4);assert_eq!(operation(7,CODE.get(),0,0,0,0),0);MODE.set(0);
    assert_eq!(operation(8,42,11,2,12,3),if query_mode{Error::InvalidArgument.into_raw()}else{43});
 }
}
"#);
    probe::run(&program);
}
