#[allow(dead_code)]
#[path = "support/native_error_probe.rs"]
mod probe;

#[test]
fn memory_backing_query_caches_only_explicit_success_not_provider_errors() {
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
use std::cell::Cell;
use std::sync::atomic::{{AtomicBool,AtomicU64,Ordering}};
thread_local!{{
    static CALLS:Cell<usize>=const{{Cell::new(0)}};
    static IDENTITY:Cell<u64>=const{{Cell::new(0)}};
    static STATUS:Cell<i64>=const{{Cell::new(0)}};
    static FAILURE:Cell<u64>=const{{Cell::new(0)}};
    static MALFORMED:Cell<bool>=const{{Cell::new(false)}};
}}
struct ProviderObject{{
    endpoint_thread_id:u64,endpoint_slot:u16,endpoint_generation:u64,object_id:u64,
    memory_identity:AtomicU64,memory_identity_unavailable:AtomicBool,
}}
"#,
        status = root.join("core/crates/abi/src/status.rs"),
        provider = root.join("core/crates/abi/src/provider.rs"),
    );
    probe::constants(
        &mut program,
        include_str!("../../../core/crates/abi/src/lib.rs"),
        &[
            "HANDLE_SEEK_START",
            "HANDLE_SEEK_CURRENT",
            "HANDLE_SEEK_END",
        ],
    );
    program.push_str("impl ProviderObject{\n");
    program.push_str(probe::between(
        include_str!("../../../core/src/task/handle_table.rs"),
        "    pub(crate) fn memory_identity(",
        "    pub(crate) fn register_waiter(",
    ));
    program.push_str(r#"
}
mod syscall{pub mod ipc{
    #[derive(Debug,PartialEq)]pub struct IpcEndpoint{pub thread_id:u64,pub slot:u16,pub generation:u64}
    pub fn call_provider_from_kernel(endpoint:IpcEndpoint,request:&[u8],reply:&mut[u8])->Result<usize,u64>{
        use crate::*;
        assert_eq!(endpoint,IpcEndpoint{thread_id:17,slot:2,generation:3});
        CALLS.set(CALLS.get()+1);
        let (request,data)=provider::RequestHeader::decode(request).unwrap();
        assert_eq!((request.opcode,request.object_id),(provider::OP_MEMORY_OBJECT,41));assert!(data.is_empty());
        if FAILURE.get()!=0{return Err(FAILURE.get());}
        if MALFORMED.get(){return Ok(reply.len()+1);}
        provider::ResponseHeader{opcode:request.opcode,object_id:41,status:STATUS.get(),
            value:if STATUS.get()==0{IDENTITY.get()}else{0},data_length:0}
            .encode(&[],reply).map_err(|_|status::Error::BackingFailure.into_raw())
    }
}}
"#);
    let source = include_str!("../../../core/src/syscall/handle.rs");
    program.push_str(probe::between(
        source,
        "fn provider_endpoint(",
        "/// Reads from a provider object",
    ));
    program.push_str(probe::between(
        source,
        "pub(crate) fn provider_memory_object(",
        "/// The caller retains its backing I/O guard",
    ));
    program.push_str(r#"
fn object()->ProviderObject{ProviderObject{endpoint_thread_id:17,endpoint_slot:2,endpoint_generation:3,object_id:41,
    memory_identity:AtomicU64::new(0),memory_identity_unavailable:AtomicBool::new(false)}}
fn main(){
    for identity in [0,1,u64::MAX]{
        let owner=object();IDENTITY.set(identity);let before=CALLS.get();
        for _ in 0..3{
            assert_eq!(provider_memory_object(&owner),Ok(identity));
            assert_eq!(provider_cache_identity(&owner),Ok((identity!=0).then_some(identity)));
        }
        assert_eq!(CALLS.get(),before+1);
        assert_eq!(owner.memory_identity_unavailable(),identity==0);
    }
    for status in [-95,-38,-13,-11,-4095]{
        let owner=object();STATUS.set(status);let before=CALLS.get();
        assert_eq!(provider_cache_identity(&owner),Err(status as u64));
        assert_eq!(provider_memory_object(&owner),Err(status as u64));
        assert_eq!(CALLS.get(),before+2);assert!(!owner.memory_identity_unavailable());assert_eq!(owner.memory_identity(),None);
    }
    STATUS.set(0);
    for failure in [status::Error::NotReady,status::Error::ResourceUnavailable,status::Error::BackingFailure]{
        let owner=object();FAILURE.set(failure.into_raw());
        assert_eq!(provider_cache_identity(&owner),Err(failure.into_raw()));
        assert!(!owner.memory_identity_unavailable());assert_eq!(owner.memory_identity(),None);
    }
    FAILURE.set(0);let owner=object();MALFORMED.set(true);
    assert_eq!(provider_cache_identity(&owner),Err(status::Error::BackingFailure.into_raw()));
    assert!(!owner.memory_identity_unavailable());assert_eq!(owner.memory_identity(),None);
    MALFORMED.set(false);IDENTITY.set(77);assert_eq!(provider_cache_identity(&owner),Ok(Some(77)));
}
"#);
    probe::run(&program);
}
