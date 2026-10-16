#[allow(dead_code)]
#[path = "support/native_error_probe.rs"]
mod probe;

#[test]
fn provider_buffers_fail_recoverably_and_malformed_replies_use_native_errors() {
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
use status::Error;
use std::cell::Cell;
thread_local!{{
    static FAIL:Cell<Option<usize>>=const{{Cell::new(None)}};
    static MODE:Cell<u8>=const{{Cell::new(0)}};
    static FAILURE:Cell<u64>=const{{Cell::new(0)}};
    static CALLS:Cell<usize>=const{{Cell::new(0)}};
    static OP:Cell<u16>=const{{Cell::new(0)}};
}}
struct Allocator;
fn fail()->bool{{FAIL.try_with(|slot|match slot.get(){{
    Some(0)=>true,Some(n)=>{{slot.set(Some(n-1));false}},None=>false
}}).unwrap_or(false)}}
unsafe impl std::alloc::GlobalAlloc for Allocator{{
    unsafe fn alloc(&self,l:std::alloc::Layout)->*mut u8{{if fail(){{core::ptr::null_mut()}}else{{unsafe{{std::alloc::System.alloc(l)}}}}}}
    unsafe fn realloc(&self,p:*mut u8,l:std::alloc::Layout,n:usize)->*mut u8{{if fail(){{core::ptr::null_mut()}}else{{unsafe{{std::alloc::System.realloc(p,l,n)}}}}}}
    unsafe fn dealloc(&self,p:*mut u8,l:std::alloc::Layout){{unsafe{{std::alloc::System.dealloc(p,l)}}}}
}}
#[global_allocator]static ALLOCATOR:Allocator=Allocator;
struct ProviderObject{{endpoint_thread_id:u64,endpoint_slot:u16,endpoint_generation:u64,object_id:u64}}
mod syscall{{pub mod ipc{{
    #[derive(Debug,PartialEq)]pub struct IpcEndpoint{{pub thread_id:u64,pub slot:u16,pub generation:u64}}
    pub fn call_provider_from_kernel(endpoint:IpcEndpoint,request:&[u8],reply:&mut[u8])->Result<usize,u64>{{
        use crate::*;
        assert_eq!(endpoint,IpcEndpoint{{thread_id:99,slot:7,generation:123}});
        CALLS.set(CALLS.get()+1);
        let (request,data)=provider::RequestHeader::decode(request).unwrap();
        assert_eq!(request.object_id,17);assert_eq!(request.opcode,OP.get());
        if MODE.get()==10{{return Err(FAILURE.get());}}
        if MODE.get()==4{{return Ok(reply.len()+1);}}
        if MODE.get()==5{{return Ok(0);}}
        if request.opcode!=provider::OP_SYNC{{assert_eq!(request.basis,8192);}}
        if request.opcode==provider::OP_WRITE_AT{{assert_eq!(data,[0x5a;17]);}}
        let payload=if request.opcode==provider::OP_READ_AT{{&b"abc"[..]}}else{{&[][..]}};
        let status=if MODE.get()==11{{FAILURE.get()as i64}}else{{0}};
        let payload=if status!=0||MODE.get()==2{{&[][..]}}else{{payload}};
        let mut header=provider::ResponseHeader{{
            opcode:request.opcode,status,object_id:17,
            value:if status!=0{{0}}else if request.opcode==provider::OP_READ_AT{{payload.len()as u64}}
                else if request.opcode==provider::OP_WRITE_AT{{data.len()as u64}}else{{0}},
            data_length:payload.len()as u32,
        }};
        match MODE.get(){{
            2=>{{header.opcode=provider::OP_SEEK;header.value=0;}},
            3=>header.object_id=18,
            8=>header.value=1,
            9=>header.value=data.len()as u64+1,
            _=>{{}}
        }}
        let length=header.encode(payload,reply).unwrap();
        match MODE.get(){{1=>reply[0]^=1,7=>reply[24..32].copy_from_slice(&99u64.to_le_bytes()),_=>{{}}}}
        Ok(length)
    }}
}}}}
"#,
        status = root.join("core/crates/abi/src/status.rs"),
        provider = root.join("core/crates/abi/src/provider.rs"),
    );
    probe::constants(
        &mut program,
        include_str!("../../../core/crates/abi/src/lib.rs"),
        &["HANDLE_SEEK_START", "HANDLE_SEEK_CURRENT", "HANDLE_SEEK_END"],
    );
    program.push_str(probe::between(
        include_str!("../../../core/src/syscall/handle.rs"),
        "fn provider_endpoint(",
        "pub(crate) fn provider_memory_object(",
    ));
    program.push_str(r#"
fn invoke(owner:&ProviderObject,opcode:u16)->Result<usize,u64>{
    OP.set(opcode);
    match opcode{
        provider::OP_READ_AT=>{
            let mut output=[0x71;16];let result=provider_read_at(owner,8192,&mut output);
            if result.is_err(){assert_eq!(output,[0x71;16]);}
            else{assert_eq!(&output[..3],b"abc");assert_eq!(&output[3..],&[0x71;13]);}
            result
        }
        provider::OP_WRITE_AT=>provider_write_at(owner,8192,&[0x5a;17]),
        provider::OP_SYNC=>provider_sync(owner).map(|()|0),
        _=>unreachable!(),
    }
}
fn main(){
    let owner=ProviderObject{endpoint_thread_id:99,endpoint_slot:7,endpoint_generation:123,object_id:17};
    for opcode in [provider::OP_READ_AT,provider::OP_WRITE_AT,provider::OP_SYNC]{
        MODE.set(0);assert_eq!(invoke(&owner,opcode),Ok(match opcode{provider::OP_READ_AT=>3,provider::OP_WRITE_AT=>17,_=>0}));
        for fail_at in 0..if opcode==provider::OP_READ_AT{2}else{1}{
            let before=CALLS.get();FAIL.set(Some(fail_at));let result=invoke(&owner,opcode);FAIL.set(None);
            assert_eq!(result,Err(Error::ResourceUnavailable.into_raw()));assert_eq!(CALLS.get(),before);
        }
        for mode in [1,2,3,4,5]{
            MODE.set(mode);assert_eq!(invoke(&owner,opcode),Err(Error::BackingFailure.into_raw()));
        }
        for error in [Error::LimitExceeded,Error::InvalidAddress,Error::ResourceUnavailable,
            Error::BackingFailure,Error::InvalidArgument,Error::AccessDenied,Error::NotReady,
            Error::AlreadyExists,Error::NotFound,Error::PeerClosed]{
            MODE.set(10);FAILURE.set(error.into_raw());assert_eq!(invoke(&owner,opcode),Err(error.into_raw()));
        }
        for status in [-28i64,-95,provider::STATUS_BOUND_REACHED]{
            MODE.set(11);FAILURE.set(status as u64);assert_eq!(invoke(&owner,opcode),Err(status as u64));
        }
    }
    MODE.set(7);assert_eq!(invoke(&owner,provider::OP_READ_AT),Err(Error::BackingFailure.into_raw()));
    MODE.set(8);assert_eq!(invoke(&owner,provider::OP_SYNC),Err(Error::BackingFailure.into_raw()));
    MODE.set(9);assert_eq!(invoke(&owner,provider::OP_WRITE_AT),Err(Error::BackingFailure.into_raw()));
    MODE.set(0);let before=CALLS.get();
    let large=[0u8;provider::MAX_DATA_LEN+1];
    assert_eq!(provider_write_at(&owner,8192,&large),Err(Error::LimitExceeded.into_raw()));
    let mut output=large;assert_eq!(provider_read_at(&owner,8192,&mut output),Err(Error::LimitExceeded.into_raw()));
    let request=provider::RequestHeader{opcode:provider::OP_WRITE_AT,object_id:17,argument:0,basis:8192,length:1,data_length:1};
    let mut reply=[0u8;provider::RESPONSE_HEADER_LEN];
    assert_eq!(provider_call(&owner,request,&large,&mut reply),Err(Error::LimitExceeded.into_raw()));
    assert_eq!(provider_call(&owner,request,&[],&mut reply),Err(Error::InvalidArgument.into_raw()));
    assert_eq!(CALLS.get(),before);
}
"#);
    probe::run(&program);
}
