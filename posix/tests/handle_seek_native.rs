#[allow(dead_code)]
#[path = "support/native_error_probe.rs"]
mod probe;

#[test]
fn seek_preserves_signed_offsets_authority_and_opaque_errors_without_forged_success_status() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap();
    let mut program = format!(
        r#"
#![allow(dead_code)]
extern crate self as mnu_abi;
#[path={status:?}]pub mod status;
#[path={provider:?}]pub mod provider;
use status::Error;
use std::cell::Cell;
thread_local!{{
    static ADMISSION:Cell<Option<Error>>=const{{Cell::new(None)}};
    static RESULT:Cell<Result<(u64,usize),u64>>=const{{Cell::new(Ok((0,0)))}};
    static CALLS:Cell<usize>=const{{Cell::new(0)}};
    static OFFSET:Cell<i64>=const{{Cell::new(0)}};
    static BASIS:Cell<u64>=const{{Cell::new(0)}};
}}
#[derive(Debug,PartialEq)]struct HandleRights;
impl HandleRights{{const SEEK:Self=Self;}}
struct ProviderObject{{object_id:u64}}
enum KernelObject{{Provider(ProviderObject),Other}}
fn object_native(raw:u64,right:HandleRights)->Result<KernelObject,Error>{{
    assert_eq!(right,HandleRights::SEEK);
    if let Some(error)=ADMISSION.get(){{return Err(error);}}
    match raw{{1=>Ok(KernelObject::Provider(ProviderObject{{object_id:17}})),
        2=>Ok(KernelObject::Other),_=>Err(Error::InvalidArgument)}}
}}
mod syscall{{pub mod fs{{pub enum SeekBasis{{Start,Current,End}}}}}}
fn provider_call(owner:&ProviderObject,request:provider::RequestHeader,input:&[u8],output:&mut[u8])
    ->Result<(provider::ResponseHeader,usize),u64>{{
    assert_eq!(owner.object_id,17);assert_eq!(request.opcode,provider::OP_SEEK);
    assert_eq!(request.object_id,17);assert_eq!(request.argument,OFFSET.get());
    assert_eq!(request.basis,BASIS.get());assert_eq!((request.length,request.data_length),(0,0));
    assert!(input.is_empty());assert_eq!(output.len(),provider::RESPONSE_HEADER_LEN);
    CALLS.set(CALLS.get()+1);
    RESULT.get().map(|(value,length)|(provider::ResponseHeader{{opcode:request.opcode,
        object_id:17,status:0,value,data_length:length as u32}},length))
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
    let source = include_str!("../../../core/src/syscall/handle.rs");
    program.push_str(probe::between(source, "pub fn seek(", "pub fn read_at("));
    program.push_str(probe::between(
        source,
        "fn provider_seek_result(",
        "/// Reads one positional object",
    ));
    program.push_str(r#"
fn main(){
    for basis in [HANDLE_SEEK_START,HANDLE_SEEK_CURRENT,HANDLE_SEEK_END]{
        BASIS.set(basis);
        for offset in [i64::MIN,-1,0,1,i64::MAX]{
            OFFSET.set(offset);
            for position in [0,17,i64::MAX as u64]{
                RESULT.set(Ok((position,0)));assert_eq!(seek(1,offset as u64,basis),position);
            }
            for position in [i64::MAX as u64+1,u64::MAX,(-5i64)as u64,Error::NotReady.into_raw()]{
                RESULT.set(Ok((position,0)));
                assert_eq!(seek(1,offset as u64,basis),Error::LimitExceeded.into_raw());
            }
            RESULT.set(Ok((0,1)));assert_eq!(seek(1,offset as u64,basis),Error::BackingFailure.into_raw());
            for error in [(-29i64)as u64,(-22i64)as u64,Error::PeerClosed.into_raw(),Error::NotReady.into_raw()]{
                RESULT.set(Err(error));assert_eq!(seek(1,offset as u64,basis),error);
            }
        }
    }
    let before=CALLS.get();
    for basis in [0,1,2,u64::MAX]{assert_eq!(seek(1,0,basis),Error::InvalidArgument.into_raw());}
    assert_eq!(seek(0,0,HANDLE_SEEK_START),Error::InvalidArgument.into_raw());
    assert_eq!(seek(2,0,HANDLE_SEEK_START),Error::InvalidArgument.into_raw());
    for error in [Error::InvalidArgument,Error::AccessDenied,Error::NotReady]{
        ADMISSION.set(Some(error));assert_eq!(seek(1,0,HANDLE_SEEK_START),error.into_raw());
    }
    assert_eq!(CALLS.get(),before);
}
"#);
    probe::run(&program);
}
