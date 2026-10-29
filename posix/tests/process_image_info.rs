//! Committed-image observation: native authority, coherent publication and wire validation.
#[allow(dead_code)]
#[path = "support/native_error_probe.rs"]
mod probe;

#[test]
fn layout_extends_native_operations_without_changing_status_or_identity() {
    use std::mem::{align_of, offset_of, size_of};
    assert_eq!(mnu_abi::SyscallNumber::ProcessImageRead as u64, 705);
    assert_eq!(size_of::<mnu_abi::ProcessImageInfo>(), 56);
    assert_eq!(align_of::<mnu_abi::ProcessImageInfo>(), 8);
    assert_eq!(offset_of!(mnu_abi::ProcessImageInfo, digest), 24);
    assert_eq!(size_of::<mnu_abi::ProcessStatus>(), 32);
    assert_eq!(size_of::<mnu_abi::ThreadSecurityContext>(), 320);
}

#[test]
fn native_reader_preserves_authority_liveness_copy_errors_and_commit_coherence() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap();
    let program = include_str!("support/process_image_info_native.rs")
        .replace(
            "ABI_SOURCE",
            &format!("{:?}", root.join("core/crates/abi/src/lib.rs")),
        )
        .replace(
            "READER_SOURCE",
            &format!(
                "{:?}",
                root.join("core/src/syscall/handle/process_image.rs")
            ),
        );
    probe::run(&program);
}

#[test]
fn client_rejects_malformed_records_and_never_retries_authority_failures_as_self() {
    let mut program = probe::program().replace(
        "mod mnu_abi {pub mod status {",
        "mod mnu_abi {pub const SUCCESS:u64=0;pub const PROCESS_IMAGE_DIGEST_NONE:u32=0;pub const PROCESS_IMAGE_DIGEST_SHA256:u32=1;pub mod status {",
    );
    program.push_str(r#"
use std::cell::Cell;
use mnu_abi::status::Error;
#[repr(C)]#[derive(Default,Debug,PartialEq,Clone,Copy)]pub struct ProcessImageInfo{process_id:u64,image_revision:u64,digest_kind:u32,reserved:u32,digest:[u8;32]}
enum SyscallNumber{ProcessImageRead}
thread_local!{
 static CALLS:Cell<usize>=const{Cell::new(0)};
 static FAILURE:Cell<Option<Error>>=const{Cell::new(None)};
 static STATUS:Cell<u64>=const{Cell::new(0)};
 static REPLY:Cell<ProcessImageInfo>=const{Cell::new(ProcessImageInfo{process_id:17,image_revision:4,digest_kind:1,reserved:0,digest:[8;32]})};
}
fn call3(_:SyscallNumber,handle:u64,out:u64,length:u64)->SysResult<u64>{
 assert!([0,42].contains(&handle));assert_eq!(length,56);CALLS.set(CALLS.get()+1);
 if let Some(error)=FAILURE.get(){return Err(SysError::from_raw(error.into_raw()as i64));}
 unsafe{*(out as *mut ProcessImageInfo)=REPLY.get();} Ok(STATUS.get())
}
mod actual{use crate::{mnu_abi,SysError,SysResult,SyscallNumber,Error};
"#);
    program.push_str(probe::between(
        include_str!("../../../user/crates/syscall/src/execution.rs"),
        "pub fn image_info(",
        "/// No process lookup:",
    ));
    program.push_str(r#"
}
fn main(){
 assert_eq!(actual::image_info(Some(0)).unwrap_err().native_error(),Some(Error::InvalidArgument));assert_eq!(CALLS.get(),0);
 let good=REPLY.get();
 for h in [None,Some(42)]{assert_eq!(actual::image_info(h).unwrap(),good);}
 for error in [Error::InvalidArgument,Error::AccessDenied,Error::NotFound,Error::NotReady,Error::InvalidAddress,Error::ResourceUnavailable,Error::BackingFailure]{
  FAILURE.set(Some(error));let before=CALLS.get();let e=actual::image_info(Some(42)).unwrap_err();assert_eq!(e.native_error(),Some(error));assert_eq!(CALLS.get(),before+1);
 }
 FAILURE.set(None);
 for bad in [ProcessImageInfo{process_id:0,..good},ProcessImageInfo{reserved:1,..good},ProcessImageInfo{digest_kind:2,..good},ProcessImageInfo{digest_kind:0,..good}]{
  REPLY.set(bad);assert_eq!(actual::image_info(None).unwrap_err().native_error(),Some(Error::BackingFailure));
 }
 for kind in [0,1]{let zero=ProcessImageInfo{digest_kind:kind,digest:[0;32],..good};REPLY.set(zero);assert_eq!(actual::image_info(None).unwrap(),zero);}
 REPLY.set(good);STATUS.set(1);assert_eq!(actual::image_info(None).unwrap_err().native_error(),Some(Error::BackingFailure));
}
"#);
    probe::run(&program);
}
