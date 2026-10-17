//! Compile the production entry point with sampling both enabled and disabled.
//! Sample collection, usercopy and caller authority are controlled backends.
#[allow(dead_code)]
#[path = "support/native_error_probe.rs"]
mod probe;

#[test]
fn performance_snapshot_preserves_native_errors_in_both_build_modes() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap();
    let mut program = format!(
        "#![allow(dead_code,unused_attributes)]\nextern crate self as mnu_abi;\n#[path={:?}]mod abi;\npub use abi::*;\n#[path={:?}]mod entry;\nuse status::Error;\nuse Error as NativeError;\n",
        root.join("core/crates/abi/src/lib.rs"),
        root.join("core/src/syscall/performance.rs"),
    );
    program.push_str(r#"
use std::cell::Cell;
thread_local! {
    static ALLOWED:Cell<bool>=const{Cell::new(true)};
    static SAMPLES:Cell<usize>=const{Cell::new(0)};
    static COPIES:Cell<usize>=const{Cell::new(0)};
    static ERROR:Cell<Option<Error>>=const{Cell::new(None)};
}
mod capability{#[derive(Debug,PartialEq)]pub enum Capability{DeveloperProfile}}
mod performance {
    pub use crate::abi::performance::*;
    pub fn snapshot()->KernelPerformanceSnapshot{
        crate::SAMPLES.set(crate::SAMPLES.get()+1);
        KernelPerformanceSnapshot{version:PERFORMANCE_SNAPSHOT_VERSION,size:core::mem::size_of::<KernelPerformanceSnapshot>() as u32,flags:PERFORMANCE_FLAG_INSTRUMENTED,tsc_frequency_khz:12345,..KernelPerformanceSnapshot::default()}
    }
}
mod syscall {
    pub mod security{
        pub fn caller_has_any_capability(caps:&[crate::capability::Capability])->bool{assert_eq!(caps,[crate::capability::Capability::DeveloperProfile]);crate::ALLOWED.get()}
    }
    pub fn copy_to_user_native(p:u64,bytes:&[u8])->Result<(),crate::Error>{
        crate::COPIES.set(crate::COPIES.get()+1);
        if let Some(e)=crate::ERROR.get(){return Err(e)}
        if p==0||p.checked_add(bytes.len() as u64-1).is_none(){return Err(crate::Error::InvalidAddress)}
        unsafe{std::ptr::copy_nonoverlapping(bytes.as_ptr(),p as *mut u8,bytes.len())};Ok(())
    }
}
pub const STATUS_EIO:i32=-5;pub const STATUS_EAGAIN:i32=-11;
mod mochios_posix_protocol{pub mod status {
"#);
    program.push_str(include_str!(
        "../../../user/crates/posix-protocol/src/status.rs"
    ));
    program.push_str("}}\npub mod newlib_errno {use crate::mochios_posix_protocol;\n");
    program.push_str(include_str!(
        "../../../user/crates/posix-client/src/newlib_errno.rs"
    ));
    program.push_str("}\n");
    program.push_str("mod mochi_user_syscall {pub use crate::{RawSyscallResult,SysError};}\nmod mochios_posix_client {pub use crate::newlib_errno;}\nmod status_regression {use crate::{mochi_user_syscall,mochios_posix_client,mochios_posix_protocol};\n");
    program.push_str(&include_str!("native_status.rs").replace("#[test]", ""));
    program.push_str("pub fn run(){mechanism_failure_is_typed_not_an_errno_and_survives_signed_wire_status();unknown_native_codes_remain_errors_without_becoming_posix_numbers();native_categories_translate_only_at_posix_boundary();high_bit_success_values_and_legacy_errors_keep_their_existing_contract();wire_normalization_is_idempotent_and_distinct_from_c_errno();}}\n");
    // Inner module documentation belongs before imports in the assembled module.
    program = program
        .lines()
        .filter(|line| !line.starts_with("//!"))
        .collect::<Vec<_>>()
        .join("\n");
    program.push('\n');
    program.push_str(probe::between(
        include_str!("../../../user/crates/syscall/src/lib.rs"),
        "#[derive(Clone, Copy, Debug, PartialEq, Eq)]",
        "#[inline(always)]",
    ));
    program.push_str(
        r#"
extern crate self as mochi_user_platform;
mod platform_error {use crate::SysError;pub fn convert(error:SysError)->i32{native_error(error)}
"#,
    );
    let filesystem = include_str!("../../filesystem/src/memory_updates.rs");
    program.push_str(&filesystem[filesystem.find("fn native_error(").unwrap()..]);
    program.push_str("}\n");
    program.push_str(r#"
fn reset(){ALLOWED.set(true);SAMPLES.set(0);COPIES.set(0);ERROR.set(None);}
fn main(){
    status_regression::run();
    use performance::*;
    let minimum=PERFORMANCE_SNAPSHOT_V1_SIZE as u64;let size=core::mem::size_of::<KernelPerformanceSnapshot>();
    let mut output=vec![0xcc_u8;size+32];let p=output.as_mut_ptr() as u64;
    reset();ALLOWED.set(false);assert_eq!(entry::snapshot(p,minimum),Error::AccessDenied.into_raw());assert_eq!((SAMPLES.get(),COPIES.get()),(0,0));
    for n in [0,minimum-1]{reset();assert_eq!(entry::snapshot(p,n),Error::InvalidArgument.into_raw());assert_eq!((SAMPLES.get(),COPIES.get()),(0,0));}
    #[cfg(feature="performance-instrumentation")]{
        for n in [minimum,size as u64-1,size as u64,size as u64+32,u64::MAX] {
            reset();output.fill(0xcc);assert_eq!(entry::snapshot(p,n),0);assert_eq!((SAMPLES.get(),COPIES.get()),(1,1));
            assert_eq!(u32::from_ne_bytes(output[..4].try_into().unwrap()),PERFORMANCE_SNAPSHOT_VERSION);
            assert_eq!(u64::from_ne_bytes(output[16..24].try_into().unwrap()),12345);
            assert!(output[(n.min(size as u64) as usize)..].iter().all(|b|*b==0xcc));
        }
        for error in [Error::InvalidAddress,Error::ResourceUnavailable,Error::BackingFailure,Error::AccessDenied,Error::NotReady,Error::Unsupported] {
            reset();output.fill(0xcc);ERROR.set(Some(error));assert_eq!(entry::snapshot(p,minimum),error.into_raw());assert!(output.iter().all(|b|*b==0xcc));
        }
        reset();assert_eq!(entry::snapshot(0,minimum),Error::InvalidAddress.into_raw());
    }
    #[cfg(not(feature="performance-instrumentation"))]{
        for n in [minimum,size as u64,u64::MAX]{reset();assert_eq!(entry::snapshot(p,n),Error::Unsupported.into_raw());assert_eq!((SAMPLES.get(),COPIES.get()),(0,0));}
        assert!(output.iter().all(|b|*b==0xcc));
    }
    let raw=Error::Unsupported.into_raw();assert_eq!(raw as i64,-262133);assert_eq!(raw,i64::from(raw as i32) as u64);
    let error=RawSyscallResult::new(raw).into_result().unwrap_err();assert_eq!(error.native_error(),Some(Error::Unsupported));assert_eq!(error.errno(),None);
    assert_ne!(Error::Unsupported,Error::NotReady);
    for value in [raw as i64,-(raw as i64)]{assert_eq!(mochios_posix_protocol::status::normalize_failure(value),-95);assert_eq!(newlib_errno::from_status(value),newlib_errno::ENOTSUP);}
    assert_eq!(platform_error::convert(error),95);
    let unknown=(raw&!0xffff)|12;assert_eq!(Error::from_raw(unknown),None);assert!(RawSyscallResult::new(unknown).into_result().is_err());assert_eq!(newlib_errno::from_status(unknown as i64),newlib_errno::EIO);
}
"#);
    // filesystem's production converter names the platform syscall module.
    // Re-export the actual SysError into that module, alongside usercopy stubs.
    program = program.replace("mod syscall {", "mod syscall {pub use crate::SysError;");
    probe::run(&program);
    probe::run_with_cfg(&program, "feature=\"performance-instrumentation\"");
}
