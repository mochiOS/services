//! Actual boot/CPU query functions and processor sysconf path. Boot metadata,
//! CPU online sampling and usercopy are host-controlled, not a boot smoke test.
#[allow(dead_code)]
#[path = "support/native_error_probe.rs"]
mod probe;

#[test]
fn boot_queries_preserve_native_failures_and_sysconf_translates_them() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap();
    let mut program = format!(
        "#![allow(dead_code,unused_attributes,non_camel_case_types)]\nextern crate self as mnu_abi;\n#[path={:?}]mod abi;\npub use abi::*;\nuse status::Error;use Error as NativeError;\nuse boot::BOOT_FEATURE_BOOT_ESP_GUID;\n",
        root.join("core/crates/abi/src/lib.rs"),
    );
    program.push_str(
        r#"
use std::cell::Cell;
#[derive(Clone,Copy)]struct Boot{cpu_total:u32,feature_flags:u64,boot_esp_guid:[u8;16]}
const GOOD:Boot=Boot{cpu_total:8,feature_flags:BOOT_FEATURE_BOOT_ESP_GUID,boot_esp_guid:[0x71;16]};
thread_local!{
    static BOOT:Cell<Option<Boot>>=const{Cell::new(Some(GOOD))};
    static ONLINE:Cell<u32>=const{Cell::new(3)};
    static COPIES:Cell<usize>=const{Cell::new(0)};
    static COPY_ERROR:Cell<Option<Error>>=const{Cell::new(None)};
    static ERRNO:Cell<i32>=const{Cell::new(0)};
}
mod smp{pub fn boot_info()->Option<crate::Boot>{crate::BOOT.get()}}
mod mem{pub mod tlb_shootdown{pub fn online_cpu_count()->u32{crate::ONLINE.get()}}}
mod percpu{
"#,
    );
    probe::constants(
        &mut program,
        include_str!("../../../core/src/percpu.rs"),
        &["MAX_CPUS"],
    );
    program.push_str(r#"
}
fn copy_to_user_native(p:u64,b:&[u8])->Result<(),Error>{
    COPIES.set(COPIES.get()+1);if let Some(e)=COPY_ERROR.get(){return Err(e)}
    if p==0||p.checked_add(b.len() as u64-1).is_none(){return Err(Error::InvalidAddress)}
    unsafe{std::ptr::copy_nonoverlapping(b.as_ptr(),p as *mut u8,b.len())};Ok(())
}
mod syscall{
    pub use crate::{RawSyscallResult,SysError,SysResult,ProcessorInfo,SyscallNumber};
    pub fn raw_syscall2(n:SyscallNumber,p:u64,len:u64)->RawSyscallResult{
        assert_eq!(n as u64,SyscallNumber::ProcessorDescribe as u64);RawSyscallResult::new(crate::processor_describe(p,len))
    }
}
pub const STATUS_EIO:i32=-5;pub const STATUS_EAGAIN:i32=-11;
mod mochios_posix_protocol{pub mod status{
"#);
    program.push_str(include_str!(
        "../../../user/crates/posix-protocol/src/status.rs"
    ));
    program.push_str("}}\nmod mochios_posix_client{pub mod configuration{\n");
    program.push_str(probe::between(
        include_str!("../../../user/crates/posix-client/src/configuration.rs"),
        "pub fn processor_count(",
        "/// Process-local limits",
    ));
    program.push_str("pub fn local_limit(_:i32)->Option<usize>{None}\n}\npub mod newlib_errno{use crate::mochios_posix_protocol;\n");
    program.push_str(include_str!(
        "../../../user/crates/posix-client/src/newlib_errno.rs"
    ));
    program.push_str("}}\n");
    program.push_str("mod configuration_regression{use crate::mochios_posix_client;\n");
    program.push_str(&include_str!("processor_configuration.rs").replace("#[test]", ""));
    program.push_str("pub fn run(){processor_snapshot_is_generic_fixed_layout_and_sysconf_translation_is_local();absent_or_inconsistent_processor_information_is_not_faked_as_one_cpu();}}\n");
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
    let kernel = include_str!("../../../core/src/syscall/mod.rs");
    program.push_str(probe::between(
        kernel,
        "fn processor_describe(",
        "/// Read-only boot identity.",
    ));
    program.push_str(probe::between(
        kernel,
        "fn boot_esp_guid(",
        "#[cfg(feature = \"performance-instrumentation\")]",
    ));
    let runtime = include_str!("../../../user/crates/newlib-runtime/src/lib.rs");
    program.push_str("type c_int=i32;type CLong=i64;const PAGE_SIZE:usize=4096;const EINVAL:i32=22;\nfn set_errno(n:i32){ERRNO.set(n)}\nfn process_fd_limit()->Result<i32,i32>{unreachable!()}\n");
    probe::constants(
        &mut program,
        runtime,
        &[
            "SC_OPEN_MAX",
            "SC_PAGESIZE",
            "SC_NPROCESSORS_CONF",
            "SC_NPROCESSORS_ONLN",
            "SC_THREAD_STACK_MIN",
            "SC_GETPW_R_SIZE_MAX",
            "SC_HOST_NAME_MAX",
        ],
    );
    program.push_str(probe::between(
        runtime,
        "fn map_kernel_errno(",
        "fn map_posix_client_error(",
    ));
    program.push_str(probe::between(
        runtime,
        "fn syscall_errno(",
        "unsafe fn parse_stack(",
    ));
    program.push_str(probe::between(
        runtime,
        "pub extern \"C\" fn sysconf(",
        "fn process_fd_limit(",
    ));
    program.push_str(r#"
fn reset(){BOOT.set(Some(GOOD));ONLINE.set(3);COPIES.set(0);COPY_ERROR.set(None);ERRNO.set(0)}
fn main(){
    configuration_regression::run();
    let mut output=[0xcc_u8;16];let p=output.as_mut_ptr() as u64;
    for query in [processor_describe as fn(u64,u64)->u64,boot_esp_guid]{
        for n in [0,15,17,u64::MAX]{reset();assert_eq!(query(p,n),Error::InvalidArgument.into_raw());assert_eq!(COPIES.get(),0);assert_eq!(output,[0xcc;16]);}
        reset();BOOT.set(None);assert_eq!(query(p,16),Error::NotReady.into_raw());assert_eq!(COPIES.get(),0);
        for error in [Error::InvalidAddress,Error::ResourceUnavailable,Error::AccessDenied,Error::BackingFailure,Error::NotReady,Error::Unsupported]{
            reset();COPY_ERROR.set(Some(error));assert_eq!(query(p,16),error.into_raw());assert_eq!(output,[0xcc;16]);
        }
        reset();assert_eq!(query(0,16),Error::InvalidAddress.into_raw());
    }
    for (configured,online) in [(0,0),(2,0),(2,3),(100,65)]{
        reset();BOOT.set(Some(Boot{cpu_total:configured,..GOOD}));ONLINE.set(online);assert_eq!(processor_describe(p,16),Error::NotReady.into_raw());assert_eq!(COPIES.get(),0);
        assert_eq!(sysconf(9),-1);assert_eq!(ERRNO.get(),11);assert_eq!(sysconf(10),-1);assert_eq!(ERRNO.get(),11);
    }
    for (configured,online,expected) in [(1,1,1),(8,3,8),(100,64,64)]{
        reset();BOOT.set(Some(Boot{cpu_total:configured,..GOOD}));ONLINE.set(online);assert_eq!(processor_describe(p,16),0);
        let info=unsafe{std::ptr::read_unaligned(output.as_ptr().cast::<ProcessorInfo>())};assert_eq!(info,ProcessorInfo{configured:expected,online,reserved:[0;2]});
        assert_eq!(sysconf(9),i64::from(expected));assert_eq!(sysconf(10),i64::from(online));assert_eq!(ERRNO.get(),0);
    }
    for error in [Error::InvalidAddress,Error::ResourceUnavailable,Error::AccessDenied,Error::BackingFailure,Error::Unsupported]{
        reset();COPY_ERROR.set(Some(error));assert_eq!(sysconf(9),-1);assert_eq!(ERRNO.get(),mochios_posix_client::newlib_errno::from_status(error.into_raw() as i64));
    }
    reset();BOOT.set(None);assert_eq!(sysconf(9),-1);assert_eq!(ERRNO.get(),11);
    for boot in [Boot{feature_flags:0,..GOOD},Boot{boot_esp_guid:[0;16],..GOOD}]{
        reset();output.fill(0xcc);BOOT.set(Some(boot));assert_eq!(boot_esp_guid(p,16),Error::Unsupported.into_raw());assert_eq!(COPIES.get(),0);assert_eq!(output,[0xcc;16]);
    }
    reset();assert_eq!(boot_esp_guid(p,16),0);assert_eq!(output,GOOD.boot_esp_guid);
}
"#);
    probe::run(&program);
}
