#[allow(dead_code)]
#[path = "support/native_error_probe.rs"]
mod probe;

#[test]
fn public_unmap_translates_native_vm_failures_only_at_the_posix_boundary() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap();
    let mut program = format!(
        r#"#![allow(dead_code,non_camel_case_types)]
extern crate self as mochios_posix_client;
extern crate self as mochios_posix_protocol;
extern crate self as mnu_abi;
pub mod status {{
{}
#[path={status:?}]mod wire;
pub use wire::normalize_failure;
}}
pub const STATUS_EIO:i32=-5;pub const STATUS_EAGAIN:i32=-11;
#[path={errno:?}]pub mod newlib_errno;
#[path={memory:?}]pub mod memory;
use std::cell::Cell;
use core::ffi::c_void;
type c_int=i32;
use newlib_errno::EINVAL;
use mnu_abi::status::Error;
thread_local! {{
    static RESULT:Cell<u64>=const{{Cell::new(0)}};
    static ERRNO:Cell<i32>=const{{Cell::new(123)}};
    static CALLS:Cell<usize>=const{{Cell::new(0)}};
    static EXPECTED:Cell<(u64,u64)>=const{{Cell::new((4096,4096))}};
}}
fn result_with_errno<T:Copy>(result:Result<T,i32>,failure:T)->T{{
    match result{{Ok(value)=>value,Err(error)=>{{ERRNO.set(error);failure}}}}
}}
mod syscall {{
use crate::mnu_abi;
use mnu_abi::status::Error as NativeError;
"#,
        include_str!("../../../core/crates/abi/src/status.rs"),
        status = root.join("user/crates/posix-protocol/src/status.rs"),
        errno = root.join("user/crates/posix-client/src/newlib_errno.rs"),
        memory = root.join("user/crates/posix-client/src/memory.rs"),
    );
    // The memory module uses the real native access/option constants too.
    let abi = include_str!("../../../core/crates/abi/src/lib.rs");
    let mut constants = String::new();
    for line in abi.lines().filter(|line| {
        line.starts_with("pub const MEMORY_ACCESS_") || line.starts_with("pub const MEMORY_MAP_")
    }) {
        constants.push_str(line);
        constants.push('\n');
    }
    program = program.replacen("pub mod status {", &format!("{constants}\npub mod status {{"), 1);
    program.push_str(probe::between(
        include_str!("../../../user/crates/syscall/src/lib.rs"),
        "#[derive(Clone, Copy, Debug, PartialEq, Eq)]\npub struct SysError",
        "#[inline(always)]",
    ));
    program.push_str(
        r#"
pub enum SyscallNumber{MemoryUnmap}
pub fn raw_syscall2(_:SyscallNumber,address:u64,length:u64)->RawSyscallResult{
    assert_eq!((address,length),crate::EXPECTED.get());crate::CALLS.set(crate::CALLS.get()+1);
    RawSyscallResult::new(crate::RESULT.get())
}
}
"#,
    );
    program.push_str(probe::between(
        include_str!("../../../user/crates/newlib-runtime/src/lib.rs"),
        "#[unsafe(no_mangle)]\npub extern \"C\" fn munmap(",
        "#[unsafe(no_mangle)]\npub extern \"C\" fn mprotect(",
    ));
    program.push_str(
        r#"
fn main(){
    for (native,expected) in [(Error::InvalidAddress,22),(Error::AccessDenied,1),
        (Error::InvalidArgument,22),(Error::ResourceUnavailable,12),(Error::NotReady,11),
        (Error::BackingFailure,5),(Error::LimitExceeded,139),(Error::AlreadyExists,17),
        (Error::NotFound,2),(Error::PeerClosed,32)] {
        RESULT.set(native.into_raw());ERRNO.set(123);
        assert_eq!(munmap(4096 as *mut c_void,1),-1);assert_eq!(ERRNO.get(),expected);
        assert_eq!(memory::unmap_errno(native.into_raw()as i64),expected);
    }
    // Lower provider I/O failures have not all migrated yet; preserve their
    // existing translation rather than hiding them behind a generic error.
    for (legacy,expected) in [(-5i64,5),(-28,28),(-75,139)] {
        RESULT.set(legacy as u64);assert_eq!(munmap(4096 as *mut c_void,4096),-1);
        assert_eq!(ERRNO.get(),expected);
    }
    let before=CALLS.get();
    for (address,length) in [(0,4096),(4097,1),(4096,0),(4096,usize::MAX)]{
        assert_eq!(munmap(address as *mut c_void,length),-1);assert_eq!(ERRNO.get(),22);
    }
    assert_eq!(CALLS.get(),before);
    RESULT.set(0);ERRNO.set(123);EXPECTED.set((4096,8192));
    assert_eq!(munmap(4096 as *mut c_void,4097),0);assert_eq!(ERRNO.get(),123);
    assert_eq!(CALLS.get(),14);
}
"#,
    );
    // Do not interpose the host libc's munmap during std's own teardown.
    let program = program
        .replace("#[unsafe(no_mangle)]", "")
        .replace("munmap(", "production_munmap(");
    probe::run(&program);
}
