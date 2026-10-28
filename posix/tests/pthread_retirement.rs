const RUNTIME: &str = include_str!("../../../user/crates/newlib-runtime/src/lib.rs");

#[allow(dead_code)]
#[path = "support/native_error_probe.rs"]
mod probe;

#[test]
fn only_native_target_absence_or_termination_allows_stack_reclamation() {
    let mut program = probe::program()
        .replace(
            "mod mnu_abi {pub mod status {",
            "mod mnu_abi {pub const THREAD_STATE_TERMINATED:u32=5;pub mod status {",
        )
        .replace(
            "mod mochios_posix_protocol {",
            "mod mochios_posix_protocol {pub use crate::wire_status as status;",
        );
    program.push_str("const STATUS_EIO:i32=-5;const STATUS_EAGAIN:i32=-11;pub mod wire_status {use crate::mnu_abi;\n");
    for line in include_str!("../../../user/crates/posix-protocol/src/status.rs").lines() {
        if !line.starts_with("//!") {
            program.push_str(line);
            program.push('\n');
        }
    }
    program.push_str("}\nmod newlib_errno {use crate::mochios_posix_protocol;\n");
    for line in include_str!("../../../user/crates/posix-client/src/newlib_errno.rs").lines() {
        if !line.starts_with("//!") {
            program.push_str(line);
            program.push('\n');
        }
    }
    program.push_str("}\nmod raw {use crate::{mochi_user_syscall::*,mnu_abi};\n");
    program.push_str(probe::between(
        include_str!("../../../user/crates/syscall/src/lib.rs"),
        "#[derive(Clone, Copy, Debug, PartialEq, Eq)]\npub struct RawSyscallResult",
        "#[inline(always)]",
    ));
    program.push_str(
        r#"
}
use std::{cell::Cell,sync::atomic::{AtomicU32,Ordering}};
use std::ffi::c_int;
const ESRCH:c_int=3;
struct ThreadControl{native_handle:AtomicU32}
mod thread_reference {
    use super::*;
    pub fn with_control<T>(control:&ThreadControl,observe:impl FnOnce(u32)->Result<T,c_int>)->Result<T,c_int>{
        let handle=control.native_handle.load(Ordering::Acquire);
        if handle==0{return Err(ESRCH)}observe(handle)
    }
}
thread_local!{
    static RESULT:Cell<u64>=const{Cell::new(0)};
    static STATE:Cell<u32>=const{Cell::new(2)};
    static CALLS:Cell<usize>=const{Cell::new(0)};
}
fn map_kernel_errno(raw:i64)->c_int{newlib_errno::from_status(raw)}
mod syscall {
    pub enum SyscallNumber {ThreadHandleStatus}
    #[derive(Default)]pub struct ThreadStatus {pub state:u32}
    pub fn raw_syscall2(_:SyscallNumber,handle:u64,output:u64)->crate::raw::RawSyscallResult{
        assert_eq!(handle,7);crate::CALLS.set(crate::CALLS.get()+1);
        // Writes only the state field consumed by the production adapter.
        unsafe{(*(output as *mut ThreadStatus)).state=crate::STATE.get();}
        crate::raw::RawSyscallResult::new(crate::RESULT.get())
    }
}
"#,
    );
    program.push_str(probe::between(
        RUNTIME,
        "fn native_thread_retired(",
        "unsafe extern \"C\" fn pthread_start_trampoline(",
    ));
    program.push_str(
        r#"
fn main(){
    use mnu_abi::status::Error;
    let control=ThreadControl{native_handle:AtomicU32::new(7)};
    for state in 1..=5{STATE.set(state);assert_eq!(native_thread_retired(&control),Ok(state==5));}
    for (error,errno) in [(Error::InvalidArgument,22),(Error::AccessDenied,13),(Error::NotReady,11),
        (Error::InvalidAddress,14),(Error::ResourceUnavailable,12),(Error::BackingFailure,5)] {
        RESULT.set(error.into_raw());assert_eq!(native_thread_retired(&control),Err(errno));
    }
    // Unknown native codes and old raw errno must never prove target absence.
    for raw in [(Error::NotFound.into_raw()&!0xffff)|11,(-3i64)as u64,(-2i64)as u64] {
        RESULT.set(raw);assert!(native_thread_retired(&control).is_err());
    }
    RESULT.set(Error::NotFound.into_raw());assert_eq!(native_thread_retired(&control),Ok(true));
    control.native_handle.store(0,Ordering::Release);let calls=CALLS.get();
    assert_eq!(native_thread_retired(&control),Err(ESRCH));assert_eq!(CALLS.get(),calls);
}
"#,
    );
    probe::run(&program);
}

#[test]
fn join_waits_for_native_retirement_before_reclaiming_user_mappings() {
    let join = include_str!("../../../user/crates/newlib-runtime/src/thread_join.rs");
    assert!(join.contains("native_thread_retired(target)?"));
    assert!(join.contains("creation_pending.load(Ordering::Acquire) == 0"));
    assert!(join.contains("SyscallNumber::ThreadYield"));
    assert!(
        join.find("native_thread_retired(target)").unwrap()
            < join.find("release_thread_control(target)").unwrap()
    );
    let check = RUNTIME
        .split("fn native_thread_retired(")
        .nth(1)
        .unwrap()
        .split("#[unsafe(no_mangle)]")
        .next()
        .unwrap();
    assert!(check.contains("ThreadHandleStatus"));
    assert!(check.contains("mnu_abi::THREAD_STATE_TERMINATED"));
    assert!(check.contains("error.native_error() == Some(mnu_abi::status::Error::NotFound)"));
    assert!(check.contains("Err(error) => Err(map_kernel_errno(error.raw()))"));
}

#[test]
fn detached_reclamation_requires_native_retirement_and_closes_owned_handle() {
    let source = RUNTIME
        .split("fn reap_detached_threads()")
        .nth(1)
        .unwrap()
        .split("fn current_thread_control()")
        .next()
        .unwrap();
    let claim = source.find("THREAD_REAP_CLAIMED").unwrap();
    let check = source
        .find("native_thread_retired(control) == Ok(true)")
        .unwrap();
    let release = source.find("release_thread_control(control)").unwrap();
    assert!(claim < check && check < release);
    assert!(source.contains("control.joinability.store(THREAD_DETACHED, Ordering::Release)"));
    assert!(check < source.find("control.state.store(THREAD_REAPING").unwrap());
    let detach = RUNTIME
        .split("fn pthread_detach(")
        .nth(1)
        .unwrap()
        .split("fn pthread_exit(")
        .next()
        .unwrap();
    assert!(detach.contains("reap_detached_threads()"));
    let lookup = RUNTIME
        .split("fn current_thread_control()")
        .nth(1)
        .unwrap()
        .split("fn register_current_thread()")
        .next()
        .unwrap();
    assert!(lookup.contains("state != THREAD_REAPING"));
    let release = RUNTIME
        .split("fn release_thread_control(")
        .nth(1)
        .unwrap()
        .split("fn allocate_thread_reent(")
        .next()
        .unwrap();
    assert!(release.contains("thread_reference::replace(control, 0)"));
    let references = include_str!("../../../user/crates/newlib-runtime/src/thread_reference.rs");
    assert!(references.contains("native_handle.swap(handle, Ordering::AcqRel)"));
    assert!(references.contains("close_object_handle(previous)"));
}
