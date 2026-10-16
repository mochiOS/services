//! Execute the service's real wait-result adapter with controlled native calls.
#[allow(dead_code)]
#[path = "support/native_error_probe.rs"]
mod probe;

#[test]
fn service_loop_accepts_native_no_ready_without_swallowing_failures() {
    let source = include_str!("../src/main.rs");
    let mut program = probe::program();
    program = program.replace(
        "mod mnu_abi {pub mod status {",
        "mod mnu_abi {pub use crate::HandleWaitItem;pub mod status {",
    );
    program.push_str(probe::between(
        include_str!("../../../core/crates/abi/src/lib.rs"),
        "#[repr(C)]\n#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]\npub struct HandleWaitItem",
        "/// Native result returned by `WaitOnAddress`.",
    ));
    program.push_str(r#"
use std::cell::Cell;
use mnu_abi::status::Error;
thread_local! {
    static RESULT:Cell<Result<usize,mochi_user_syscall::SysError>>=const{Cell::new(Ok(0))};
    static DEADLINE:Cell<u64>=const{Cell::new(0)};
    static CALLS:Cell<usize>=const{Cell::new(0)};
}
mod mochi_user_platform {
    pub mod syscall {
        pub use crate::HandleWaitItem;
        pub const HANDLE_SIGNAL_READABLE:u64=crate::HANDLE_SIGNAL_READABLE;
        pub const HANDLE_SIGNAL_TERMINATED:u64=crate::HANDLE_SIGNAL_TERMINATED;
    }
    pub mod process {
        pub fn wait_many(items:&mut[crate::HandleWaitItem],deadline:u64)->Result<usize,crate::mochi_user_syscall::SysError>{
            assert_eq!(items.len(),3);assert_eq!(deadline,crate::DEADLINE.get());
            assert_eq!(items[0].handle,42);assert_eq!(items[0].interests,crate::HANDLE_SIGNAL_READABLE);
            for (item,handle) in items[1..].iter().zip([7,8]) {
                assert_eq!(item.handle,handle);assert_eq!(item.interests,crate::HANDLE_SIGNAL_TERMINATED);
            }
            crate::CALLS.set(crate::CALLS.get()+1);crate::RESULT.get()
        }
    }
}
"#);
    program.push_str(probe::between(
        source,
        "fn wait_for_request_or_child(",
        "#[cfg(target_os = \"mochios\")]\nfn initialize_sender_process(",
    ));
    program.push_str(r#"
fn invoke(deadline:u64)->Result<bool,i64>{
    DEADLINE.set(deadline);wait_for_request_or_child(42,vec![7,8],deadline)
}
fn main(){
    for deadline in [0,100,u64::MAX] {
        for (index,request) in [(0,true),(1,false),(2,false)] {
            RESULT.set(Ok(index));assert_eq!(invoke(deadline),Ok(request));
        }
        RESULT.set(Err(mochi_user_syscall::SysError::from_raw(Error::NotReady.into_raw() as i64)));
        assert_eq!(invoke(deadline),Ok(false)); // A finite expiry or an infinite-wait upcall is ordinary.
        for error in [Error::AccessDenied,Error::InvalidArgument,Error::ResourceUnavailable,
            Error::BackingFailure,Error::NotFound,Error::InvalidAddress,Error::LimitExceeded,
            Error::AlreadyExists,Error::PeerClosed] {
            let raw=error.into_raw() as i64;
            RESULT.set(Err(mochi_user_syscall::SysError::from_raw(raw)));
            assert_eq!(invoke(deadline),Err(raw));
        }
        for raw in [-11,11,i64::MIN,i64::MAX] {
            RESULT.set(Err(mochi_user_syscall::SysError::from_raw(raw)));
            assert_eq!(invoke(deadline),Err(raw)); // No numeric/legacy fallback.
        }
    }
    assert_eq!(CALLS.get(),51);
}
"#);
    probe::run(&program);
}

#[test]
fn socket_gc_wait_classifies_the_native_tag_not_an_errno_magnitude() {
    let source = include_str!("../src/socket_native.rs");
    let wait = probe::between(
        source,
        "if let Err(error) = platform::process::wait_many(",
        "                Err(error) => {",
    );
    assert!(wait.contains("error.native_error() != Some(mnu_abi::status::Error::NotReady)"));
    assert!(!wait.contains("error.raw()"));
}
