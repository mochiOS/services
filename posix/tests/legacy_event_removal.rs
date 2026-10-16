#[allow(dead_code)]
#[path = "support/native_error_probe.rs"]
mod probe;

#[test]
fn global_event_ids_have_no_kernel_abi_dispatch_or_platform_wrapper() {
    let abi = include_str!("../../../core/crates/abi/src/lib.rs");
    let dispatch = include_str!("../../../core/src/syscall/mod.rs");
    let platform = include_str!("../../../user/crates/platform/src/lib.rs");
    let example = include_str!("../../../core/examples/user/src/lib.rs");
    for name in ["EventCreate", "EventWait", "EventSignal", "EventPoll"] {
        for source in [abi, dispatch, platform, example] {
            assert!(!source.contains(name), "legacy native syscall {name}");
        }
    }
    assert!(!dispatch.contains("pub mod event;"));
    assert!(!platform.contains("pub mod event {"));
    assert!(!include_str!("../../../core/src/task/handle_table.rs").contains("Event(u64)"));
    assert!(
        !std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../core/src/syscall/event.rs")
            .exists()
    );
    // Hypervisor event ports are a separate protected ABI, not these IDs.
    let hypervisor = include_str!("../../../core/crates/abi/src/hypervisor.rs");
    assert!(hypervisor.contains("EventWait = 6"));
    assert!(hypervisor.contains("EventPoll = 23"));
}

#[test]
fn sample_sync_test_uses_native_address_wait_and_checks_every_result() {
    let mut program = probe::program().replace(
        "mod mochi_user_syscall {",
        "mod mochi_user_syscall {pub use crate::backend::{call4,call2,SyscallNumber};pub use crate::AddressWaitResult;",
    );
    program.push_str(probe::between(
        include_str!("../../../core/crates/abi/src/lib.rs"),
        "#[repr(u64)]\n#[derive(Debug, Clone, Copy, PartialEq, Eq)]\npub enum AddressWaitResult",
        "/// Wait without a deadline when passed to `WaitOnAddress`.",
    ));
    program.push_str(r#"
use std::cell::Cell;
thread_local! {
    static FAIL_AT:Cell<usize>=const{Cell::new(0)};
    static CALLS:Cell<usize>=const{Cell::new(0)};
    static ADDRESS:Cell<u64>=const{Cell::new(0)};
}
mod backend {
    use crate::{AddressWaitResult,mochi_user_syscall::{SysError,SysResult}};
    #[derive(Debug,PartialEq)]pub enum SyscallNumber{WaitOnAddress,WakeAddress}
    fn failed()->bool{let next=crate::CALLS.get()+1;crate::CALLS.set(next);next==crate::FAIL_AT.get()}
    pub fn call4(number:SyscallNumber,address:u64,expected:u64,size:u64,deadline:u64)->SysResult<u64>{
        assert_eq!(number,SyscallNumber::WaitOnAddress);assert_eq!((size,deadline),(4,0));
        let word=unsafe{&*(address as *const core::sync::atomic::AtomicU32)};
        assert_eq!(word.load(core::sync::atomic::Ordering::Relaxed),0);
        if crate::CALLS.get()==0{crate::ADDRESS.set(address);}else{assert_eq!(address,crate::ADDRESS.get());}
        if failed(){return Err(SysError::from_raw(crate::mnu_abi::status::Error::InvalidAddress.into_raw()as i64));}
        Ok(if expected==1{AddressWaitResult::ValueChanged as u64}else{assert_eq!(expected,0);AddressWaitResult::DeadlineReached as u64})
    }
    pub fn call2(number:SyscallNumber,address:u64,count:u64)->SysResult<u64>{
        assert_eq!(number,SyscallNumber::WakeAddress);assert_eq!(address,crate::ADDRESS.get());assert_eq!(count,u64::MAX);
        if failed(){Err(SysError::from_raw(crate::mnu_abi::status::Error::InvalidAddress.into_raw()as i64))}else{Ok(0)}
    }
}
"#);
    program.push_str(probe::between(
        include_str!("../../../core/examples/user/src/main.rs"),
        "fn run_native_wait_tests()",
        "fn run_capability_tests(",
    ));
    program.push_str(
        r#"
fn main(){
    assert_eq!(run_native_wait_tests(),0);assert_eq!(CALLS.get(),3);
    for failure in 1..=3{
        CALLS.set(0);FAIL_AT.set(failure);
        assert_eq!(run_native_wait_tests(),30+failure as u64);assert_eq!(CALLS.get(),failure);
    }
}
"#,
    );
    probe::run(&program);
}
