//! Run the real std bridge, native clock conversion and client synchronization.
#[allow(dead_code)]
#[path = "support/native_error_probe.rs"]
mod probe;

#[test]
fn std_bridge_preserves_native_errors_and_never_borrows_caller_addresses() {
    let abi = include_str!("../../../core/crates/abi/src/lib.rs");
    let runtime = include_str!("../../../user/crates/newlib-runtime/src/lib.rs");
    let mut program = probe::program();
    program.push_str("extern crate self as mochios_posix_client;\n");
    let definitions = probe::between(
        abi,
        "/// Native result returned by `WaitOnAddress`.",
        "/// Smallest representable increment of a native clock",
    );
    program = program.replacen(
        "mod mnu_abi {pub mod status {",
        &format!("mod mnu_abi {{\n{definitions}\npub mod status {{"),
        1,
    );
    program.push_str(probe::between(
        abi,
        "#[repr(C)]\n#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]\npub struct HandleWaitGuard",
        "/// Native result returned by `WaitOnAddress`.",
    ));
    program.push_str(r#"
use std::cell::Cell;
use mnu_abi::{ClockInstant,status::Error};
thread_local! {
    static CLOCK_RESULT:Cell<u64>=const{Cell::new(0)};
    static INSTANT:Cell<ClockInstant>=Cell::new(ClockInstant::default());
    static RESULT:Cell<SysResult<u64>>=const{Cell::new(Ok(0))};
    static EXPECTED:Cell<(u64,u64,u64)>=const{Cell::new((0,0,0))};
    static CLOCK_CALLS:Cell<usize>=const{Cell::new(0)};
    static WAIT_CALLS:Cell<usize>=const{Cell::new(0)};
    static WAKE_CALLS:Cell<usize>=const{Cell::new(0)};
}
mod syscall {
    use crate::mnu_abi;
    pub use crate::mochi_user_syscall::{SysError,SysResult};
    pub use crate::mnu_abi::{AddressWaitResult,ADDRESS_WAIT_INFINITE,status::Error as NativeError};
    pub use crate::AddressWaitGuard;
    #[derive(Debug,PartialEq)]pub enum SyscallNumber{ClockRead,WaitOnAddress,WaitOnAddressGuarded,WakeAddress}
"#);
    program.push_str(probe::between(
        include_str!("../../../user/crates/syscall/src/lib.rs"),
        "#[derive(Clone, Copy, Debug, PartialEq, Eq)]\npub struct RawSyscallResult",
        "#[inline(always)]",
    ));
    program.push_str(r#"
    pub fn raw_syscall2(number:SyscallNumber,a:u64,b:u64)->RawSyscallResult{
        assert_eq!(number,SyscallNumber::ClockRead);assert_eq!(a,mnu_abi::ClockId::Monotonic as u64);
        crate::CLOCK_CALLS.set(crate::CLOCK_CALLS.get()+1);
        if crate::CLOCK_RESULT.get()==0 {
            unsafe{(b as *mut mnu_abi::ClockInstant).write(crate::INSTANT.get());}
        }
        RawSyscallResult::new(crate::CLOCK_RESULT.get())
    }
    pub fn call4(number:SyscallNumber,a:u64,b:u64,c:u64,d:u64)->SysResult<u64>{
        assert_eq!(number,SyscallNumber::WaitOnAddress);assert_eq!(c,4);
        assert_eq!((a,b,d),crate::EXPECTED.get());
        crate::WAIT_CALLS.set(crate::WAIT_CALLS.get()+1);crate::RESULT.get()
    }
    pub fn call2(number:SyscallNumber,a:u64,b:u64)->SysResult<u64>{
        assert_eq!(number,SyscallNumber::WakeAddress);assert_eq!((a,b,0),crate::EXPECTED.get());
        crate::WAKE_CALLS.set(crate::WAKE_CALLS.get()+1);crate::RESULT.get()
    }
    pub fn call5(_:SyscallNumber,_:u64,_:u64,_:u64,_:u64,_:u64)->SysResult<u64>{panic!("unexpected guarded wait")}
}
pub mod synchronization {
"#);
    let sync = include_str!("../../../user/crates/posix-client/src/synchronization.rs");
    program.push_str(
        &sync[sync.find("use core::sync::atomic::").unwrap()..]
            .replace("use mochi_user_syscall as syscall;", "use crate::syscall;"),
    );
    program.push_str("}\n");
    program.push_str(probe::between(
        runtime,
        "fn native_monotonic_nanoseconds()",
        "fn monotonic_nanoseconds()",
    ));
    let bridge = probe::between(
        runtime,
        "/// Private runtime bridge used by the mochiOS Rust standard library. The",
        "fn wait_for_multiplex(",
    );
    assert!(!bridge.contains("unsafe {"));
    assert!(!bridge.contains("unsafe{"));
    assert!(!bridge.contains("&*address"));
    program.push_str(bridge);
    program.push_str(r#"
fn wait(address:u64,timeout:u64)->u64{
    __mochios_wait_on_address_u32(address as *const core::sync::atomic::AtomicU32,91,timeout)
}
fn wake(address:u64,maximum:usize)->u64{
    __mochios_wake_address_u32(address as *const core::sync::atomic::AtomicU32,maximum)
}
fn native(raw:u64,error:Error){assert_eq!(raw,error.into_raw());assert_eq!(SysError::from(raw).errno(),None);}
fn counts()->(usize,usize,usize){(CLOCK_CALLS.get(),WAIT_CALLS.get(),WAKE_CALLS.get())}
fn main(){
    let before=counts();
    for timeout in [0,1,u64::MAX]{native(wait(0,timeout),Error::InvalidAddress);}
    native(wake(0,1),Error::InvalidAddress);assert_eq!(counts(),before);
    // No real allocation backs these addresses: creating a Rust reference or
    // loading them would be invalid. The controlled native boundary owns validation.
    for address in [1,4096,4097,u64::MAX] {
        for error in [Error::InvalidAddress,Error::InvalidArgument,Error::ResourceUnavailable,
            Error::BackingFailure,Error::AccessDenied,Error::NotReady,Error::NotFound,
            Error::LimitExceeded,Error::AlreadyExists,Error::PeerClosed] {
            RESULT.set(Err(error.into_raw().into()));
            EXPECTED.set((address,91,u64::MAX));native(wait(address,u64::MAX),error);
            EXPECTED.set((address,7,0));native(wake(address,7),error);
        }
    }
    CLOCK_RESULT.set(0);INSTANT.set(ClockInstant{seconds:2,nanoseconds:3,reserved:0});
    for (timeout,deadline) in [(0,2_000_000_003),(9,2_000_000_012),(u64::MAX,u64::MAX)] {
        for raw in 0..3 {
            RESULT.set(Ok(raw));EXPECTED.set((4096,91,deadline));assert_eq!(wait(4096,timeout),raw);
        }
    }
    RESULT.set(Ok(3));EXPECTED.set((4096,91,u64::MAX));native(wait(4096,u64::MAX),Error::BackingFailure);
    RESULT.set(Ok(2));EXPECTED.set((4096,1,0));native(wake(4096,1),Error::BackingFailure);
    RESULT.set(Ok(1));assert_eq!(wake(4096,1),1);
    let waits=WAIT_CALLS.get();
    for error in [Error::InvalidAddress,Error::ResourceUnavailable,Error::BackingFailure,
        Error::NotReady,Error::LimitExceeded,Error::AccessDenied,Error::InvalidArgument,
        Error::AlreadyExists,Error::NotFound,Error::PeerClosed] {
        CLOCK_RESULT.set(error.into_raw());native(wait(4096,1),error);
    }
    CLOCK_RESULT.set(0);
    for instant in [ClockInstant{seconds:0,nanoseconds:1_000_000_000,reserved:0},
        ClockInstant{seconds:0,nanoseconds:0,reserved:1}] {
        INSTANT.set(instant);native(wait(4096,1),Error::BackingFailure);
    }
    for instant in [ClockInstant{seconds:u64::MAX/1_000_000_000+1,nanoseconds:0,reserved:0},
        ClockInstant{seconds:u64::MAX/1_000_000_000,nanoseconds:999_999_999,reserved:0}] {
        INSTANT.set(instant);native(wait(4096,1),Error::LimitExceeded);
    }
    INSTANT.set(ClockInstant{seconds:2,nanoseconds:3,reserved:0});
    for timeout in [u64::MAX-2_000_000_003,u64::MAX-2_000_000_002]{
        native(wait(4096,timeout),Error::LimitExceeded);
    }
    assert_eq!(WAIT_CALLS.get(),waits,"failed deadline conversion must not begin a wait");
    let before=CLOCK_CALLS.get();
    EXPECTED.set((4096,91,u64::MAX));RESULT.set(Ok(2));assert_eq!(wait(4096,u64::MAX),2);
    assert_eq!(CLOCK_CALLS.get(),before,"infinite wait must not read a clock");
    assert_eq!(counts(),(22,51,42));
}
"#);
    probe::run(&program);
}
