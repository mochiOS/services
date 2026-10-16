//! Exercise the real client fast path with scripted native syscall responses.
#[allow(dead_code)]
#[path = "support/native_error_probe.rs"]
mod probe;

#[test]
fn native_client_waits_and_wakes_preserve_errors_and_reject_malformed_results() {
    let mut program = probe::program();
    let abi = include_str!("../../../core/crates/abi/src/lib.rs");
    program.push_str(probe::between(
        abi,
        "#[repr(C)]\n#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]\npub struct HandleWaitGuard",
        "/// Native result returned by `WaitOnAddress`.",
    ));
    program.push_str(probe::between(
        abi,
        "/// Native result returned by `WaitOnAddress`.",
        "/// Kernel-provided clocks.",
    ));
    program.push_str(r#"
use std::cell::Cell;
use std::sync::atomic::{AtomicU32,AtomicU64};
use mnu_abi::status::Error;
thread_local! {
    static RESULT:Cell<SysResult<u64>>=const{Cell::new(Ok(0))};
    static EXPECTED:Cell<(syscall::SyscallNumber,[u64;4])>=const{
        Cell::new((syscall::SyscallNumber::WakeAddress,[0;4]))
    };
    static GUARD:Cell<(u64,u64)>=const{Cell::new((0,0))};
    static CALLS:Cell<usize>=const{Cell::new(0)};
}
mod syscall {
    pub use crate::mochi_user_syscall::SysError;
    pub use crate::{AddressWaitResult,AddressWaitGuard};
    pub use crate::mnu_abi::status::Error as NativeError;
    #[derive(Clone,Copy,Debug,PartialEq,Eq)]
    pub enum SyscallNumber{WaitOnAddress,WaitOnAddressGuarded,WakeAddress}
    fn invoke(number:SyscallNumber,args:[u64;4])->Result<u64,SysError>{
        assert_eq!(crate::EXPECTED.get(),(number,args));
        crate::CALLS.set(crate::CALLS.get()+1);crate::RESULT.get()
    }
    pub fn call2(number:SyscallNumber,a:u64,b:u64)->Result<u64,SysError>{invoke(number,[a,b,0,0])}
    pub fn call4(number:SyscallNumber,a:u64,b:u64,c:u64,d:u64)->Result<u64,SysError>{invoke(number,[a,b,c,d])}
    pub fn call5(number:SyscallNumber,a:u64,b:u64,c:u64,d:u64,e:u64)->Result<u64,SysError>{
        assert_eq!(number,SyscallNumber::WaitOnAddressGuarded);assert_ne!(e,0);
        assert_eq!(e%core::mem::align_of::<AddressWaitGuard>()as u64,0);
        // Production supplies a live stack guard; validate both fields before return.
        let guard=unsafe{&*(e as *const AddressWaitGuard)};
        assert_eq!((guard.address,guard.expected),crate::GUARD.get());
        invoke(number,[a,b,c,d])
    }
}
mod actual {
"#);
    let source = include_str!("../../../user/crates/posix-client/src/synchronization.rs");
    program.push_str(
        &source[source.find("use core::sync::atomic::").unwrap()..]
            .replace("use mochi_user_syscall as syscall;", "use crate::syscall;"),
    );
    program.push_str(r#"
}
fn native<T:std::fmt::Debug>(result:SysResult<T>,error:Error){
    let result=result.unwrap_err();assert_eq!(result.native_error(),Some(error));
    assert_eq!(result.errno(),None);
}
fn wait(kind:usize,deadline:u64,result:SysResult<u64>)->SysResult<actual::WaitStatus>{
    use syscall::SyscallNumber as S;
    let word32=AtomicU32::new(91);let word64=AtomicU64::new(0x9876_5432_1000);
    let notification=AtomicU64::new(0x1234_5678_9000);
    let pointer=if kind==0{&word32 as *const _ as u64}else{&word64 as *const _ as u64};
    let expected=if kind==0{91}else{0x9876_5432_1000};
    GUARD.set((&notification as *const _ as u64,0x1234_5678_9000));
    EXPECTED.set((if kind==2{S::WaitOnAddressGuarded}else{S::WaitOnAddress},
        [pointer,expected,if kind==0{4}else{8},deadline]));RESULT.set(result);
    match kind{
        0=>actual::wait_u32(&word32,91,deadline),
        1=>actual::wait_u64(&word64,expected,deadline),
        2=>actual::wait_u64_guarded(&word64,expected,&notification,0x1234_5678_9000,deadline),
        _=>unreachable!(),
    }
}
fn wake(kind:usize,maximum:usize,result:SysResult<u64>)->SysResult<usize>{
    let word32=AtomicU32::new(0);let word64=AtomicU64::new(0);
    let pointer=if kind==0{&word32 as *const _ as u64}else{&word64 as *const _ as u64};
    EXPECTED.set((syscall::SyscallNumber::WakeAddress,[pointer,maximum as u64,0,0]));RESULT.set(result);
    if kind==0{actual::wake_u32(&word32,maximum)}else{actual::wake_u64(&word64,maximum)}
}
fn main(){
    use actual::WaitStatus as W;
    for deadline in [0,987_654,u64::MAX] {
        for kind in 0..3 {
            for (raw,status) in [(0,W::Awoken),(1,W::ValueChanged),(2,W::DeadlineReached)]{
                assert_eq!(wait(kind,deadline,Ok(raw)),Ok(status));
            }
            for raw in [3,4,u64::MAX]{native(wait(kind,deadline,Ok(raw)),Error::BackingFailure);}
            for error in [Error::LimitExceeded,Error::InvalidAddress,Error::ResourceUnavailable,
                Error::BackingFailure,Error::InvalidArgument,Error::AccessDenied,Error::NotReady,
                Error::AlreadyExists,Error::NotFound,Error::PeerClosed] {
                native(wait(kind,deadline,Err(error.into_raw().into())),error);
            }
        }
    }
    for kind in 0..2 {
        for maximum in [0,1,7,usize::MAX] {
            for count in [0,maximum as u64]{assert_eq!(wake(kind,maximum,Ok(count)),Ok(count as usize));}
            if maximum!=usize::MAX{
                for raw in [maximum as u64+1,u64::MAX]{native(wake(kind,maximum,Ok(raw)),Error::BackingFailure);}
            }
            for error in [Error::LimitExceeded,Error::InvalidAddress,Error::ResourceUnavailable,
                Error::BackingFailure,Error::InvalidArgument,Error::AccessDenied,Error::NotReady,
                Error::AlreadyExists,Error::NotFound,Error::PeerClosed] {
                native(wake(kind,maximum,Err(error.into_raw().into())),error);
            }
        }
    }
    assert_eq!(CALLS.get(),252);
}
"#);
    probe::run(&program);
}
