//! Run the production native wrappers, not copies of their error handling.
#[allow(dead_code)]
#[path = "support/native_error_probe.rs"]
mod probe;

#[test]
fn clock_synchronization_and_random_wrappers_never_synthesize_posix_errno() {
    let abi = include_str!("../../../core/crates/abi/src/lib.rs");
    let source = include_str!("../../../user/crates/platform/src/lib.rs");
    let mut program = probe::program();
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
    program.push_str(
        r#"
use std::cell::Cell;
use mnu_abi::{AddressWaitResult,ClockId,ClockInstant,status::Error};
thread_local! {
    static RESULT:Cell<SysResult<u64>>=const{Cell::new(Ok(0))};
    static INSTANT:Cell<ClockInstant>=Cell::new(ClockInstant::default());
    static EXPECTED:Cell<(syscall::SyscallNumber,[u64;4])>=const{
        Cell::new((syscall::SyscallNumber::TimeNow,[0;4]))
    };
    static CALLS:Cell<usize>=const{Cell::new(0)};
}
mod syscall {
    pub use crate::mochi_user_syscall::{SysResult,SysError};
    pub use crate::mnu_abi::status::Error as NativeError;
    #[derive(Debug,Clone,Copy,PartialEq,Eq)]
    pub enum SyscallNumber{TimeNow,ClockRead,WaitOnAddress,WakeAddress,RandomFill}
    fn invoke(number:SyscallNumber,arguments:[u64;4])->SysResult<u64>{
        assert_eq!(crate::EXPECTED.get(),(number,arguments));
        crate::CALLS.set(crate::CALLS.get()+1);
        let result=crate::RESULT.get();
        if number==SyscallNumber::ClockRead && result.is_ok(){
            // The production wrapper passes its live stack ClockInstant.
            unsafe{(arguments[1]as *mut crate::ClockInstant).write(crate::INSTANT.get());}
        }
        result
    }
    pub fn call0(number:SyscallNumber)->SysResult<u64>{invoke(number,[0;4])}
    pub fn call2(number:SyscallNumber,a:u64,b:u64)->SysResult<u64>{
        let mut expected=crate::EXPECTED.get();
        if number==SyscallNumber::ClockRead{
            assert_ne!(b,0);assert_eq!(b%core::mem::align_of::<crate::ClockInstant>()as u64,0);
            assert_eq!(expected.1[1],0);expected.1[1]=b;crate::EXPECTED.set(expected);
        }
        invoke(number,[a,b,0,0])
    }
    pub fn call4(number:SyscallNumber,a:u64,b:u64,c:u64,d:u64)->SysResult<u64>{
        invoke(number,[a,b,c,d])
    }
}
"#,
    );
    program.push_str(
        &probe::between(source, "pub mod time {", "pub mod port {")
            .replace("use mnu_abi::", "use crate::mnu_abi::"),
    );
    program.push_str(r#"
fn expect(number:syscall::SyscallNumber,args:[u64;4],result:SysResult<u64>){
    EXPECTED.set((number,args));RESULT.set(result);
}
fn native<T:std::fmt::Debug>(result:SysResult<T>,error:Error){
    let result=result.unwrap_err();assert_eq!(result.native_error(),Some(error));
    assert_eq!(result.errno(),None);
}
fn clock(which:usize,instant:ClockInstant,result:SysResult<u64>)->SysResult<u64>{
    INSTANT.set(instant);
    let selector=if which==0{ClockId::Realtime}else{ClockId::Monotonic};
    expect(syscall::SyscallNumber::ClockRead,[selector as u64,0,0,0],result);
    match which{0=>time::utc_seconds(),1=>time::monotonic_milliseconds(),2=>time::monotonic_nanoseconds(),_=>unreachable!()}
}
fn main(){
    use syscall::SyscallNumber as S;
    let mut bytes=[0u8;17];let pointer=bytes.as_mut_ptr()as u64;
    let address=0x1000 as *const u8;
    for error in [Error::LimitExceeded,Error::InvalidAddress,Error::ResourceUnavailable,
        Error::BackingFailure,Error::InvalidArgument,Error::AccessDenied,Error::NotReady,
        Error::AlreadyExists,Error::NotFound,Error::PeerClosed] {
        let failure=Err(SysError::from(error.into_raw()));
        for which in 0..3{native(clock(which,ClockInstant::default(),failure),error);}
        expect(S::TimeNow,[0;4],failure);native(time::ticks(),error);
        expect(S::WaitOnAddress,[address as u64,0x1234,4,987],failure);
        native(unsafe{synchronization::wait_on_address(address,0x1234,4,987)},error);
        expect(S::WakeAddress,[address as u64,7,0,0],failure);
        native(unsafe{synchronization::wake_address(address,7)},error);
        expect(S::RandomFill,[pointer,17,0,0],failure);native(random::fill(&mut bytes),error);
    }
    for (raw,result) in [(0,AddressWaitResult::Awoken),(1,AddressWaitResult::ValueChanged),
        (2,AddressWaitResult::DeadlineReached)] {
        expect(S::WaitOnAddress,[address as u64,19,8,u64::MAX],Ok(raw));
        assert_eq!(unsafe{synchronization::wait_on_address(address,19,8,u64::MAX)},Ok(result));
    }
    for raw in [3,u64::MAX]{
        expect(S::WaitOnAddress,[address as u64,0,1,0],Ok(raw));
        native(unsafe{synchronization::wait_on_address(address,0,1,0)},Error::BackingFailure);
    }
    for maximum in [0,1,7,usize::MAX] {
        for count in [0,maximum as u64] {
            expect(S::WakeAddress,[address as u64,maximum as u64,0,0],Ok(count));
            assert_eq!(unsafe{synchronization::wake_address(address,maximum)},Ok(count as usize));
        }
        if maximum!=usize::MAX {
            expect(S::WakeAddress,[address as u64,maximum as u64,0,0],Ok(maximum as u64+1));
            native(unsafe{synchronization::wake_address(address,maximum)},Error::BackingFailure);
        }
    }
    for length in [0,1,17] {
        for count in [0,length as u64,length as u64+1,u64::MAX] {
            expect(S::RandomFill,[pointer,length as u64,0,0],Ok(count));
            let result=random::fill(&mut bytes[..length]);
            if count==length as u64{assert_eq!(result,Ok(()));}
            else{native(result,Error::BackingFailure);}
        }
    }
    let valid=ClockInstant{seconds:123,nanoseconds:987_654_321,reserved:0};
    assert_eq!(clock(0,valid,Ok(0)),Ok(123));
    assert_eq!(clock(1,valid,Ok(0)),Ok(123_987));
    assert_eq!(clock(2,valid,Ok(0)),Ok(123_987_654_321));
    for which in 0..3 {
        for instant in [ClockInstant{nanoseconds:1_000_000_000,..valid},
            ClockInstant{reserved:1,..valid},ClockInstant{nanoseconds:u32::MAX,..valid}] {
            native(clock(which,instant,Ok(0)),Error::BackingFailure);
        }
    }
    // Multiplication and the fractional addition have independent overflow boundaries.
    for (which,scale,nanos) in [(1,1_000u64,999_000_000),(2,1_000_000_000u64,999_999_999)] {
        native(clock(which,ClockInstant{seconds:u64::MAX/scale+1,nanoseconds:0,reserved:0},Ok(0)),Error::LimitExceeded);
        native(clock(which,ClockInstant{seconds:u64::MAX/scale,nanoseconds:nanos,reserved:0},Ok(0)),Error::LimitExceeded);
        assert_eq!(clock(which,ClockInstant{seconds:u64::MAX/scale,nanoseconds:0,reserved:0},Ok(0)),Ok(u64::MAX/scale*scale));
    }
    assert_eq!(clock(0,ClockInstant{seconds:u64::MAX,nanoseconds:0,reserved:0},Ok(0)),Ok(u64::MAX));
    expect(S::TimeNow,[0;4],Ok(u64::MAX));assert_eq!(time::ticks(),Ok(u64::MAX));
    assert!(CALLS.get()>100);
}
"#);
    probe::run(&program);
}
