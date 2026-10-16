//! Execute both production platform wrappers with controlled syscall results.
#[allow(dead_code)]
#[path = "support/native_error_probe.rs"]
mod probe;

#[test]
fn wait_wrappers_keep_native_errors_and_validate_indices_without_posix_errno() {
    let source = include_str!("../../../user/crates/platform/src/lib.rs");
    let mut program = probe::program();
    program.push_str(probe::between(
        include_str!("../../../core/crates/abi/src/lib.rs"),
        "#[repr(C)]\n#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]\npub struct HandleWaitItem",
        "/// Native result returned by `WaitOnAddress`.",
    ));
    program.push_str(
        r#"
use std::cell::Cell;
use mochi_user_syscall::{SysError,SysResult};
use mnu_abi::status::Error;
thread_local! {
    static RESULT:Cell<SysResult<u64>>=const{Cell::new(Ok(0))};
    static CALLS:Cell<usize>=const{Cell::new(0)};
    static POINTER:Cell<u64>=const{Cell::new(0)};
    static COUNT:Cell<u64>=const{Cell::new(0)};
    static DEADLINE:Cell<u64>=const{Cell::new(0)};
    static GUARD:Cell<u64>=const{Cell::new(0)};
}
mod syscall {
    pub use crate::{HandleWaitItem,HandleWaitGuard,HANDLE_WAIT_MANY_MAX_ITEMS};
    pub use crate::mochi_user_syscall::{SysError,SysResult};
    pub use crate::mnu_abi::status::Error as NativeError;
    #[derive(Debug,PartialEq)]pub enum SyscallNumber{HandleWaitMany,HandleWaitManyGuarded}
    fn call(pointer:u64,count:u64,deadline:u64)->SysResult<u64>{
        assert_eq!(pointer,crate::POINTER.get());assert_eq!(count,crate::COUNT.get());
        assert_eq!(deadline,crate::DEADLINE.get());crate::CALLS.set(crate::CALLS.get()+1);
        crate::RESULT.get()
    }
    pub fn call3(number:SyscallNumber,pointer:u64,count:u64,deadline:u64)->SysResult<u64>{
        assert_eq!(number,SyscallNumber::HandleWaitMany);assert_eq!(crate::GUARD.get(),0);
        call(pointer,count,deadline)
    }
    pub fn call4(number:SyscallNumber,pointer:u64,count:u64,deadline:u64,guard:u64)->SysResult<u64>{
        assert_eq!(number,SyscallNumber::HandleWaitManyGuarded);assert_ne!(guard,0);
        assert_eq!(guard,crate::GUARD.get());call(pointer,count,deadline)
    }
}
"#,
    );
    for signature in ["    pub fn wait_many_guarded(", "    pub fn wait_many(\n"] {
        program.push_str(probe::between(source, signature, "    pub fn exit("));
    }
    program.push_str(r#"
fn invoke(guarded:bool,items:&mut[HandleWaitItem],deadline:u64)->SysResult<usize>{
    let guard=HandleWaitGuard{address:8,expected:99};
    POINTER.set(items.as_mut_ptr()as u64);COUNT.set(items.len()as u64);DEADLINE.set(deadline);
    GUARD.set(if guarded{&guard as *const _ as u64}else{0});
    if guarded{wait_many_guarded(items,deadline,&guard)}else{wait_many(items,deadline)}
}
fn main(){
    let mut items=[HandleWaitItem::default();65];
    for guarded in [false,true] {
        let before=CALLS.get();
        let error=invoke(guarded,&mut items,0).unwrap_err();
        assert_eq!(error.native_error(),Some(Error::InvalidArgument));assert_eq!(error.errno(),None);
        assert_eq!(CALLS.get(),before,"oversized input must not enter the kernel");
        for deadline in [0,123,u64::MAX] {
            RESULT.set(Ok(63));assert_eq!(invoke(guarded,&mut items[..64],deadline),Ok(63));
            for index in [64,u64::MAX] {
                RESULT.set(Ok(index));let error=invoke(guarded,&mut items[..64],deadline).unwrap_err();
                assert_eq!(error.native_error(),Some(Error::BackingFailure));assert_eq!(error.errno(),None);
            }
            for native in [Error::LimitExceeded,Error::InvalidAddress,Error::ResourceUnavailable,
                Error::BackingFailure,Error::InvalidArgument,Error::AccessDenied,Error::NotReady,
                Error::AlreadyExists,Error::NotFound,Error::PeerClosed] {
                let error=SysError::from_raw(native.into_raw()as i64);RESULT.set(Err(error));
                assert_eq!(invoke(guarded,&mut items[..64],deadline),Err(error));
            }
            // Empty waits can block for a guard/notification or deadline. They
            // have no valid ready index, so an apparent success is malformed.
            RESULT.set(Err(SysError::from_raw(Error::NotReady.into_raw()as i64)));
            assert_eq!(invoke(guarded,&mut [],deadline).unwrap_err().native_error(),Some(Error::NotReady));
            RESULT.set(Ok(0));assert_eq!(invoke(guarded,&mut [],deadline).unwrap_err().native_error(),Some(Error::BackingFailure));
        }
    }
    assert_eq!(CALLS.get(),90);
}
"#);
    probe::run(&program);
}
