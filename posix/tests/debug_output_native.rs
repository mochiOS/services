//! Run both production DebugWrite adapters without executing a host syscall.
#[allow(dead_code)]
#[path = "support/native_error_probe.rs"]
mod probe;

#[test]
fn debug_output_validates_native_results_without_synthesizing_posix_errno() {
    let mut program = probe::program();
    program.push_str(
        r#"
use std::cell::Cell;
thread_local! {
    static RESULT:Cell<SysResult<u64>>=const{Cell::new(Ok(5))};
    static CALLS:Cell<usize>=const{Cell::new(0)};
    static EXPECTED:Cell<(u64,u64)>=const{Cell::new((0,0))};
}
mod syscall {
    pub use crate::mochi_user_syscall::*;
    #[derive(PartialEq,Debug)]pub enum SyscallNumber{DebugWrite}
    pub fn call2(number:SyscallNumber,pointer:u64,length:u64)->SysResult<u64> {
        assert_eq!(number,SyscallNumber::DebugWrite);
        assert_eq!((pointer,length),crate::EXPECTED.get());
        crate::CALLS.set(crate::CALLS.get()+1);crate::RESULT.get()
    }
}
mod runtime {
    use crate::syscall;
"#,
    );
    program.push_str(probe::between(
        include_str!("../../../user/crates/runtime/src/lib.rs"),
        "pub fn write_all(",
        "\npub fn stdout_write(",
    ));
    program.push_str("}\nmod platform {use crate::syscall;\n");
    program.push_str(probe::between(
        include_str!("../../../user/crates/platform/src/lib.rs"),
        "pub fn write_all(",
        "\n    pub fn yield_now(",
    ));
    program.push_str(r#"
}
fn main() {
    use mnu_abi::status::Error;
    let bytes=b"hello";
    EXPECTED.set((bytes.as_ptr() as u64,bytes.len() as u64));
    for write in [runtime::write_all,platform::write_all] {
        for destination in [0,3,u64::MAX] {
            for bytes in [&bytes[..],&bytes[..0]] {
                CALLS.set(0);
                assert_eq!(write(destination,bytes).unwrap_err().native_error(),Some(Error::InvalidArgument));
                assert_eq!(CALLS.get(),0);
            }
        }
        for destination in [1,2] {
            CALLS.set(0);RESULT.set(Err(SysError::from(Error::AccessDenied.into_raw())));
            assert_eq!(write(destination,&[]),Ok(()));assert_eq!(CALLS.get(),0);
            for count in [0,1,4,6,u64::MAX] {
                CALLS.set(0);RESULT.set(Ok(count));
                assert_eq!(write(destination,bytes).unwrap_err().native_error(),Some(Error::BackingFailure));
                assert_eq!(CALLS.get(),1,"a malformed successful write must not be replayed");
            }
            CALLS.set(0);RESULT.set(Ok(5));assert_eq!(write(destination,bytes),Ok(()));
            assert_eq!(CALLS.get(),1);
            for raw in [Error::AccessDenied.into_raw() as i64,
                        Error::ResourceUnavailable.into_raw() as i64,
                        Error::NotReady.into_raw() as i64,
                        ((Error::LimitExceeded.into_raw() & !0xffff)|0xffff) as i64,-13,-9] {
                CALLS.set(0);RESULT.set(Err(SysError::from_raw(raw)));
                assert_eq!(write(destination,bytes).unwrap_err().raw(),raw);
                assert_eq!(CALLS.get(),1);
            }
        }
    }
}
"#);
    probe::run(&program);
}
