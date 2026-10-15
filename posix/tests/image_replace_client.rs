use mnu_abi::SyscallNumber;
use std::sync::Mutex;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SysError(i64);
impl SysError {
    fn from_raw(raw: i64) -> Self {
        Self(raw)
    }
}
type SysResult<T> = Result<T, SysError>;
static RESULT: Mutex<SysResult<u64>> = Mutex::new(Err(SysError(-12)));
static CALLS: Mutex<Vec<u64>> = Mutex::new(Vec::new());
static SERIAL: Mutex<()> = Mutex::new(());
fn call6(
    number: SyscallNumber,
    handle: u64,
    identity: u64,
    identity_len: u64,
    startup: u64,
    startup_len: u64,
    ceiling: u64,
) -> SysResult<u64> {
    assert_eq!(number, SyscallNumber::ProcessImageReplaceBounded);
    assert_eq!(handle, 7);
    assert_eq!(
        unsafe { std::slice::from_raw_parts(identity as *const u8, identity_len as usize) },
        b"opaque:target"
    );
    assert_eq!(
        unsafe { std::slice::from_raw_parts(startup as *const u8, startup_len as usize) },
        b"startup-bytes"
    );
    CALLS.lock().unwrap().push(ceiling);
    *RESULT.lock().unwrap()
}
#[path = "../../../user/crates/syscall/src/image.rs"]
mod production;

#[test]
fn explicit_ceiling_and_all_native_errors_are_preserved_without_fallback() {
    let _serial = SERIAL.lock().unwrap();
    for ceiling in [0, 4096, u64::MAX] {
        for error in [-12, -13, -9, -14, -22, -38] {
            CALLS.lock().unwrap().clear();
            *RESULT.lock().unwrap() = Err(SysError(error));
            assert_eq!(
                production::replace_bounded(7, "opaque:target", b"startup-bytes", ceiling),
                Err(SysError(error))
            );
            assert_eq!(*CALLS.lock().unwrap(), [ceiling]);
        }
    }
}

#[test]
fn unexpected_returned_success_is_not_a_returning_successful_exec() {
    let _serial = SERIAL.lock().unwrap();
    for status in [0, 1, u64::MAX] {
        CALLS.lock().unwrap().clear();
        *RESULT.lock().unwrap() = Ok(status);
        assert_eq!(
            production::replace_bounded(7, "opaque:target", b"startup-bytes", 4096),
            Err(SysError(-5))
        );
        assert_eq!(*CALLS.lock().unwrap(), [4096]);
    }
}
