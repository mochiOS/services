//! Exercise the runtime's actual owner with deterministic native call results.
#![allow(non_camel_case_types)]
use std::sync::Mutex;
type c_int = i32;
const EIO: c_int = 5;
const EAGAIN: c_int = 11;
const EOVERFLOW: c_int = 139;
static CLOSED: Mutex<Vec<u32>> = Mutex::new(Vec::new());
static CREATED: Mutex<Result<u64, c_int>> = Mutex::new(Ok(91));
static CONTENT: Mutex<Result<Vec<u8>, c_int>> = Mutex::new(Ok(Vec::new()));

mod syscall {
    pub use mnu_abi::SyscallNumber;
    pub fn raw_syscall0(number: SyscallNumber) -> Result<u64, super::c_int> {
        assert!(matches!(number, SyscallNumber::HandleTableCapture));
        *super::CREATED.lock().unwrap()
    }
    pub fn raw_syscall4(
        number: SyscallNumber,
        handle: u64,
        target: u64,
        capacity: u64,
        offset: u64,
    ) -> Result<u64, super::c_int> {
        assert!(matches!(number, SyscallNumber::HandleReadAt));
        assert_eq!((handle, offset), (91, 0));
        let content = super::CONTENT.lock().unwrap();
        let content = content.as_ref().map_err(|error| *error)?;
        let count = content.len().min(capacity as usize);
        unsafe {
            std::ptr::copy_nonoverlapping(content.as_ptr(), target as *mut u8, count);
        }
        Ok(count as u64)
    }
}
fn syscall_errno(value: Result<u64, c_int>) -> Result<u64, c_int> {
    value.map_err(|status| mochios_posix_client::newlib_errno::from_status(i64::from(status)))
}
fn close_object_handle(handle: u32) {
    CLOSED.lock().unwrap().push(handle);
}

#[path = "../../../user/crates/newlib-runtime/src/handle_capture.rs"]
mod handle_capture;

#[test]
fn parent_releases_on_success_and_error_but_child_never_closes_copied_number() {
    use handle_capture::Capture;
    let mut records = [mnu_abi::HandleInfo::default(); 1];
    *CONTENT.lock().unwrap() = Ok([1u32, 1, 16, 0, 7, 0, 1, 0]
        .into_iter()
        .flat_map(u32::to_le_bytes)
        .collect());
    {
        let capture = Capture::new().unwrap();
        assert_eq!(capture.handle(), 91);
        assert_eq!(capture.records(&mut records), Ok(1));
        assert_eq!(records[0].handle, 7);
    }
    assert_eq!(*CLOSED.lock().unwrap(), [91]);
    {
        let mut child_copy = Capture::new().unwrap();
        child_copy.disarm_child();
    }
    assert_eq!(*CLOSED.lock().unwrap(), [91]);
    *CONTENT.lock().unwrap() = Err(13);
    {
        let capture = Capture::new().unwrap();
        assert_eq!(capture.records(&mut records), Err(13));
    }
    assert_eq!(*CLOSED.lock().unwrap(), [91, 91]);
    *CONTENT.lock().unwrap() = Ok(Vec::new());
    {
        let capture = Capture::new().unwrap();
        assert_eq!(capture.records(&mut records), Err(EIO));
    }
    assert_eq!(*CLOSED.lock().unwrap(), [91, 91, 91]);
    *CREATED.lock().unwrap() = Err(12);
    assert!(matches!(Capture::new(), Err(12)));
    for (native, expected) in [
        (mnu_abi::status::Error::ResourceUnavailable, 12),
        (mnu_abi::status::Error::NotReady, EAGAIN),
    ] {
        *CREATED.lock().unwrap() = Err(native.into_raw() as i32);
        assert!(matches!(Capture::new(), Err(error) if error == expected));
    }
    for (returned, expected) in [(0, EIO), (u64::from(u32::MAX) + 1, EOVERFLOW)] {
        *CREATED.lock().unwrap() = Ok(returned);
        assert!(matches!(Capture::new(), Err(error) if error == expected));
    }
    assert_eq!(*CLOSED.lock().unwrap(), [91, 91, 91]);
}
