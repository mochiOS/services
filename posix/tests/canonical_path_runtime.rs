//! Exercise production canonical output and tracked allocation ownership.
#![allow(dead_code)]
use mochios_posix_client::upcall_guard::Guard;
use mochios_posix_protocol as posix_protocol;
use std::ffi::{c_char, c_int, c_void};
use std::{
    ptr,
    sync::{
        Mutex,
        atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering},
    },
};
#[path = "../../../user/crates/newlib-runtime/src/callback_resources.rs"]
mod callback_resources;
#[path = "../../../user/crates/newlib-runtime/src/canonical_path.rs"]
mod implementation;
#[path = "../../../user/crates/newlib-runtime/src/user_copy.rs"]
mod user_copy;
#[path = "support/user_copy_native.rs"]
mod user_copy_native;
use user_copy_native::{syscall, syscall_errno};
const PAGE_SIZE: usize = 4096;
const ENOENT: c_int = 2;
#[path = "../../../user/crates/newlib-runtime/src/io_resources.rs"]
mod io_resources;
const EIO: c_int = 5;
const EFAULT: c_int = 14;
const ENOMEM: c_int = 12;
const EAGAIN: c_int = 11;
const ENAMETOOLONG: c_int = 91;
static SERIAL: Mutex<()> = Mutex::new(());
static REPLY: Mutex<Result<Vec<u8>, c_int>> = Mutex::new(Ok(Vec::new()));
static ALLOCATION: AtomicUsize = AtomicUsize::new(0);
static FAIL_ALLOC: AtomicU32 = AtomicU32::new(0);
struct ThreadControl {
    callback_resources: callback_resources::Chain,
    active_signal_scope_id: AtomicU64,
    native: AtomicU32,
}
static CONTROL: ThreadControl = ThreadControl {
    callback_resources: callback_resources::Chain::new(),
    active_signal_scope_id: AtomicU64::new(0),
    native: AtomicU32::new(0),
};
fn register_current_thread() -> Option<(u32, &'static ThreadControl)> {
    Some((1, &CONTROL))
}
fn defer_native_delivery() -> Option<Guard<'static>> {
    Guard::enter(&CONTROL.native)
}
unsafe fn malloc(size: usize) -> *mut c_void {
    assert_ne!(CONTROL.native.load(Ordering::Relaxed), 0);
    if FAIL_ALLOC.load(Ordering::Relaxed) != 0 {
        return ptr::null_mut();
    }
    assert_eq!(ALLOCATION.swap(size, Ordering::Relaxed), 0);
    unsafe { std::alloc::alloc(std::alloc::Layout::from_size_align(size, 1).unwrap()).cast() }
}
unsafe fn free(pointer: *mut c_void) {
    let size = ALLOCATION.swap(0, Ordering::Relaxed);
    assert_ne!(size, 0);
    unsafe {
        std::alloc::dealloc(
            pointer.cast(),
            std::alloc::Layout::from_size_align(size, 1).unwrap(),
        )
    }
}
// Path capture itself is tested against its production module in path_io_resources.
mod path_io {
    use super::*;
    pub fn at<T: Copy>(
        fd: c_int,
        path: *const c_char,
        run: impl FnOnce((), &str) -> Result<T, c_int>,
    ) -> Result<T, c_int> {
        assert_eq!(fd, -2);
        if path.is_null() {
            return Err(EFAULT);
        }
        let text = unsafe { std::ffi::CStr::from_ptr(path) }.to_str().unwrap();
        if text.is_empty() {
            return Err(2);
        }
        run((), text)
    }
}
struct Client;
fn posix_client() -> Result<Client, c_int> {
    Ok(Client)
}
fn map_posix_client_error(error: c_int) -> c_int {
    error
}
impl Client {
    fn canonical_path_at(&self, _: (), path: &str, output: &mut [u8]) -> Result<usize, c_int> {
        assert_eq!(path, "input");
        assert_eq!(CONTROL.native.load(Ordering::Relaxed), 0);
        assert_eq!(ALLOCATION.load(Ordering::Relaxed), 0);
        let reply = REPLY.lock().unwrap();
        let bytes = reply.as_ref().map_err(|error| *error)?;
        if bytes.len() <= output.len() {
            output[..bytes.len()].copy_from_slice(bytes);
        }
        Ok(bytes.len())
    }
}
fn resolve(output: *mut c_char) -> Result<*mut c_char, c_int> {
    let result = implementation::resolve(c"input".as_ptr(), output);
    assert!(CONTROL.callback_resources.is_empty());
    assert_eq!(CONTROL.native.load(Ordering::Relaxed), 0);
    result
}
#[test]
fn supplied_buffers_obey_newlib_bound_and_never_write_partial_errors() {
    let _serial = SERIAL.lock().unwrap();
    for length in [1, 1023, 1024, 4096] {
        let mut reply = vec![b'x'; length];
        reply[0] = b'/';
        *REPLY.lock().unwrap() = Ok(reply.clone());
        let mut output = [0xa5; 1025];
        let pointer = output.as_mut_ptr().cast();
        if length < 1024 {
            assert_eq!(resolve(pointer), Ok(pointer));
            assert_eq!(&output[..length], reply);
            assert_eq!(output[length], 0);
            assert!(output[length + 1..].iter().all(|byte| *byte == 0xa5));
        } else {
            assert_eq!(resolve(pointer), Err(ENAMETOOLONG));
            assert_eq!(output, [0xa5; 1025]);
        }
    }
}
#[test]
fn null_output_allocates_exact_size_even_beyond_caller_buffer_bound() {
    let _serial = SERIAL.lock().unwrap();
    for length in [1, 1023, 1024, 4096] {
        let mut bytes = vec![b'x'; length];
        bytes[0] = b'/';
        *REPLY.lock().unwrap() = Ok(bytes.clone());
        let output = resolve(ptr::null_mut()).unwrap();
        assert_eq!(ALLOCATION.load(Ordering::Relaxed), length + 1);
        assert_eq!(
            unsafe { std::ffi::CStr::from_ptr(output) }.to_bytes(),
            bytes
        );
        unsafe { free(output.cast()) };
    }
    FAIL_ALLOC.store(1, Ordering::Relaxed);
    assert_eq!(resolve(ptr::null_mut()), Err(ENOMEM));
    FAIL_ALLOC.store(0, Ordering::Relaxed);
}
#[test]
fn malformed_and_service_errors_do_not_write_or_allocate() {
    let _serial = SERIAL.lock().unwrap();
    for (reply, error) in [
        (Err(2), 2),
        (Err(13), 13),
        (Ok(vec![]), EIO),
        (Ok(b"relative".to_vec()), EIO),
        (Ok(b"/a\0b".to_vec()), EIO),
        (Ok(vec![b'/'; 4097]), EIO),
    ] {
        *REPLY.lock().unwrap() = reply;
        let mut output = [0xa5; 1024];
        assert_eq!(resolve(output.as_mut_ptr().cast()), Err(error));
        assert_eq!(resolve(ptr::null_mut()), Err(error));
        assert_eq!(output, [0xa5; 1024]);
        assert_eq!(ALLOCATION.load(Ordering::Relaxed), 0);
    }
    *REPLY.lock().unwrap() = Ok(b"/ok".to_vec());
    assert_eq!(resolve(usize::MAX as *mut c_char), Err(EFAULT));
    assert_eq!(
        implementation::resolve(ptr::null(), ptr::null_mut()),
        Err(EFAULT)
    );
    assert_eq!(
        implementation::resolve(c"".as_ptr(), ptr::null_mut()),
        Err(2)
    );
}
#[test]
fn caller_buffer_limit_matches_newlib_public_header() {
    let header = include_str!("../../../libraries/newlib/newlib/libc/include/sys/syslimits.h");
    let limit = header
        .lines()
        .find(|line| {
            line.starts_with("#define") && line.split_whitespace().nth(1) == Some("PATH_MAX")
        })
        .unwrap();
    assert_eq!(
        limit
            .split_whitespace()
            .nth(2)
            .unwrap()
            .parse::<usize>()
            .unwrap(),
        implementation::OUTPUT_PATH_MAX
    );
}
