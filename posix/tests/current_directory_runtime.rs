//! Exercise the production getcwd output adapter with a reentrant boundary.
use mochios_posix_protocol as posix_protocol;
use std::ffi::{c_char, c_int};
use std::ptr;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
#[path = "../../../user/crates/newlib-runtime/src/current_directory.rs"]
mod implementation;
const EINVAL: c_int = 22;
const EIO: c_int = 5;
const ERANGE: c_int = 34;
const EFAULT: c_int = 14;
static SERIAL: Mutex<()> = Mutex::new(());
static REPLY: Mutex<Result<Vec<u8>, c_int>> = Mutex::new(Ok(Vec::new()));
static CALLER: AtomicUsize = AtomicUsize::new(0);
static CAPACITY: AtomicUsize = AtomicUsize::new(0);
static CALLS: AtomicUsize = AtomicUsize::new(0);
struct Client;
fn posix_client() -> Result<Client, c_int> {
    Ok(Client)
}
fn map_posix_client_error(error: c_int) -> c_int {
    error
}
impl Client {
    fn getcwd(&self, output: &mut [u8]) -> Result<usize, c_int> {
        CALLS.fetch_add(1, Ordering::Relaxed);
        let caller = CALLER.load(Ordering::Relaxed);
        let capacity = CAPACITY.load(Ordering::Relaxed);
        assert!(
            !(output.as_ptr() as usize..output.as_ptr() as usize + output.len()).contains(&caller),
            "caller buffer borrowed across IPC"
        );
        // A real signal handler may access the application's output while the
        // request is in flight. The Rust &mut supplied to IPC must not alias it.
        if capacity != 0 {
            unsafe { (caller as *mut u8).write(0x5a) };
        }
        let reply = REPLY.lock().unwrap();
        let reply = reply.as_ref().map_err(|error| *error)?;
        if reply.len() > output.len() {
            return Err(ERANGE);
        }
        output[..reply.len()].copy_from_slice(reply);
        Ok(reply.len())
    }
}
fn reply(value: Result<&[u8], c_int>, output: &mut [u8], callback: bool) {
    *REPLY.lock().unwrap() = value.map(|bytes| bytes.to_vec());
    CALLS.store(0, Ordering::Relaxed);
    CALLER.store(output.as_mut_ptr() as usize, Ordering::Relaxed);
    CAPACITY.store(if callback { output.len() } else { 0 }, Ordering::Relaxed);
}

#[test]
fn copies_only_the_complete_cwd_and_nul_after_reentrant_service_return() {
    let _serial = SERIAL.lock().unwrap();
    for path in [b"/".as_slice(), b"/home/user", b"/renamed/\xff"] {
        let mut output = [0xa5; 64];
        reply(Ok(path), &mut output, true);
        let pointer = output.as_mut_ptr().cast();
        assert_eq!(implementation::copy(pointer, path.len() + 1), Ok(pointer));
        assert_eq!(&output[..path.len()], path);
        assert_eq!(output[path.len()], 0);
        assert!(output[path.len() + 1..].iter().all(|byte| *byte == 0xa5));
    }
}

#[test]
fn short_buffers_return_erange_without_any_partial_response_write() {
    let _serial = SERIAL.lock().unwrap();
    for size in 1..=5 {
        let mut output = [0xa5; 64];
        reply(Ok(b"/home"), &mut output, false);
        assert_eq!(
            implementation::copy(output.as_mut_ptr().cast(), size),
            Err(ERANGE)
        );
        assert_eq!(output, [0xa5; 64]);
    }
}

#[test]
fn service_and_malformed_path_errors_leave_the_callers_memory_unchanged() {
    let _serial = SERIAL.lock().unwrap();
    for (value, error) in [
        (Err(2), 2),
        (Err(13), 13),
        (Err(4), 4),
        (Ok(b"".as_slice()), EIO),
        (Ok(b"relative"), EIO),
        (Ok(b"/with\0nul"), EIO),
    ] {
        let mut output = [0xa5; 64];
        reply(value, &mut output, false);
        assert_eq!(
            implementation::copy(output.as_mut_ptr().cast(), output.len()),
            Err(error)
        );
        assert_eq!(output, [0xa5; 64]);
    }
}

#[test]
fn maximum_path_and_oversized_advertised_capacity_never_form_an_unbounded_slice() {
    let _serial = SERIAL.lock().unwrap();
    let mut path = vec![b'a'; posix_protocol::MAX_PATH_LEN];
    path[0] = b'/';
    let mut output = vec![0xa5; path.len() + 2];
    reply(Ok(&path), &mut output, false);
    assert_eq!(
        implementation::copy(output.as_mut_ptr().cast(), usize::MAX),
        Ok(output.as_mut_ptr().cast())
    );
    assert_eq!(&output[..path.len()], path);
    assert_eq!(&output[path.len()..], &[0, 0xa5]);
    assert_eq!(
        implementation::copy(usize::MAX as *mut c_char, usize::MAX),
        Err(EFAULT)
    );
}

#[test]
fn null_and_zero_capacity_are_rejected_before_ipc_and_public_api_uses_adapter() {
    let _serial = SERIAL.lock().unwrap();
    let mut output = [0xa5; 8];
    reply(Ok(b"/"), &mut output, false);
    assert_eq!(implementation::copy(ptr::null_mut(), 8), Err(EINVAL));
    assert_eq!(
        implementation::copy(output.as_mut_ptr().cast(), 0),
        Err(EINVAL)
    );
    assert_eq!(CALLS.load(Ordering::Relaxed), 0);
    let source = include_str!("../../../user/crates/newlib-runtime/src/lib.rs");
    let body = source
        .split("pub extern \"C\" fn getcwd(")
        .nth(1)
        .unwrap()
        .split("\n}\n")
        .next()
        .unwrap();
    assert!(body.contains("current_directory::copy(buffer, size)"));
    assert!(!body.contains("from_raw_parts_mut"));
}
