//! Execute the actual path scope, including input mutation and reentrant close.
#![allow(dead_code)]
use mochios_posix_client::{ObjectHandleAttachment, StatAtBase, upcall_guard::Guard};
use mochios_posix_protocol as posix_protocol;
use std::ffi::{c_char, c_int};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
#[path = "../../../user/crates/newlib-runtime/src/callback_resources.rs"]
mod callback_resources;
#[path = "../../../user/crates/newlib-runtime/src/path_io.rs"]
mod implementation;
#[path = "../../../user/crates/newlib-runtime/src/io_resources.rs"]
mod io_resources;
const EAGAIN: c_int = 11;
const EFAULT: c_int = 14;
const EINVAL: c_int = 22;
const EIO: c_int = 5;
const ENOENT: c_int = 2;
const ENAMETOOLONG: c_int = 91;
const EBADF: c_int = 9;
static SERIAL: Mutex<()> = Mutex::new(());
static PINS: AtomicU32 = AtomicU32::new(0);
static CLOSED: AtomicU32 = AtomicU32::new(0);
static RETIRED: AtomicU32 = AtomicU32::new(0);
static CALLS: AtomicU32 = AtomicU32::new(0);
static CASE: AtomicU32 = AtomicU32::new(0);
static INPUT: AtomicU64 = AtomicU64::new(0);
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
mod fd_lease {
    use super::*;
    pub struct Lease;
    impl Drop for Lease {
        fn drop(&mut self) {
            assert_ne!(CONTROL.native.load(Ordering::Relaxed), 0);
            let before = PINS.fetch_sub(1, Ordering::Relaxed);
            assert_ne!(before, 0);
            if before == 1 && RETIRED.load(Ordering::Relaxed) != 0 {
                CLOSED.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}
fn rename_posix_base(
    fd: c_int,
    path: &str,
) -> Result<(StatAtBase<u32>, Option<fd_lease::Lease>), c_int> {
    assert_ne!(CONTROL.native.load(Ordering::Relaxed), 0);
    assert!(!CONTROL.callback_resources.is_empty());
    if path.starts_with('/') {
        return Ok((StatAtBase::ProcessRoot, None));
    }
    if fd == -2 {
        return Ok((StatAtBase::ProcessCwd, None));
    }
    if fd != 7 {
        return Err(EBADF);
    }
    PINS.fetch_add(1, Ordering::Relaxed);
    Ok((
        StatAtBase::Directory(ObjectHandleAttachment {
            handle: 42,
            rights: 0x15,
        }),
        Some(fd_lease::Lease),
    ))
}
struct Client;
fn posix_client() -> Result<Client, c_int> {
    Ok(Client)
}
fn map_posix_client_error(error: c_int) -> c_int {
    error
}
impl Client {
    fn readlink_at(
        &self,
        base: StatAtBase<u32>,
        path: &str,
        output: &mut [u8],
    ) -> Result<usize, c_int> {
        assert_eq!(CONTROL.native.load(Ordering::Relaxed), 0);
        assert!(!CONTROL.callback_resources.is_empty());
        assert_eq!(PINS.load(Ordering::Relaxed), 1);
        assert_eq!(
            base,
            StatAtBase::Directory(ObjectHandleAttachment {
                handle: 42,
                rights: 0x15
            })
        );
        CALLS.fetch_add(1, Ordering::Relaxed);
        match CASE.load(Ordering::Relaxed) {
            1 => return Err(13),
            2 => {
                RETIRED.store(1, Ordering::Relaxed);
                assert_eq!(CLOSED.load(Ordering::Relaxed), 0);
            }
            3 => unsafe { (INPUT.load(Ordering::Relaxed) as *mut u8).write(b'X') },
            _ => {}
        }
        assert_eq!(path, "target");
        let count = output.len().min(b"destination".len());
        output[..count].copy_from_slice(&b"destination"[..count]);
        Ok(count)
    }
}
fn reset() {
    assert_eq!(PINS.load(Ordering::Relaxed), 0);
    assert!(CONTROL.callback_resources.is_empty());
    assert_eq!(CONTROL.native.load(Ordering::Relaxed), 0);
    CLOSED.store(0, Ordering::Relaxed);
    RETIRED.store(0, Ordering::Relaxed);
    CALLS.store(0, Ordering::Relaxed);
}
#[test]
fn readlink_owns_input_and_directory_through_errors_copyout_and_reentrant_close() {
    let _serial = SERIAL.lock().unwrap();
    for case in 0..4 {
        reset();
        CASE.store(case, Ordering::Relaxed);
        let mut input = *b"target\0";
        INPUT.store(input.as_mut_ptr() as u64, Ordering::Relaxed);
        let mut output = [0xa5u8; 8];
        let result = implementation::readlink(
            7,
            input.as_ptr().cast(),
            output.as_mut_ptr().cast(),
            output.len(),
        );
        assert_eq!(result, if case == 1 { Err(13) } else { Ok(8) });
        if case != 1 {
            assert_eq!(&output, b"destinat");
        }
        assert_eq!(input[0], if case == 3 { b'X' } else { b't' });
        assert_eq!(PINS.load(Ordering::Relaxed), 0);
        assert_eq!(CLOSED.load(Ordering::Relaxed), u32::from(case == 2));
        assert_eq!(CALLS.load(Ordering::Relaxed), 1);
        assert!(CONTROL.callback_resources.is_empty());
        assert_eq!(CONTROL.native.load(Ordering::Relaxed), 0);
    }
}
#[test]
fn invalid_paths_fail_before_borrowing_a_directory_or_calling_the_provider() {
    let _serial = SERIAL.lock().unwrap();
    let mut overlong = vec![b'a'; posix_protocol::MAX_PATH_LEN + 1];
    overlong.push(0);
    for (path, error) in [
        (b"\0".as_slice(), ENOENT),
        (b"\xff\0", EINVAL),
        (&overlong, ENAMETOOLONG),
    ] {
        reset();
        assert_eq!(
            implementation::at(7, path.as_ptr().cast(), |_, _| Ok(0)),
            Err(error)
        );
        assert_eq!(PINS.load(Ordering::Relaxed), 0);
        assert!(CONTROL.callback_resources.is_empty());
    }
    assert_eq!(
        implementation::at(7, std::ptr::null(), |_, _| Ok(0)),
        Err(EFAULT)
    );
    assert_eq!(
        implementation::at(-9, c"target".as_ptr(), |_, _| Ok(0)),
        Err(EBADF)
    );
}
#[test]
fn absolute_and_cwd_paths_ignore_irrelevant_dirfds_and_nested_scopes_keep_parent_pins() {
    let _serial = SERIAL.lock().unwrap();
    reset();
    assert_eq!(
        implementation::at(-9, c"/absolute".as_ptr(), |base, path| {
            assert_eq!(base, StatAtBase::ProcessRoot);
            assert_eq!(path, "/absolute");
            Ok(1)
        }),
        Ok(1)
    );
    assert_eq!(
        implementation::at(-2, c"relative".as_ptr(), |base, _| {
            assert_eq!(base, StatAtBase::ProcessCwd);
            Ok(2)
        }),
        Ok(2)
    );
    assert_eq!(
        implementation::at(7, c"parent".as_ptr(), |_, _| {
            assert_eq!(PINS.load(Ordering::Relaxed), 1);
            assert_eq!(
                implementation::at(7, c"child".as_ptr(), |_, _| {
                    assert_eq!(PINS.load(Ordering::Relaxed), 2);
                    Ok(3)
                }),
                Ok(3)
            );
            assert_eq!(PINS.load(Ordering::Relaxed), 1);
            Ok(4)
        }),
        Ok(4)
    );
    assert_eq!(PINS.load(Ordering::Relaxed), 0);
    assert!(CONTROL.callback_resources.is_empty());
}
#[test]
fn the_maximum_wire_path_is_captured_without_requiring_a_shorter_buffer() {
    let _serial = SERIAL.lock().unwrap();
    reset();
    let mut input = vec![b'x'; posix_protocol::MAX_PATH_LEN];
    input.push(0);
    assert_eq!(
        implementation::at(7, input.as_ptr().cast(), |_, path| {
            assert_eq!(path.len(), posix_protocol::MAX_PATH_LEN);
            assert!(path.as_bytes().iter().all(|byte| *byte == b'x'));
            Ok(1)
        }),
        Ok(1)
    );
    assert_eq!(PINS.load(Ordering::Relaxed), 0);
    assert!(CONTROL.callback_resources.is_empty());
    assert_eq!(CONTROL.native.load(Ordering::Relaxed), 0);
}

#[test]
fn invalid_output_ranges_are_rejected_before_rust_slice_construction() {
    let _serial = SERIAL.lock().unwrap();
    reset();
    let path = c"target".as_ptr();
    assert_eq!(
        implementation::readlink(7, path, std::ptr::null_mut(), 1),
        Err(EFAULT)
    );
    assert_eq!(
        implementation::readlink(7, path, 1usize as *mut c_char, 0),
        Err(EINVAL)
    );
    assert_eq!(
        implementation::readlink(7, path, 1usize as *mut c_char, usize::MAX),
        Err(EINVAL)
    );
    assert_eq!(
        implementation::readlink(7, path, usize::MAX as *mut c_char, 2),
        Err(EFAULT)
    );
    assert_eq!(CALLS.load(Ordering::Relaxed), 0);
    assert_eq!(PINS.load(Ordering::Relaxed), 0);
}
