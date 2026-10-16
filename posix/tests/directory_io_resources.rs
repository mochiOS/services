//! Execute the production refill adapter, including reentrant close and errors.
#![allow(dead_code)]
use std::ffi::c_int;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use mochios_posix_client::upcall_guard::Guard;
#[path = "../../../user/crates/newlib-runtime/src/callback_resources.rs"]
mod callback_resources;
#[path = "../../../user/crates/newlib-runtime/src/directory_io.rs"]
mod implementation;
#[path = "../../../user/crates/newlib-runtime/src/io_resources.rs"]
mod io_resources;
const EBADF: c_int = 9;
const EAGAIN: c_int = 11;
const EIO: c_int = 5;
struct DirStream {
    fd: c_int,
    buffer: [u8; 16],
    buffer_offset: usize,
    buffer_len: usize,
}
#[derive(Clone, Copy, PartialEq)]
enum FdKind {
    ObjectDirectory,
    ObjectFile,
}
struct Object {
    kind: FdKind,
    lower_handle: u64,
}
struct Lease {
    handle: Object,
}
impl Drop for Lease {
    fn drop(&mut self) {
        assert_ne!(CONTROL.native.load(Ordering::Relaxed), 0);
        assert_eq!(PINS.fetch_sub(1, Ordering::Relaxed), 1);
        if RETIRED.load(Ordering::Relaxed) != 0 {
            CLOSED.fetch_add(1, Ordering::Relaxed);
        }
    }
}
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
static CASE: AtomicU32 = AtomicU32::new(0);
static PINS: AtomicU32 = AtomicU32::new(0);
static CALLS: AtomicU32 = AtomicU32::new(0);
static RETIRED: AtomicU32 = AtomicU32::new(0);
static CLOSED: AtomicU32 = AtomicU32::new(0);
fn register_current_thread() -> Option<(u32, &'static ThreadControl)> {
    Some((1, &CONTROL))
}
fn defer_native_delivery() -> Option<Guard<'static>> {
    Guard::enter(&CONTROL.native)
}
fn with_fd_entry(fd: c_int) -> Result<Lease, c_int> {
    assert_ne!(CONTROL.native.load(Ordering::Relaxed), 0);
    assert_eq!(fd, 7);
    if CASE.load(Ordering::Relaxed) == 8 {
        return Err(EBADF);
    }
    PINS.fetch_add(1, Ordering::Relaxed);
    Ok(Lease {
        handle: Object {
            lower_handle: 10,
            kind: if CASE.load(Ordering::Relaxed) == 9 {
                FdKind::ObjectFile
            } else {
                FdKind::ObjectDirectory
            },
        },
    })
}
fn syscall_errno(raw: u64) -> Result<u64, c_int> {
    if raw >= (-4095i64) as u64 {
        Err(-(raw as i64) as c_int)
    } else {
        Ok(raw)
    }
}
mod syscall {
    use super::*;
    pub enum SyscallNumber {
        HandleRead,
    }
    pub fn raw_syscall3(_: SyscallNumber, handle: u64, output: u64, capacity: u64) -> u64 {
        assert_eq!(handle, 10);
        assert_eq!(capacity, 16);
        assert_eq!(CONTROL.native.load(Ordering::Relaxed), 0);
        assert!(!CONTROL.callback_resources.is_empty());
        assert_eq!(PINS.load(Ordering::Relaxed), 1);
        CALLS.fetch_add(1, Ordering::Relaxed);
        let case = CASE.load(Ordering::Relaxed);
        if case >= 4 {
            RETIRED.store(1, Ordering::Relaxed);
        }
        assert_eq!(CLOSED.load(Ordering::Relaxed), 0);
        match case % 4 {
            0 => {
                unsafe { std::ptr::write_bytes(output as *mut u8, 0xa5, 8) };
                8
            }
            1 => 0,
            2 => (-5i64) as u64,
            _ => 17, // Malformed provider count must not become a slice bound.
        }
    }
}
#[test]
fn refills_release_pins_after_data_eof_errors_and_reentrant_close() {
    for case in 0..10 {
        CASE.store(case, Ordering::Relaxed);
        CALLS.store(0, Ordering::Relaxed);
        RETIRED.store(0, Ordering::Relaxed);
        CLOSED.store(0, Ordering::Relaxed);
        let mut stream = DirStream {
            fd: 7,
            buffer: [0; 16],
            buffer_offset: 3,
            buffer_len: 4,
        };
        let result = implementation::refill(&mut stream);
        assert_eq!(
            result,
            match case {
                0 | 4 => Ok(true),
                1 | 5 => Ok(false),
                8 | 9 => Err(EBADF),
                _ => Err(EIO),
            }
        );
        if matches!(case, 0 | 1 | 4 | 5) {
            assert_eq!(stream.buffer_offset, 0);
            assert_eq!(stream.buffer_len, if case % 4 == 0 { 8 } else { 0 });
        } else {
            assert_eq!((stream.buffer_offset, stream.buffer_len), (3, 4));
        }
        assert_eq!(CALLS.load(Ordering::Relaxed), u32::from(case < 8));
        assert_eq!(PINS.load(Ordering::Relaxed), 0);
        assert_eq!(
            CLOSED.load(Ordering::Relaxed),
            u32::from((4..8).contains(&case))
        );
        assert!(CONTROL.callback_resources.is_empty());
        assert_eq!(CONTROL.native.load(Ordering::Relaxed), 0);
    }
}
