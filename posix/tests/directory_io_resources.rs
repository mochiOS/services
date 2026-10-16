//! Execute the production refill adapter, including reentrant close and errors.
#![allow(dead_code)]
use mochios_posix_client::upcall_guard::Guard;
use std::ffi::{c_char, c_int, c_void};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
#[path = "../../../user/crates/newlib-runtime/src/callback_resources.rs"]
mod callback_resources;
#[path = "../../../user/crates/newlib-runtime/src/directory_io.rs"]
mod implementation;
#[path = "../../../user/crates/newlib-runtime/src/io_resources.rs"]
mod io_resources;
const EBADF: c_int = 9;
const EAGAIN: c_int = 11;
const EIO: c_int = 5;
const EACCES: c_int = 13;
const EPERM: c_int = 1;
const ENOMEM: c_int = 12;
const ENOTDIR: c_int = 20;
const O_CLOEXEC: c_int = 0x40000;
static SERIAL: Mutex<()> = Mutex::new(());
static OPEN_CASE: AtomicU32 = AtomicU32::new(0);
static OPEN_CALLS: AtomicU32 = AtomicU32::new(0);
static LIVE_MEMORY: AtomicU32 = AtomicU32::new(0);
static PROMPTS: AtomicU32 = AtomicU32::new(0);
static CLOSE_FAILURE: AtomicU32 = AtomicU32::new(0);
static CLOSE_CALLS: AtomicU32 = AtomicU32::new(0);
fn _close(fd: c_int) -> c_int {
    assert_eq!(fd, 7);
    assert_ne!(
        CONTROL.native.load(Ordering::Relaxed),
        0,
        "delivery reopened between free and close"
    );
    assert_eq!(LIVE_MEMORY.load(Ordering::Relaxed), 0);
    CLOSE_CALLS.fetch_add(1, Ordering::Relaxed);
    if CLOSE_FAILURE.load(Ordering::Relaxed) != 0 {
        -1
    } else {
        0
    }
}
struct DirStream {
    fd: c_int,
    buffer: [u8; 16],
    buffer_offset: usize,
    buffer_len: usize,
}
impl DirStream {
    fn new(fd: c_int) -> Self {
        Self {
            fd,
            buffer: [0; 16],
            buffer_offset: 0,
            buffer_len: 0,
        }
    }
}
unsafe fn malloc(size: usize) -> *mut c_void {
    assert_ne!(CONTROL.native.load(Ordering::Relaxed), 0);
    if OPEN_CASE.load(Ordering::Relaxed) == 1 {
        return std::ptr::null_mut();
    }
    assert_eq!(size, std::mem::size_of::<DirStream>());
    let pointer = unsafe { std::alloc::alloc(std::alloc::Layout::new::<DirStream>()) };
    assert!(!pointer.is_null());
    LIVE_MEMORY.fetch_add(1, Ordering::Relaxed);
    pointer.cast()
}
unsafe fn free(pointer: *mut c_void) {
    assert_ne!(CONTROL.native.load(Ordering::Relaxed), 0);
    assert_eq!(LIVE_MEMORY.fetch_sub(1, Ordering::Relaxed), 1);
    unsafe { std::alloc::dealloc(pointer.cast(), std::alloc::Layout::new::<DirStream>()) };
}
mod file_mutation {
    use super::*;
    pub fn open_with_handoff(
        _: *const c_char,
        flags: c_int,
        mode: c_int,
        handoff: &mut dyn FnMut(c_int) -> Result<(), c_int>,
    ) -> Result<c_int, c_int> {
        assert_eq!(flags, 0x200000 | O_CLOEXEC);
        assert_eq!(mode, 0);
        assert_eq!(
            CONTROL.native.load(Ordering::Relaxed),
            0,
            "deferred across open"
        );
        assert!(!CONTROL.callback_resources.is_empty());
        assert_eq!(LIVE_MEMORY.load(Ordering::Relaxed), 1);
        let call = OPEN_CALLS.fetch_add(1, Ordering::Relaxed);
        match OPEN_CASE.load(Ordering::Relaxed) {
            2 => return Err(2),
            3 if call == 0 => return Err(EACCES),
            5 => return Err(4),
            _ => {}
        }
        let _native = defer_native_delivery();
        handoff(7)?;
        if OPEN_CASE.load(Ordering::Relaxed) == 4 {
            return Err(EIO);
        }
        Ok(7)
    }
}
fn retry_open_with_prompt_using(
    _: *const c_char,
    _: c_int,
    retry: impl FnOnce() -> Result<c_int, c_int>,
) -> Result<c_int, c_int> {
    assert_eq!(
        CONTROL.native.load(Ordering::Relaxed),
        0,
        "deferred across prompt"
    );
    PROMPTS.fetch_add(1, Ordering::Relaxed);
    retry()
}
#[derive(Clone, Copy, PartialEq)]
enum FdKind {
    ObjectDirectory,
    ObjectFile,
}
struct Object {
    kind: FdKind,
    lower_handle: u64,
    open_flags: c_int,
}
static ADOPT_CASE: AtomicU32 = AtomicU32::new(0);
struct Entry {
    handle: Object,
    rights: u64,
}
struct Table;
impl Table {
    fn get(&self, fd: c_int) -> Option<Entry> {
        assert_ne!(CONTROL.native.load(Ordering::Relaxed), 0);
        let case = ADOPT_CASE.load(Ordering::Relaxed);
        if fd != 7 || case == 1 {
            return None;
        }
        Some(Entry {
            handle: Object {
                kind: if case == 2 {
                    FdKind::ObjectFile
                } else {
                    FdKind::ObjectDirectory
                },
                lower_handle: 10,
                open_flags: if case == 3 { 1 } else { 0 },
            },
            rights: if case == 4 {
                0
            } else {
                syscall::HANDLE_RIGHT_READ
            },
        })
    }
}
struct State {
    fds: Table,
}
static STATE: Mutex<State> = Mutex::new(State { fds: Table });
fn state() -> std::sync::MutexGuard<'static, State> {
    STATE.lock().unwrap()
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
            open_flags: 0,
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
    pub const HANDLE_RIGHT_READ: u64 = 1;
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
fn adoption_consumes_only_successful_directory_descriptors_without_provider_calls() {
    let _serial = SERIAL.lock().unwrap();
    CLOSE_FAILURE.store(0, Ordering::Relaxed);
    for case in 0..6 {
        ADOPT_CASE.store(case, Ordering::Relaxed);
        OPEN_CASE.store(u32::from(case == 5), Ordering::Relaxed);
        OPEN_CALLS.store(0, Ordering::Relaxed);
        CLOSE_CALLS.store(0, Ordering::Relaxed);
        let result = implementation::adopt(7);
        if case == 0 {
            let pointer = result.unwrap().cast::<DirStream>();
            let stream = unsafe { &*pointer };
            assert_eq!(
                (stream.fd, stream.buffer_offset, stream.buffer_len),
                (7, 0, 0)
            );
            assert_eq!(CLOSE_CALLS.load(Ordering::Relaxed), 0);
            assert_eq!(unsafe { implementation::close(pointer) }, 0);
            assert_eq!(CLOSE_CALLS.load(Ordering::Relaxed), 1);
        } else {
            assert_eq!(
                result,
                Err(match case {
                    2 => ENOTDIR,
                    5 => ENOMEM,
                    _ => EBADF,
                })
            );
            assert_eq!(CLOSE_CALLS.load(Ordering::Relaxed), 0);
        }
        assert_eq!(OPEN_CALLS.load(Ordering::Relaxed), 0);
        assert_eq!(LIVE_MEMORY.load(Ordering::Relaxed), 0);
        assert_eq!(CONTROL.native.load(Ordering::Relaxed), 0);
        assert!(CONTROL.callback_resources.is_empty());
    }
}
#[test]
fn refills_release_pins_after_data_eof_errors_and_reentrant_close() {
    let _serial = SERIAL.lock().unwrap();
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

#[test]
fn directory_allocation_is_tracked_before_open_and_handoff_is_guarded_until_retirement() {
    let _serial = SERIAL.lock().unwrap();
    for case in 0..6 {
        OPEN_CASE.store(case, Ordering::Relaxed);
        OPEN_CALLS.store(0, Ordering::Relaxed);
        PROMPTS.store(0, Ordering::Relaxed);
        let result = implementation::open(c"/directory".as_ptr());
        if matches!(case, 0 | 3) {
            let pointer = result.unwrap();
            assert_eq!(unsafe { (*pointer.cast::<DirStream>()).fd }, 7);
            assert_eq!(LIVE_MEMORY.load(Ordering::Relaxed), 1);
            let _native = defer_native_delivery();
            unsafe { free(pointer) };
        } else {
            assert_eq!(
                result,
                Err(match case {
                    1 => ENOMEM,
                    2 => 2,
                    4 => EIO,
                    _ => 4,
                })
            );
        }
        assert_eq!(LIVE_MEMORY.load(Ordering::Relaxed), 0);
        assert_eq!(
            OPEN_CALLS.load(Ordering::Relaxed),
            match case {
                1 => 0,
                3 => 2,
                _ => 1,
            }
        );
        assert_eq!(PROMPTS.load(Ordering::Relaxed), u32::from(case == 3));
        assert!(CONTROL.callback_resources.is_empty());
        assert_eq!(CONTROL.native.load(Ordering::Relaxed), 0);
    }
}

#[test]
fn handoff_precedes_fd_installation_and_callback_retirement_is_still_guarded() {
    let source = include_str!("../../../user/crates/newlib-runtime/src/file_mutation.rs");
    let body = source.split("fn open_in_slot(").nth(1).unwrap();
    assert!(
        body.find("completion_delivery = Some(native)").unwrap()
            < body.find("handoff(fd)?").unwrap()
    );
    assert!(body.find("handoff(fd)?").unwrap() < body.find("commit_reservation(").unwrap());
    assert!(body.find("retire()").unwrap() < body.find("drop(completion_delivery)").unwrap());
}

#[test]
fn directory_close_keeps_delivery_closed_through_both_free_and_fd_retirement() {
    let _serial = SERIAL.lock().unwrap();
    for fail in [0, 1] {
        OPEN_CASE.store(0, Ordering::Relaxed);
        CLOSE_FAILURE.store(fail, Ordering::Relaxed);
        CLOSE_CALLS.store(0, Ordering::Relaxed);
        let pointer = implementation::open(c"/directory".as_ptr()).unwrap();
        assert_eq!(LIVE_MEMORY.load(Ordering::Relaxed), 1);
        assert_eq!(
            unsafe { implementation::close(pointer.cast()) },
            if fail != 0 { -1 } else { 0 }
        );
        assert_eq!(CLOSE_CALLS.load(Ordering::Relaxed), 1);
        assert_eq!(LIVE_MEMORY.load(Ordering::Relaxed), 0);
        assert_eq!(CONTROL.native.load(Ordering::Relaxed), 0);
        assert!(CONTROL.callback_resources.is_empty());
    }
    let source = include_str!("../../../user/crates/newlib-runtime/src/lib.rs");
    let body = source
        .split("fn closedir(")
        .nth(1)
        .unwrap()
        .split("#[unsafe(no_mangle)]")
        .next()
        .unwrap();
    assert!(body.contains("directory_io::close(dirp.cast())"));
}
