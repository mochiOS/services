//! Exercise the production FD export and callback-aware ownership boundaries.
#![allow(dead_code)]
use mochios_posix_client::{ObjectHandleAttachment, fd, upcall_guard::Guard};
use mochios_posix_protocol as posix_protocol;
use std::ffi::c_int;
use std::sync::atomic::{AtomicI32, AtomicU32, AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard};

#[path = "../../../user/crates/newlib-runtime/src/callback_resources.rs"]
mod callback_resources;
#[path = "../../../user/crates/newlib-runtime/src/fd_creation.rs"]
mod fd_creation;
#[path = "../../../user/crates/newlib-runtime/src/file_handle_export.rs"]
mod implementation;
#[path = "../../../user/crates/newlib-runtime/src/io_resources.rs"]
mod io_resources;

const EAGAIN: c_int = 11;
const EBADF: c_int = 9;
const EACCES: c_int = 13;
const EFAULT: c_int = 14;
const EINVAL: c_int = 22;
const EIO: c_int = 5;
const SOURCE: u32 = 7;
const DUPLICATE: u32 = 42;
const READ: u64 = mnu_abi::HANDLE_RIGHT_READ;
const WRITE: u64 = mnu_abi::HANDLE_RIGHT_WRITE;
const BASE: u64 = mnu_abi::HANDLE_RIGHT_DUPLICATE | mnu_abi::HANDLE_RIGHT_TRANSFER;
static SERIAL: Mutex<()> = Mutex::new(());
static ENTRY: Mutex<Option<FdEntry>> = Mutex::new(None);
static ERRNO: AtomicI32 = AtomicI32::new(0);
static MODE: AtomicU32 = AtomicU32::new(0);
static PINNED: AtomicU32 = AtomicU32::new(0);
static CALLS: Mutex<Vec<(u64, u64)>> = Mutex::new(Vec::new());
static CLOSED: Mutex<Vec<u32>> = Mutex::new(Vec::new());

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
#[derive(Clone, Copy)]
struct FdObject {
    lower_handle: u64,
    kind: u8,
    open_flags: c_int,
    close_owned: bool,
}
type FdEntry = fd::Entry<FdObject>;
type FdReservation = fd::FdReservation;
struct State {
    fds: fd::FdTable<FdObject>,
}
static STATE: Mutex<State> = Mutex::new(State {
    fds: fd::FdTable::new(),
});
fn state() -> MutexGuard<'static, State> {
    STATE.lock().unwrap()
}
struct Lease(FdEntry);
impl std::ops::Deref for Lease {
    type Target = FdEntry;
    fn deref(&self) -> &FdEntry {
        &self.0
    }
}
impl Drop for Lease {
    fn drop(&mut self) {
        assert_eq!(PINNED.fetch_sub(1, Ordering::Relaxed), 1);
    }
}
fn with_fd_entry(fd: c_int) -> Result<Lease, c_int> {
    if fd != 3 {
        return Err(EBADF);
    }
    let entry = ENTRY.lock().unwrap().ok_or(EBADF)?;
    PINNED.fetch_add(1, Ordering::Relaxed);
    Ok(Lease(entry))
}
fn inherited_fd_kind(kind: u8) -> Option<u8> {
    posix_protocol::inherited_fd_kind_requires_handle(kind)
        .is_some()
        .then_some(kind)
}
fn close_object_handle(handle: u32) {
    assert_eq!(
        handle, DUPLICATE,
        "the FD's borrowed source must remain open"
    );
    assert_ne!(CONTROL.native.load(Ordering::Relaxed), 0);
    CLOSED.lock().unwrap().push(handle);
}
fn syscall_errno(result: Result<u64, c_int>) -> Result<u64, c_int> {
    result
}
fn result_with_errno<T>(result: Result<T, c_int>, failure: T) -> T {
    result.unwrap_or_else(|error| {
        ERRNO.store(error, Ordering::Relaxed);
        failure
    })
}
mod syscall {
    pub use mnu_abi::{
        HANDLE_RIGHT_ALL, HANDLE_RIGHT_DUPLICATE, HANDLE_RIGHT_READ, HANDLE_RIGHT_WRITE,
        SyscallNumber,
    };
    pub fn raw_syscall2(number: SyscallNumber, source: u64, rights: u64) -> Result<u64, i32> {
        use super::*;
        assert_eq!(number, SyscallNumber::HandleDuplicate);
        assert_eq!(source, u64::from(SOURCE));
        assert_eq!(PINNED.load(Ordering::Relaxed), 1);
        assert_ne!(CONTROL.native.load(Ordering::Relaxed), 0);
        CALLS.lock().unwrap().push((source, rights));
        if MODE.load(Ordering::Relaxed) == 1 {
            Err(EACCES)
        } else {
            Ok(u64::from(DUPLICATE))
        }
    }
}
mod user_copy {
    pub fn write(destination: *mut u8, bytes: &[u8]) -> Result<(), i32> {
        use super::*;
        assert_eq!(PINNED.load(Ordering::Relaxed), 1);
        assert_ne!(CONTROL.native.load(Ordering::Relaxed), 0);
        assert!(!CONTROL.callback_resources.is_empty());
        if MODE.load(Ordering::Relaxed) == 2 {
            return Err(EFAULT);
        }
        // The successful cases pass a live, disjoint ExportedFdHandle buffer.
        unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), destination, bytes.len()) };
        Ok(())
    }
}

fn reset(rights: u64, mode: u32) {
    assert!(CONTROL.callback_resources.is_empty());
    assert_eq!(CONTROL.native.load(Ordering::Relaxed), 0);
    assert_eq!(PINNED.load(Ordering::Relaxed), 0);
    *ENTRY.lock().unwrap() = Some(FdEntry {
        handle: FdObject {
            lower_handle: u64::from(SOURCE),
            kind: posix_protocol::INHERITED_FD_KIND_FILE,
            open_flags: 2 | 0x4000,
            close_owned: true,
        },
        rights,
        descriptor_flags: fd::FD_CLOEXEC,
    });
    ERRNO.store(0, Ordering::Relaxed);
    MODE.store(mode, Ordering::Relaxed);
    CALLS.lock().unwrap().clear();
    CLOSED.lock().unwrap().clear();
}

#[test]
fn exported_reference_attenuates_access_without_consuming_or_changing_the_fd() {
    let _serial = SERIAL.lock().unwrap();
    for (rights, access) in [(READ, 0), (WRITE, 1), (READ | WRITE, 2)] {
        reset(BASE | READ | WRITE, 0);
        let mut result = implementation::ExportedFdHandle::default();
        assert_eq!(implementation::mochi_fd_export(3, rights, &mut result), 0);
        assert_eq!(
            (result.handle, result.reserved, result.rights),
            (DUPLICATE, 0, rights)
        );
        let metadata = posix_protocol::decode_inherited_fd_metadata(result.metadata).unwrap();
        assert_eq!(metadata.open_flags, 0x4000 | access);
        assert_eq!(metadata.descriptor_flags, fd::FD_CLOEXEC as u8);
        assert_eq!(metadata.kind, posix_protocol::INHERITED_FD_KIND_FILE);
        assert!(CLOSED.lock().unwrap().is_empty());
        assert_eq!(*CALLS.lock().unwrap(), [(u64::from(SOURCE), rights)]);
        let original = ENTRY.lock().unwrap().unwrap();
        assert_eq!(original.handle.open_flags, 2 | 0x4000);
        assert_eq!(original.handle.lower_handle, u64::from(SOURCE));
        assert_eq!(PINNED.load(Ordering::Relaxed), 0);
        assert!(CONTROL.callback_resources.is_empty());
    }
}

#[test]
fn invalid_fd_rights_access_and_pseudo_stdio_never_allocate_a_native_reference() {
    let _serial = SERIAL.lock().unwrap();
    for case in 0..8 {
        reset(BASE | READ, 0);
        let mut result = implementation::ExportedFdHandle::default();
        let (fd, rights, output, expected) = match case {
            0 => (4, READ, &mut result as *mut _, EBADF),
            1 => (3, WRITE, &mut result as *mut _, EACCES),
            2 => (3, 1 << 61, &mut result as *mut _, EINVAL),
            3 => (3, READ, std::ptr::null_mut(), EFAULT),
            4 => {
                ENTRY.lock().unwrap().as_mut().unwrap().rights = READ;
                (3, READ, &mut result as *mut _, EACCES)
            }
            5 => {
                ENTRY.lock().unwrap().as_mut().unwrap().handle.close_owned = false;
                (3, READ, &mut result as *mut _, 95)
            }
            6 => {
                ENTRY.lock().unwrap().as_mut().unwrap().handle.open_flags = 1;
                (3, READ, &mut result as *mut _, EACCES)
            }
            _ => (3, BASE, &mut result as *mut _, EINVAL),
        };
        assert_eq!(implementation::mochi_fd_export(fd, rights, output), -1);
        assert_eq!(ERRNO.load(Ordering::Relaxed), expected);
        assert!(CALLS.lock().unwrap().is_empty());
        assert!(CLOSED.lock().unwrap().is_empty());
        assert_eq!(PINNED.load(Ordering::Relaxed), 0);
        assert!(CONTROL.callback_resources.is_empty());
    }
}

#[test]
fn native_duplicate_and_copyout_failure_reclaim_only_new_ownership() {
    let _serial = SERIAL.lock().unwrap();
    for (mode, expected, closes) in [(1, EACCES, vec![]), (2, EFAULT, vec![DUPLICATE])] {
        reset(BASE | READ, mode);
        let mut result = implementation::ExportedFdHandle::default();
        assert_eq!(implementation::mochi_fd_export(3, READ, &mut result), -1);
        assert_eq!(ERRNO.load(Ordering::Relaxed), expected);
        assert_eq!(*CLOSED.lock().unwrap(), closes);
        assert_eq!(PINNED.load(Ordering::Relaxed), 0);
        assert!(ENTRY.lock().unwrap().is_some());
        assert!(CONTROL.callback_resources.is_empty());
        assert_eq!(CONTROL.native.load(Ordering::Relaxed), 0);
    }
}
