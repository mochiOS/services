//! Execute production status adapters with a reentrant/failing provider.
#![allow(dead_code)]
use std::ffi::c_int;
use std::sync::{Mutex, MutexGuard};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use mochios_posix_client::{
    ObjectHandleAttachment,
    fd::{Entry, FdTable},
    handle_borrow::Book,
    upcall_guard::Guard,
};
#[path = "../../../user/crates/newlib-runtime/src/callback_resources.rs"]
mod callback_resources;
#[path = "../../../user/crates/newlib-runtime/src/fd_options.rs"]
mod implementation;
#[path = "../../../user/crates/newlib-runtime/src/io_resources.rs"]
mod io_resources;
const EBADF: c_int = 9;
const EAGAIN: c_int = 11;
const EINVAL: c_int = 22;
const ENOTTY: c_int = 25;
const EIO: c_int = 5;
const O_NONBLOCK: c_int = 0x4000;
const F_GETFL: c_int = 3;
const F_SETFL: c_int = 4;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FdKind {
    Unused,
    Stdin,
    Stdout,
    Stderr,
    ObjectFile,
    ObjectSpecial,
    ObjectDirectory,
    ObjectSharedMemory,
    ObjectSocket,
    ObjectDatagram,
    ObjectStreamRead,
    ObjectStreamWrite,
    ObjectPty,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Object {
    lower_handle: u64,
    kind: FdKind,
    open_flags: c_int,
}
type FdEntry = Entry<Object>;
struct State {
    fds: FdTable<Object>,
}
static STATE: Mutex<State> = Mutex::new(State {
    fds: FdTable::new(),
});
fn state() -> MutexGuard<'static, State> {
    STATE.lock().unwrap()
}
static BOOK: Mutex<Book<32>> = Mutex::new(Book::new());
static CLOSED: Mutex<Vec<u32>> = Mutex::new(Vec::new());
static SERIAL: Mutex<()> = Mutex::new(());
static SOURCE: Mutex<Option<FdEntry>> = Mutex::new(None);
static CASE: AtomicU32 = AtomicU32::new(0);
static CALLS: AtomicU32 = AtomicU32::new(0);
mod fd_lease {
    use super::*;
    pub(super) struct Lease {
        entry: FdEntry,
        pin: Option<mochios_posix_client::handle_borrow::Pin>,
    }
    impl Lease {
        pub fn new(entry: FdEntry) -> Result<Self, c_int> {
            assert_ne!(CONTROL.native.load(Ordering::Relaxed), 0);
            let pin = BOOK
                .lock()
                .unwrap()
                .pin(entry.handle.lower_handle)
                .ok_or(EBADF)?;
            Ok(Self {
                entry,
                pin: Some(pin),
            })
        }
    }
    impl std::ops::Deref for Lease {
        type Target = FdEntry;
        fn deref(&self) -> &FdEntry {
            &self.entry
        }
    }
    impl Drop for Lease {
        fn drop(&mut self) {
            assert_ne!(CONTROL.native.load(Ordering::Relaxed), 0);
            let close = BOOK.lock().unwrap().release(self.pin.take().unwrap());
            if close {
                close_object_handle(self.entry.handle.lower_handle as u32);
            }
        }
    }
}
fn with_fd_entry(fd: c_int) -> Result<fd_lease::Lease, c_int> {
    fd_lease::Lease::new(state().fds.get(fd).ok_or(EBADF)?)
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
fn register_current_thread() -> Option<(u32, &'static ThreadControl)> {
    Some((1, &CONTROL))
}
fn defer_native_delivery() -> Option<Guard<'static>> {
    Guard::enter(&CONTROL.native)
}
fn close_object_handle(handle: u32) {
    CLOSED.lock().unwrap().push(handle);
}
fn remove(fd: i32) {
    let entry = state().fds.take(fd).unwrap();
    if BOOK
        .lock()
        .unwrap()
        .retire(entry.handle.lower_handle)
        .unwrap()
    {
        close_object_handle(entry.handle.lower_handle as u32);
    }
}
fn entry(kind: FdKind, handle: u64, flags: c_int) -> FdEntry {
    Entry {
        handle: Object {
            lower_handle: handle,
            kind,
            open_flags: flags,
        },
        rights: 7,
        descriptor_flags: 0,
    }
}
fn backend(handle: u64) -> Result<(), c_int> {
    assert_eq!(handle, 10);
    assert!(STATE.try_lock().is_ok(), "STATE held across provider call");
    assert_eq!(
        CONTROL.native.load(Ordering::Relaxed),
        0,
        "delivery deferred across provider call"
    );
    assert!(!CONTROL.callback_resources.is_empty());
    CALLS.fetch_add(1, Ordering::Relaxed);
    if CASE.load(Ordering::Relaxed) >= 2 {
        remove(0);
        assert!(
            CLOSED.lock().unwrap().is_empty(),
            "operation lost its source reference"
        );
        state()
            .fds
            .install_from(0, 32, entry(FdKind::ObjectFile, 20, 123))
            .unwrap();
        assert_eq!(implementation::status(1, F_SETFL, 77), Ok(0));
    }
    if CASE.load(Ordering::Relaxed) % 2 == 1 {
        Err(EIO)
    } else {
        Ok(())
    }
}
fn validate(entry: FdEntry) {
    assert_eq!(Some(entry), *SOURCE.lock().unwrap());
}
mod socket {
    use super::*;
    pub fn get_status_flags(entry: FdEntry) -> Result<c_int, c_int> {
        validate(entry);
        backend(entry.handle.lower_handle)?;
        Ok(2 | O_NONBLOCK)
    }
    pub fn set_status_flags(entry: FdEntry, flags: c_int) -> Result<(), c_int> {
        validate(entry);
        assert_eq!(flags, 2 | O_NONBLOCK);
        backend(entry.handle.lower_handle)
    }
}
mod shared_memory {
    pub use super::socket::{get_status_flags, set_status_flags};
    pub fn update_status_flags(entry: super::FdEntry, _: u32, _: u32) -> Result<(), i32> {
        super::backend(entry.handle.lower_handle)
    }
}
mod posix_protocol {
    pub const OPEN_NONBLOCK: u32 = 0x4000;
}
struct Client;
fn posix_client() -> Result<Client, c_int> {
    Ok(Client)
}
fn map_posix_client_error(error: c_int) -> c_int {
    error
}
fn newlib_mutable_status_flags(flags: u32) -> c_int {
    flags as c_int
}
fn posix_mutable_status_flags(flags: c_int) -> u32 {
    (flags & !3) as u32
}
impl Client {
    fn get_status_flags(self, handle: ObjectHandleAttachment<u32>) -> Result<u32, c_int> {
        assert_eq!(handle.rights, 7);
        backend(handle.handle.into())?;
        Ok(O_NONBLOCK as u32)
    }
    fn set_status_flags(
        self,
        handle: ObjectHandleAttachment<u32>,
        flags: u32,
    ) -> Result<(), c_int> {
        assert_eq!(handle.rights, 7);
        assert_eq!(flags, O_NONBLOCK as u32);
        backend(handle.handle.into())
    }
    fn update_status_flags(
        self,
        handle: ObjectHandleAttachment<u32>,
        _: u32,
        _: u32,
        _: fn(u32),
    ) -> Result<(), c_int> {
        backend(handle.handle.into())
    }
}
mod syscall {
    pub const HANDLE_OPTION_NONBLOCKING: u64 = 1;
    pub const HANDLE_OPTIONS_ALL: u64 = 1;
    pub enum SyscallNumber {
        HandleOptionsGet,
        HandleOptionsSet,
    }
    pub fn raw_syscall1(_: SyscallNumber, handle: u64) -> u64 {
        match super::backend(handle) {
            Ok(()) => 1,
            Err(error) => (-(error as i64)) as u64,
        }
    }
    pub fn raw_syscall2(_: SyscallNumber, handle: u64, options: u64) -> u64 {
        assert_eq!(options, 1);
        match super::backend(handle) {
            Ok(()) => 0,
            Err(error) => (-(error as i64)) as u64,
        }
    }
}
fn syscall_errno(value: u64) -> Result<u64, c_int> {
    if value >= (-4095i64) as u64 {
        Err(-(value as i64) as c_int)
    } else {
        Ok(value)
    }
}
fn result_with_errno(result: Result<c_int, c_int>, fallback: c_int) -> c_int {
    result.unwrap_or(fallback)
}
#[test]
fn provider_status_calls_run_without_state_lock_and_retain_the_original_reference_on_reentry() {
    let _serial = SERIAL.lock().unwrap();
    for kind in [
        FdKind::ObjectFile,
        FdKind::ObjectSpecial,
        FdKind::ObjectDirectory,
        FdKind::ObjectSharedMemory,
        FdKind::ObjectSocket,
        FdKind::ObjectDatagram,
        FdKind::ObjectStreamRead,
        FdKind::ObjectStreamWrite,
        FdKind::ObjectPty,
    ] {
        for command in [F_GETFL, F_SETFL] {
            for case in 0..4 {
                state().fds = FdTable::new();
                *BOOK.lock().unwrap() = Book::new();
                CLOSED.lock().unwrap().clear();
                CASE.store(case, Ordering::Relaxed);
                CALLS.store(0, Ordering::Relaxed);
                let source = entry(kind, 10, 2);
                *SOURCE.lock().unwrap() = Some(source);
                state().fds.install_from(0, 32, source).unwrap();
                state()
                    .fds
                    .install_from(0, 32, entry(FdKind::Stdin, 0, 0))
                    .unwrap();
                assert_eq!(
                    implementation::status(0, command, 2 | O_NONBLOCK),
                    if case % 2 == 1 {
                        Err(EIO)
                    } else {
                        Ok(if command == F_GETFL {
                            2 | O_NONBLOCK
                        } else {
                            0
                        })
                    }
                );
                assert_eq!(CALLS.load(Ordering::Relaxed), 1);
                if case >= 2 {
                    assert_eq!(*CLOSED.lock().unwrap(), [10]);
                    assert_eq!(state().fds.get(0).unwrap().handle.lower_handle, 20);
                    assert_eq!(state().fds.get(0).unwrap().handle.open_flags, 123);
                    assert_eq!(state().fds.get(1).unwrap().handle.open_flags, 77);
                } else {
                    assert!(CLOSED.lock().unwrap().is_empty());
                }
                remove(0);
                assert_eq!(
                    *CLOSED.lock().unwrap(),
                    if case >= 2 { vec![10, 20] } else { vec![10] }
                );
                assert!(CONTROL.callback_resources.is_empty());
                assert_eq!(CONTROL.native.load(Ordering::Relaxed), 0);
            }
        }
    }
}

#[test]
fn local_status_and_invalid_descriptors_do_not_pin_or_call_a_provider() {
    let _serial = SERIAL.lock().unwrap();
    for kind in [
        FdKind::Unused,
        FdKind::Stdin,
        FdKind::Stdout,
        FdKind::Stderr,
    ] {
        state().fds = FdTable::new();
        CALLS.store(0, Ordering::Relaxed);
        state().fds.install_from(0, 32, entry(kind, 0, 5)).unwrap();
        assert_eq!(implementation::status(0, F_GETFL, 0), Ok(5));
        assert_eq!(implementation::status(0, F_SETFL, 99), Ok(0));
        assert_eq!(implementation::status(0, F_GETFL, 0), Ok(99));
        assert_eq!(implementation::status(-1, F_GETFL, 0), Err(EBADF));
        assert_eq!(implementation::status(1, F_SETFL, 0), Err(EBADF));
        assert_eq!(CALLS.load(Ordering::Relaxed), 0);
        assert!(CONTROL.callback_resources.is_empty());
        assert_eq!(CONTROL.native.load(Ordering::Relaxed), 0);
    }
}

#[test]
fn native_streams_reject_unsupported_status_bits_before_calling_the_backend() {
    let _serial = SERIAL.lock().unwrap();
    for kind in [
        FdKind::ObjectStreamRead,
        FdKind::ObjectStreamWrite,
        FdKind::ObjectPty,
    ] {
        state().fds = FdTable::new();
        *BOOK.lock().unwrap() = Book::new();
        CALLS.store(0, Ordering::Relaxed);
        CLOSED.lock().unwrap().clear();
        state().fds.install_from(0, 32, entry(kind, 10, 2)).unwrap();
        assert_eq!(implementation::status(0, F_SETFL, 0x1000_0000), Err(EINVAL));
        assert_eq!(CALLS.load(Ordering::Relaxed), 0);
        remove(0);
        assert_eq!(*CLOSED.lock().unwrap(), [10]);
        assert!(CONTROL.callback_resources.is_empty());
    }
}

#[test]
fn fcntl_routes_shared_status_before_locking_the_descriptor_table() {
    let source = include_str!("../../../user/crates/newlib-runtime/src/lib.rs");
    let start = source.find("fn fcntl(").unwrap();
    let end = start + source[start..].find("\n}\n").unwrap();
    let body = &source[start..end];
    assert!(
        body.find("return fd_options::status(fd, cmd, arg)")
            .unwrap()
            < body.find("let mut state = state()").unwrap()
    );
    assert!(!body.contains(".get_status_flags("));
    assert!(!body.contains(".set_status_flags("));
}
