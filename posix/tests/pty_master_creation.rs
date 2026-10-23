//! Production runtime FD/Handle owners with controlled native acquisition.
#![allow(dead_code)]
use mochios_posix_client::{
    ObjectHandleAttachment,
    fd::{Entry, FdReservation, FdTable},
    upcall_guard::Guard,
};
use std::{
    ffi::c_int,
    sync::{
        Mutex, MutexGuard,
        atomic::{AtomicU32, AtomicU64, Ordering},
    },
};
#[path = "../../../user/crates/newlib-runtime/src/callback_resources.rs"]
mod callback_resources;
#[path = "../../../user/crates/newlib-runtime/src/fd_creation.rs"]
mod fd_creation;
#[path = "../../../user/crates/newlib-runtime/src/pty_master.rs"]
mod implementation;
#[path = "../../../user/crates/newlib-runtime/src/io_resources.rs"]
mod io_resources;
const EINVAL: i32 = 22;
const EAGAIN: i32 = 11;
const EMFILE: i32 = 24;
const EACCES: i32 = 13;
const EIO: i32 = 5;
const O_NONBLOCK: i32 = 0x4000;
const O_CLOEXEC: i32 = 0x40000;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FdKind {
    ObjectPty,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Object {
    handle: u32,
    flags: i32,
}
struct State {
    fds: FdTable<Object>,
}
static STATE: Mutex<State> = Mutex::new(State {
    fds: FdTable::new(),
});
fn state() -> MutexGuard<'static, State> {
    STATE.lock().unwrap()
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
static CREATES: AtomicU32 = AtomicU32::new(0);
static OPTIONS: AtomicU32 = AtomicU32::new(0);
static LIVE: AtomicU32 = AtomicU32::new(0);
static CLOSES: AtomicU32 = AtomicU32::new(0);
fn register_current_thread() -> Option<(u32, &'static ThreadControl)> {
    Some((1, &CONTROL))
}
fn defer_native_delivery() -> Option<Guard<'static>> {
    Guard::enter(&CONTROL.native)
}
fn process_fd_limit() -> Result<c_int, i32> {
    Ok(if CASE.load(Ordering::Acquire) == 5 {
        0
    } else {
        1
    })
}
fn object_entry(handle: u64, rights: u64, _: FdKind, flags: i32) -> Entry<Object> {
    assert!(CONTROL.native.load(Ordering::Acquire) > 0);
    assert!(!CONTROL.callback_resources.is_empty());
    if CASE.load(Ordering::Acquire) == 4 {
        state().fds = FdTable::new();
    }
    Entry {
        handle: Object {
            handle: handle as u32,
            flags,
        },
        rights,
        descriptor_flags: if flags & O_CLOEXEC != 0 { 1 } else { 0 },
    }
}
fn close_object_handle(handle: u32) {
    assert_eq!(handle, 61);
    assert_eq!(LIVE.swap(0, Ordering::AcqRel), 1, "double close");
    CLOSES.fetch_add(1, Ordering::AcqRel);
}
mod user_copy {
    pub fn write(_: *mut u8, _: &[u8]) -> Result<(), i32> {
        unreachable!()
    }
}
mod syscall {
    pub use mnu_abi::{
        HANDLE_OPTION_NONBLOCKING, HANDLE_RIGHT_CONTROL, HANDLE_RIGHT_DUPLICATE, HANDLE_RIGHT_READ,
        HANDLE_RIGHT_TRANSFER, HANDLE_RIGHT_WAIT, HANDLE_RIGHT_WRITE,
    };
    pub enum SyscallNumber {
        HandleOptionsSet,
    }
    pub fn raw_syscall2(_: SyscallNumber, handle: u64, options: u64) -> Result<u64, i32> {
        use super::*;
        assert_eq!((handle, options), (61, HANDLE_OPTION_NONBLOCKING));
        assert!(CONTROL.native.load(Ordering::Acquire) > 0);
        assert!(state().fds.get(0).is_none());
        OPTIONS.fetch_add(1, Ordering::AcqRel);
        if CASE.load(Ordering::Acquire) == 3 {
            Err(EIO)
        } else {
            Ok(0)
        }
    }
}
fn syscall_errno(result: Result<u64, i32>) -> Result<u64, i32> {
    result
}
struct Client;
fn posix_client() -> Result<Client, i32> {
    Ok(Client)
}
fn map_posix_client_error(error: i32) -> i32 {
    error
}
impl Client {
    fn open_pty_master(self) -> Result<ObjectHandleAttachment<u32>, i32> {
        assert!(CONTROL.native.load(Ordering::Acquire) > 0);
        assert!(state().fds.get(0).is_none());
        assert!(
            state().fds.reserve_from(0, 1).is_err(),
            "FD not reserved before RPC"
        );
        CREATES.fetch_add(1, Ordering::AcqRel);
        if CASE.load(Ordering::Acquire) == 1 {
            return Err(EIO);
        }
        assert_eq!(LIVE.swap(1, Ordering::AcqRel), 0);
        Ok(ObjectHandleAttachment {
            handle: 61,
            rights: posix_service::pty_factory::MASTER_RIGHTS
                & if CASE.load(Ordering::Acquire) == 2 {
                    !syscall::HANDLE_RIGHT_CONTROL
                } else {
                    u64::MAX
                },
        })
    }
}
#[test]
fn master_fd_is_published_once_and_every_creation_failure_reclaims_reservation_and_handle() {
    for case in 0..=5 {
        for flags in [2, 2 | 0x8000, 2 | O_NONBLOCK, 2 | O_NONBLOCK | O_CLOEXEC] {
            CASE.store(case, Ordering::Release);
            CREATES.store(0, Ordering::Release);
            OPTIONS.store(0, Ordering::Release);
            LIVE.store(0, Ordering::Release);
            CLOSES.store(0, Ordering::Release);
            state().fds = FdTable::new();
            let result = implementation::create(flags);
            if case == 0 {
                assert_eq!(result, Ok(0));
                let entry = state().fds.get(0).unwrap();
                assert_eq!(entry.handle, Object { handle: 61, flags });
                assert_eq!(
                    entry.descriptor_flags,
                    if flags & O_CLOEXEC != 0 { 1 } else { 0 }
                );
                assert_eq!(CLOSES.load(Ordering::Acquire), 0);
                close_object_handle(entry.handle.handle);
                state().fds = FdTable::new();
            } else {
                let failed = case != 3 || flags & O_NONBLOCK != 0;
                if failed {
                    assert_eq!(
                        result,
                        Err(if case == 2 {
                            EACCES
                        } else if case == 5 {
                            EMFILE
                        } else {
                            EIO
                        })
                    );
                    assert!(state().fds.get(0).is_none());
                    assert_eq!(
                        CLOSES.load(Ordering::Acquire),
                        u32::from((2..=4).contains(&case))
                    );
                } else {
                    assert_eq!(result, Ok(0));
                    close_object_handle(61);
                    state().fds = FdTable::new();
                }
            }
            assert_eq!(LIVE.load(Ordering::Acquire), 0);
            assert_eq!(CREATES.load(Ordering::Acquire), u32::from(case != 5));
            assert!(CONTROL.callback_resources.is_empty());
            assert_eq!(CONTROL.native.load(Ordering::Acquire), 0);
            let ticket = state().fds.reserve_from(0, 1).unwrap();
            assert_eq!(ticket.descriptor(), 0);
            state().fds.cancel_reservation(&ticket);
        }
    }
    CREATES.store(0, Ordering::Release);
    for flags in [0, 1, 3, -1, 2 | 0x200, 2 | 0x8] {
        assert_eq!(implementation::create(flags), Err(EINVAL));
    }
    assert_eq!(CREATES.load(Ordering::Acquire), 0);
}
