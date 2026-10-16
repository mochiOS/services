//! Run the production PTY adapter against deterministic acquisition/control failures.
#![allow(dead_code)]
use std::ffi::c_int;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard};
use mochios_posix_client::{
    ObjectHandleAttachment,
    fd::{Entry, FdReservation, FdTable},
};
use mochios_posix_client::upcall_guard::Guard;
#[path = "../../../user/crates/newlib-runtime/src/callback_resources.rs"]
mod callback_resources;
#[path = "../../../user/crates/newlib-runtime/src/fd_creation.rs"]
mod fd_creation;
#[path = "../../../user/crates/newlib-runtime/src/pty_creation.rs"]
mod implementation;
#[path = "../../../user/crates/newlib-runtime/src/io_resources.rs"]
mod io_resources;
const EAGAIN: c_int = 11;
const EACCES: c_int = 13;
const EMFILE: c_int = 24;
const EIO: c_int = 5;
const TCSANOW: c_int = 0;
mod syscall {
    pub use mnu_abi::{
        HANDLE_RIGHT_READ, HANDLE_RIGHT_WRITE, HANDLE_RIGHT_WAIT, HANDLE_RIGHT_CONTROL,
        HANDLE_RIGHT_DUPLICATE, HANDLE_RIGHT_TRANSFER,
    };
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FdKind {
    ObjectPty,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Object {
    handle: u32,
    flags: c_int,
    kind: FdKind,
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
fn object_entry(handle: u64, rights: u64, kind: FdKind, flags: c_int) -> FdEntry {
    Entry {
        handle: Object {
            handle: handle as u32,
            flags,
            kind,
        },
        rights,
        descriptor_flags: 0,
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
fn register_current_thread() -> Option<(u32, &'static ThreadControl)> {
    Some((1, &CONTROL))
}
fn defer_native_delivery() -> Option<Guard<'static>> {
    Guard::enter(&CONTROL.native)
}
#[derive(Clone, Copy)]
struct NewlibTermios(u32);
#[derive(Clone, Copy)]
struct NewlibWinSize(u32);
static CASE: AtomicU32 = AtomicU32::new(0);
static CREATES: AtomicU32 = AtomicU32::new(0);
static CONFIGURED: Mutex<Vec<&'static str>> = Mutex::new(Vec::new());
static LIVE: Mutex<Vec<u32>> = Mutex::new(Vec::new());
static CLOSED: Mutex<Vec<u32>> = Mutex::new(Vec::new());
fn process_fd_limit() -> Result<i32, i32> {
    match CASE.load(Ordering::Relaxed) {
        2 => Ok(1),
        3 => Err(EAGAIN),
        _ => Ok(256),
    }
}
fn close_object_handle(handle: u32) {
    assert_ne!(CONTROL.native.load(Ordering::Relaxed), 0);
    let mut live = LIVE.lock().unwrap();
    let index = live
        .iter()
        .position(|&h| h == handle)
        .expect("double close");
    live.remove(index);
    CLOSED.lock().unwrap().push(handle);
}
struct Client;
struct Pair {
    master: ObjectHandleAttachment<u32>,
    slave: ObjectHandleAttachment<u32>,
}
fn posix_client() -> Result<Client, c_int> {
    Ok(Client)
}
fn map_posix_client_error(error: c_int) -> c_int {
    error
}
impl Client {
    fn open_pty(self) -> Result<Pair, c_int> {
        assert_ne!(CONTROL.native.load(Ordering::Relaxed), 0);
        assert!(state().fds.reserve_pair_from(0, 2).is_err());
        CREATES.fetch_add(1, Ordering::Relaxed);
        if CASE.load(Ordering::Relaxed) == 4 {
            return Err(EIO);
        }
        *LIVE.lock().unwrap() = vec![10, 11];
        let rights = syscall::HANDLE_RIGHT_READ
            | syscall::HANDLE_RIGHT_WRITE
            | syscall::HANDLE_RIGHT_WAIT
            | syscall::HANDLE_RIGHT_CONTROL
            | syscall::HANDLE_RIGHT_DUPLICATE
            | syscall::HANDLE_RIGHT_TRANSFER;
        Ok(Pair {
            master: ObjectHandleAttachment { handle: 10, rights },
            slave: ObjectHandleAttachment {
                handle: 11,
                rights: if CASE.load(Ordering::Relaxed) == 5 {
                    rights & !syscall::HANDLE_RIGHT_CONTROL
                } else {
                    rights
                },
            },
        })
    }
}
fn check_control(entry: FdEntry) {
    assert_eq!(
        CONTROL.native.load(Ordering::Relaxed),
        0,
        "callbacks suppressed across control"
    );
    assert!(
        !CONTROL.callback_resources.is_empty(),
        "untracked PTY handles"
    );
    assert_eq!(entry.handle.handle, 11);
    assert!(state().fds.get(0).is_none() && state().fds.get(1).is_none());
    assert!(state().fds.reserve_pair_from(0, 2).is_err());
}
fn set_terminal_attributes(
    entry: FdEntry,
    action: c_int,
    attributes: NewlibTermios,
) -> Result<(), c_int> {
    check_control(entry);
    assert_eq!(action, TCSANOW);
    assert_eq!(attributes.0, 123);
    CONFIGURED.lock().unwrap().push("attributes");
    if CASE.load(Ordering::Relaxed) == 6 {
        Err(EIO)
    } else {
        Ok(())
    }
}
fn set_terminal_window_size(entry: FdEntry, window: NewlibWinSize) -> Result<(), c_int> {
    check_control(entry);
    assert_eq!(window.0, 456);
    CONFIGURED.lock().unwrap().push("window");
    if CASE.load(Ordering::Relaxed) == 7 {
        Err(EIO)
    } else {
        Ok(())
    }
}
#[test]
fn configuration_precedes_publication_and_failures_reclaim_both_references_and_slots() {
    for case in 0..8 {
        state().fds = FdTable::new();
        CASE.store(case, Ordering::Relaxed);
        CREATES.store(0, Ordering::Relaxed);
        LIVE.lock().unwrap().clear();
        CLOSED.lock().unwrap().clear();
        CONFIGURED.lock().unwrap().clear();
        let (mut master, mut slave) = (-123, -123);
        let result = implementation::create(
            &mut master,
            &mut slave,
            if case == 1 {
                std::ptr::null()
            } else {
                &NewlibTermios(123)
            },
            if case == 1 {
                std::ptr::null()
            } else {
                &NewlibWinSize(456)
            },
        );
        if case < 2 {
            assert_eq!(result, Ok(0));
            assert_eq!((master, slave), (0, 1));
            assert_eq!(*LIVE.lock().unwrap(), [10, 11]);
            assert!(CLOSED.lock().unwrap().is_empty());
            for index in 0..2 {
                let entry = state().fds.get(index).unwrap();
                assert_eq!(
                    entry.handle,
                    Object {
                        handle: 10 + index as u32,
                        flags: 2,
                        kind: FdKind::ObjectPty
                    }
                );
            }
        } else {
            assert_eq!(
                result,
                Err(match case {
                    2 => EMFILE,
                    3 => EAGAIN,
                    5 => EACCES,
                    _ => EIO,
                })
            );
            assert_eq!((master, slave), (-123, -123));
            assert!(LIVE.lock().unwrap().is_empty());
            assert_eq!(
                *CLOSED.lock().unwrap(),
                if case >= 5 { vec![10, 11] } else { vec![] }
            );
            let reservations = state().fds.reserve_pair_from(0, 2).unwrap();
            assert_eq!(
                [reservations[0].descriptor(), reservations[1].descriptor()],
                [0, 1]
            );
            for reservation in &reservations {
                assert!(state().fds.cancel_reservation(reservation));
            }
        }
        assert_eq!(
            CREATES.load(Ordering::Relaxed),
            u32::from(!matches!(case, 2 | 3))
        );
        assert_eq!(
            *CONFIGURED.lock().unwrap(),
            match case {
                0 | 7 => vec!["attributes", "window"],
                6 => vec!["attributes"],
                _ => vec![],
            }
        );
        assert!(CONTROL.callback_resources.is_empty());
        assert_eq!(CONTROL.native.load(Ordering::Relaxed), 0);
    }
}
