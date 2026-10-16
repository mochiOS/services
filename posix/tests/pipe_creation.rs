//! Execute the actual pipe adapter with a deterministic failing native backend.
use mochios_posix_client::upcall_guard::Guard;
use mochios_posix_client::{
    ObjectHandleAttachment,
    fd::{Entry, FdReservation, FdTable},
};
use mochios_posix_protocol as posix_protocol;
use std::ffi::{c_char, c_int};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard};
#[path = "../../../user/crates/newlib-runtime/src/callback_resources.rs"]
mod callback_resources;
#[path = "../../../user/crates/newlib-runtime/src/fd_creation.rs"]
mod fd_creation;
#[path = "../../../user/crates/newlib-runtime/src/pipe.rs"]
mod implementation;
#[path = "../../../user/crates/newlib-runtime/src/io_resources.rs"]
mod io_resources;
#[path = "../../../user/crates/newlib-runtime/src/user_copy.rs"]
mod user_copy;
#[path = "support/user_copy_native.rs"]
mod user_copy_native;

const EAGAIN: c_int = 11;
const EMFILE: c_int = 24;
const EIO: c_int = 5;
const EFAULT: c_int = 14;
const ENOENT: c_int = 2;
const ENAMETOOLONG: c_int = 91;
const PAGE_SIZE: usize = 4096;
const O_NONBLOCK: c_int = 0x4000;
const O_CLOEXEC: c_int = 0x80000;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FdKind {
    ObjectStreamRead,
    ObjectStreamWrite,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Object {
    handle: u32,
    kind: FdKind,
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
fn object_entry(handle: u64, rights: u64, kind: FdKind, flags: i32) -> Entry<Object> {
    Entry {
        handle: Object {
            handle: handle as u32,
            kind,
            flags,
        },
        rights,
        descriptor_flags: u32::from(flags & O_CLOEXEC != 0),
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
static CASE: AtomicU32 = AtomicU32::new(0);
static CREATES: AtomicU32 = AtomicU32::new(0);
static OPTIONS: AtomicU32 = AtomicU32::new(0);
static LIVE: Mutex<Vec<u32>> = Mutex::new(Vec::new());
static CLOSED: Mutex<Vec<u32>> = Mutex::new(Vec::new());
static SERIAL: Mutex<()> = Mutex::new(());
fn process_fd_limit() -> Result<i32, i32> {
    match CASE.load(Ordering::Relaxed) {
        2 => Ok(1),
        6 => Err(EAGAIN),
        _ => Ok(256),
    }
}
fn close_object_handle(handle: u32) {
    assert_ne!(CONTROL.native.load(Ordering::Relaxed), 0);
    let mut live = LIVE.lock().unwrap();
    let index = live
        .iter()
        .position(|&item| item == handle)
        .expect("double close");
    live.remove(index);
    CLOSED.lock().unwrap().push(handle);
}
fn syscall_errno(raw: u64) -> Result<u64, i32> {
    if mnu_abi::status::is_error(raw) || raw >= (-4095i64) as u64 {
        Err(mochios_posix_client::newlib_errno::from_status(raw as i64))
    } else {
        Ok(raw)
    }
}
mod syscall {
    use super::*;
    pub use mnu_abi::{
        HANDLE_OPTION_NONBLOCKING, HANDLE_RIGHT_CONTROL, HANDLE_RIGHT_DUPLICATE, HANDLE_RIGHT_READ,
        HANDLE_RIGHT_TRANSFER, HANDLE_RIGHT_WAIT, HANDLE_RIGHT_WRITE,
    };
    pub enum SyscallNumber {
        StreamPairCreate,
        HandleOptionsSet,
        MemoryCopy,
    }
    pub fn raw_syscall3(number: SyscallNumber, destination: u64, source: u64, length: u64) -> u64 {
        assert!(matches!(number, SyscallNumber::MemoryCopy));
        user_copy_native::syscall::raw_syscall3(
            mnu_abi::SyscallNumber::MemoryCopy,
            destination,
            source,
            length,
        )
        .unwrap_or_else(|errno| (-i64::from(errno)) as u64)
    }
    #[derive(Default)]
    pub struct StreamPair {
        pub read: u32,
        pub write: u32,
    }
    pub fn raw_syscall1(_: SyscallNumber, output: u64) -> u64 {
        assert_ne!(CONTROL.native.load(Ordering::Relaxed), 0);
        assert!(
            state().fds.reserve_pair_from(0, 2).is_err(),
            "FDs not reserved first"
        );
        CREATES.fetch_add(1, Ordering::Relaxed);
        if CASE.load(Ordering::Relaxed) == 3 {
            return mnu_abi::status::Error::ResourceUnavailable.into_raw();
        }
        if CASE.load(Ordering::Relaxed) == 8 {
            return mnu_abi::status::Error::NotReady.into_raw();
        }
        unsafe {
            (output as *mut StreamPair).write(StreamPair {
                read: 10,
                write: 11,
            });
        }
        *LIVE.lock().unwrap() = vec![10, 11];
        0
    }
    pub fn raw_syscall2(_: SyscallNumber, handle: u64, options: u64) -> u64 {
        assert_ne!(CONTROL.native.load(Ordering::Relaxed), 0);
        let call = OPTIONS.fetch_add(1, Ordering::Relaxed) + 1;
        assert_eq!(handle, 9 + u64::from(call));
        assert_eq!(options, HANDLE_OPTION_NONBLOCKING);
        if CASE.load(Ordering::Relaxed) == 3 + call {
            (-5i64) as u64
        } else {
            0
        }
    }
}

#[test]
fn native_failures_release_both_handles_and_every_reserved_slot_before_return() {
    let _serial = SERIAL.lock().unwrap();
    for case in 0..9 {
        assert!(CONTROL.callback_resources.is_empty());
        assert_eq!(CONTROL.native.load(Ordering::Relaxed), 0);
        state().fds = FdTable::new();
        CASE.store(case, Ordering::Relaxed);
        CREATES.store(0, Ordering::Relaxed);
        OPTIONS.store(0, Ordering::Relaxed);
        LIVE.lock().unwrap().clear();
        CLOSED.lock().unwrap().clear();
        let flags = if matches!(case, 1 | 4 | 5) {
            O_NONBLOCK | O_CLOEXEC
        } else {
            0
        };
        let mut output = [-123; 2];
        let result = implementation::create(
            if case == 7 {
                1usize as *mut _
            } else {
                output.as_mut_ptr()
            },
            flags,
        );
        if case < 2 {
            assert_eq!(result, Ok(0));
            assert_eq!(output, [0, 1]);
            for index in 0..2 {
                let entry = state().fds.get(index).unwrap();
                assert_eq!(entry.handle.handle, 10 + index as u32);
                assert_eq!(entry.handle.flags, flags | index);
                assert_eq!(entry.descriptor_flags, u32::from(case == 1));
                assert_eq!(
                    entry.handle.kind,
                    if index == 0 {
                        FdKind::ObjectStreamRead
                    } else {
                        FdKind::ObjectStreamWrite
                    }
                );
                assert_eq!(
                    entry.rights & (syscall::HANDLE_RIGHT_READ | syscall::HANDLE_RIGHT_WRITE),
                    if index == 0 {
                        syscall::HANDLE_RIGHT_READ
                    } else {
                        syscall::HANDLE_RIGHT_WRITE
                    }
                );
            }
            assert!(CLOSED.lock().unwrap().is_empty());
            assert_eq!(*LIVE.lock().unwrap(), [10, 11]);
        } else {
            assert_eq!(
                result,
                Err(match case {
                    2 => EMFILE,
                    3 => 12,
                    4 | 5 => EIO,
                    7 => EFAULT,
                    _ => EAGAIN,
                })
            );
            assert_eq!(output, [-123; 2]);
            assert!(LIVE.lock().unwrap().is_empty());
            assert_eq!(
                *CLOSED.lock().unwrap(),
                if matches!(case, 4 | 5 | 7) {
                    vec![10, 11]
                } else {
                    vec![]
                }
            );
            let group = state().fds.reserve_pair_from(0, 2).unwrap();
            assert_eq!([group[0].descriptor(), group[1].descriptor()], [0, 1]);
            for reservation in &group {
                assert!(state().fds.cancel_reservation(reservation));
            }
        }
        assert_eq!(
            CREATES.load(Ordering::Relaxed),
            u32::from(!matches!(case, 2 | 6))
        );
        assert_eq!(
            OPTIONS.load(Ordering::Relaxed),
            match case {
                1 | 5 => 2,
                4 => 1,
                _ => 0,
            }
        );
        assert!(CONTROL.callback_resources.is_empty());
        assert_eq!(CONTROL.native.load(Ordering::Relaxed), 0);
    }
}

#[test]
fn pair_copy_preserves_c_integer_layout_and_never_installs_reserved_descriptors() {
    let _serial = SERIAL.lock().unwrap();
    let _native = defer_native_delivery();
    state().fds = FdTable::new();
    let pair = fd_creation::PendingPair(state().fds.reserve_pair_from(0, 2).unwrap());
    let mut bytes = [0xa5u8; 10];
    pair.copy_descriptors(bytes.as_mut_ptr().wrapping_add(1).cast())
        .unwrap();
    assert_eq!(&bytes[1..5], 0i32.to_ne_bytes());
    assert_eq!(&bytes[5..9], 1i32.to_ne_bytes());
    assert_eq!((bytes[0], bytes[9]), (0xa5, 0xa5));
    assert_eq!(pair.copy_descriptors(1usize as *mut _), Err(EFAULT));
    assert_eq!(pair.copy_descriptors(usize::MAX as *mut _), Err(EFAULT));
    assert!(state().fds.get(0).is_none() && state().fds.get(1).is_none());
    drop(pair);
    let reused = state().fds.reserve_pair_from(0, 2).unwrap();
    for reservation in &reused {
        assert!(state().fds.cancel_reservation(reservation));
    }
}
