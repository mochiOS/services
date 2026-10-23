//! Compile the production runtime CPU sleep body with deterministic native
//! waits. FD lease ownership is separately tested against its real pin book.
#![allow(non_camel_case_types, dead_code)]
use mochios_posix_client::{ClientError as PosixClientError, ObjectHandleAttachment};
use mochios_posix_protocol as posix_protocol;
use std::cell::{Cell, RefCell};
use std::sync::atomic::{AtomicU64, Ordering};

type c_int = i32;
const EINVAL: i32 = 22;
const ESRCH: i32 = 3;
const EINTR: i32 = 4;
const EAGAIN: i32 = 11;
const EIO: i32 = 5;
const EFAULT: i32 = 14;
const EOVERFLOW: i32 = 75;
const O_NONBLOCK: i32 = 0x4000;
struct Timespec {
    tv_sec: i64,
    tv_nsec: i64,
}
struct ThreadControl {
    caught_signal_generation: AtomicU64,
}
thread_local! {
    static CONTROL: ThreadControl = const { ThreadControl { caught_signal_generation: AtomicU64::new(0) } };
    static CASE: Cell<u32> = const { Cell::new(0) };
    static PID: Cell<u64> = const { Cell::new(7) };
    static READS: Cell<usize> = const { Cell::new(0) };
    static WAITS: Cell<usize> = const { Cell::new(0) };
    static CLOSED: Cell<usize> = const { Cell::new(0) };
    static CANCEL: Cell<bool> = const { Cell::new(false) };
    static SCOPED: Cell<bool> = const { Cell::new(false) };
    static REQUESTS: RefCell<Vec<posix_protocol::cpu_sleep::Request>> = const { RefCell::new(Vec::new()) };
    static SAMPLES: RefCell<Vec<u64>> = const { RefCell::new(Vec::new()) };
}
#[derive(Debug)]
struct SysError;
impl SysError {
    fn raw(self) -> i64 {
        5
    }
}
fn native_process_id() -> Result<u64, SysError> {
    Ok(PID.get())
}
fn map_kernel_errno(raw: i64) -> i32 {
    raw as i32
}
fn map_posix_client_error(error: PosixClientError<()>) -> i32 {
    match error {
        PosixClientError::Remote(status) => -status,
        _ => EIO,
    }
}
fn register_current_thread() -> Option<(usize, &'static ThreadControl)> {
    // Thread-local control outlives every synchronous call in these probes.
    Some((1, unsafe {
        &*CONTROL.with(|control| control as *const ThreadControl)
    }))
}
fn io_cancellation_requested(_: &ThreadControl) -> bool {
    CANCEL.get() && CASE.get() != 3
}
fn pthread_testcancel() {
    assert!(
        !SCOPED.get(),
        "resource scope must be retired before cancellation"
    );
    if CANCEL.get() && CASE.get() != 3 {
        assert_eq!(CLOSED.get(), 1);
        std::panic::panic_any("cancelled");
    }
}
#[derive(Clone, Copy)]
struct Object {
    lower_handle: u64,
}
#[derive(Clone, Copy)]
struct Entry {
    handle: Object,
}
enum FdKind {
    ObjectStreamRead,
}
fn object_entry(handle: u64, rights: u64, _: FdKind, flags: i32) -> Entry {
    assert_eq!(rights, posix_protocol::cpu_sleep::COMPLETION_RIGHTS);
    assert_eq!(flags, O_NONBLOCK);
    Entry {
        handle: Object {
            lower_handle: handle,
        },
    }
}
mod fd_lease {
    use super::*;
    pub(super) struct Lease(Entry);
    impl Lease {
        pub fn adopt_private(entry: Entry) -> Result<Self, i32> {
            assert!(SCOPED.get());
            Ok(Self(entry))
        }
    }
    impl std::ops::Deref for Lease {
        type Target = Entry;
        fn deref(&self) -> &Entry {
            &self.0
        }
    }
    impl Drop for Lease {
        fn drop(&mut self) {
            assert!(SCOPED.get());
            CLOSED.set(CLOSED.get() + 1);
        }
    }
}
mod io_resources {
    use super::*;
    pub unsafe fn with_fork_opaque<R, T: Copy>(
        prepare: impl FnOnce() -> Result<R, i32>,
        allow: impl FnOnce(&R) -> bool,
        operation: impl FnOnce(&mut R) -> Result<T, i32>,
    ) -> Result<T, i32> {
        assert!(!SCOPED.replace(true));
        let result = match prepare() {
            Ok(mut resources) => {
                assert!(allow(&resources));
                operation(&mut resources)
            }
            Err(error) => Err(error),
        };
        assert!(SCOPED.replace(false));
        result
    }
}
struct Client;
fn posix_client() -> Result<Client, PosixClientError<()>> {
    Ok(Client)
}
impl Client {
    fn begin_process_cpu_sleep(
        &self,
        request: posix_protocol::cpu_sleep::Request,
    ) -> Result<mochios_posix_client::cpu_sleep::Pending<u32>, PosixClientError<()>> {
        REQUESTS.with(|requests| requests.borrow_mut().push(request));
        if CASE.get() == 9 {
            return Err(PosixClientError::Remote(-3));
        }
        Ok(mochios_posix_client::cpu_sleep::Pending {
            completion: ObjectHandleAttachment {
                handle: 77,
                rights: posix_protocol::cpu_sleep::COMPLETION_RIGHTS,
            },
            deadline_ns: 300_000_000,
        })
    }
}
mod process_clock {
    use super::*;
    pub fn nanoseconds(pid: u64) -> Result<u128, i32> {
        assert_eq!(CLOSED.get(), 1);
        SAMPLES.with(|samples| samples.borrow_mut().push(pid));
        Ok(100_000_000)
    }
}
mod time_memory {
    use super::*;
    pub fn write_timespec(out: *mut Timespec, value: Timespec) -> Result<(), i32> {
        assert_eq!(CLOSED.get(), 1);
        if (out as usize) < 4096 {
            return Err(EFAULT);
        }
        unsafe {
            out.write(value);
        }
        Ok(())
    }
}
mod syscall {
    pub use mnu_abi::{
        HANDLE_SIGNAL_PEER_CLOSED, HANDLE_SIGNAL_READABLE, HANDLE_WAIT_INFINITE, HandleWaitItem,
    };
    pub enum SyscallNumber {
        StreamRead,
    }
    pub fn raw_syscall4(
        _: SyscallNumber,
        handle: u64,
        destination: u64,
        length: u64,
        options: u64,
    ) -> Result<u64, i32> {
        use super::*;
        assert!(SCOPED.get());
        assert_eq!(handle, 77);
        assert_eq!(options, mnu_abi::STREAM_IO_TRY);
        let read = READS.get();
        READS.set(read + 1);
        match CASE.get() {
            1 | 2 | 3 | 11 | 12 | 13 if read == 0 => return Err(EAGAIN),
            4 => return Ok(0),
            5 => return Err(EIO),
            6 => {
                CANCEL.set(true);
                return Err(EIO);
            }
            8 if read != 0 => return Ok(0),
            _ => {}
        }
        let mut packet = [0; posix_protocol::cpu_sleep::COMPLETION_LEN];
        posix_protocol::cpu_sleep::encode_completion(
            if CASE.get() == 14 { Err(-3) } else { Ok(()) },
            &mut packet,
        )
        .unwrap();
        if CASE.get() == 7 {
            packet[0] = 9;
        }
        let (offset, count) = if CASE.get() == 8 {
            (0, 3)
        } else if CASE.get() == 0 && read == 0 {
            (0, 3)
        } else if CASE.get() == 0 {
            (3, 5)
        } else {
            (0, packet.len())
        };
        assert!(count <= length as usize);
        unsafe {
            std::ptr::copy_nonoverlapping(packet[offset..].as_ptr(), destination as *mut u8, count);
        }
        Ok(count as u64)
    }
}
fn syscall_errno(result: Result<u64, i32>) -> Result<u64, i32> {
    result
}
fn wait_for_multiplex(
    items: &mut [syscall::HandleWaitItem],
    deadline: u64,
    control: &ThreadControl,
    caught: u64,
) -> Result<(), i32> {
    assert_eq!(deadline, syscall::HANDLE_WAIT_INFINITE);
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].handle, 77);
    mochios_posix_client::multiplex::wait_cancellable(
        caught,
        || control.caught_signal_generation.load(Ordering::Acquire),
        || io_cancellation_requested(control),
        || 0,
        |_| {
            WAITS.set(WAITS.get() + 1);
            match CASE.get() {
                1 | 11 | 12 => {
                    control
                        .caught_signal_generation
                        .fetch_add(1, Ordering::AcqRel);
                }
                2 | 3 => CANCEL.set(true),
                13 => PID.set(8),
                _ => panic!("unexpected native wait"),
            }
            Ok(true)
        },
        || -> Result<bool, i32> { panic!("CPU sleep must not poll wall time") },
    )
    .map_err(|error| match error {
        mochios_posix_client::multiplex::WaitError::Io(error) => error,
        _ => EINTR,
    })
}
#[path = "../../../user/crates/newlib-runtime/src/cpu_sleep.rs"]
mod actual;

#[test]
fn production_cpu_sleep_preserves_completion_interruption_and_private_resource_lifetimes() {
    for case in 0..=15 {
        CASE.set(case);
        PID.set(7);
        READS.set(0);
        WAITS.set(0);
        CLOSED.set(0);
        CANCEL.set(false);
        CONTROL.with(|control| control.caught_signal_generation.store(0, Ordering::Release));
        REQUESTS.with(|requests| requests.borrow_mut().clear());
        SAMPLES.with(|samples| samples.borrow_mut().clear());
        let mut remaining = Timespec {
            tv_sec: 99,
            tv_nsec: 99,
        };
        let output = if case == 11 {
            1usize as *mut Timespec
        } else {
            &mut remaining
        };
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            actual::sleep(
                0,
                if case == 10 {
                    1
                } else if case == 12 {
                    4
                } else {
                    0
                },
                Timespec {
                    tv_sec: if case == 15 { i64::MAX } else { 1 },
                    tv_nsec: 999_999_999,
                },
                output,
            )
        }));
        if case == 2 || case == 6 {
            assert!(result.is_err());
        } else {
            let expected = match case {
                1 | 13 => Err(EINTR),
                4 | 5 | 7 | 8 => Err(EIO),
                9 | 10 | 14 => Err(EINVAL),
                11 => Err(EFAULT),
                12 => Err(EINTR),
                _ => Ok(()),
            };
            assert_eq!(result.unwrap(), expected, "case {case}");
        }
        assert!(!SCOPED.get());
        assert_eq!(
            CLOSED.get(),
            usize::from(case != 9 && case != 10),
            "case {case}"
        );
        if matches!(case, 1 | 13) {
            assert_eq!((remaining.tv_sec, remaining.tv_nsec), (0, 200_000_000));
        } else {
            assert_eq!((remaining.tv_sec, remaining.tv_nsec), (99, 99));
        }
        if case == 12 {
            SAMPLES.with(|samples| assert!(samples.borrow().is_empty()));
        }
        if case == 15 {
            REQUESTS.with(|requests| {
                assert_eq!(
                    requests.borrow()[0].nanoseconds,
                    i64::MAX as u128 * 1_000_000_000 + 999_999_999
                )
            });
        }
        if case == 3 {
            assert!(CANCEL.get());
        }
    }
}

#[test]
fn cpu_sleep_routes_only_process_clocks_without_narrowing_clock_ids() {
    assert_eq!(actual::target(2), Some(0));
    for pid in [1, i32::MAX as u64] {
        assert_eq!(
            actual::target(mochios_posix_client::process_clock::clock_id(pid).unwrap()),
            Some(pid)
        );
    }
    for id in [0, 1, 3, 4, 1 << 31, 1 << 32, u64::MAX] {
        assert_eq!(actual::target(id), None);
    }
}
