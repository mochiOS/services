//! Actual pthread-clock implementation with controlled native observations.
//! Thread Handle pinning itself is exercised in thread_reference.rs.
#![allow(dead_code)]
use mochios_posix_client::thread_clock::Registry;
use mochios_posix_protocol as posix_protocol;
use std::{
    ffi::c_int,
    sync::{
        Mutex, MutexGuard,
        atomic::{AtomicBool, AtomicI32, AtomicU32, AtomicU64, AtomicUsize, Ordering},
    },
};
type Pthread = u32;
const EINVAL: c_int = 22;
const ESRCH: c_int = 3;
const EFAULT: c_int = 14;
const EAGAIN: c_int = 11;
const EIO: c_int = 5;
const EOVERFLOW: c_int = 139;
const ENOTSUP: c_int = 134;
const THREAD_STARTING: u32 = 1;
const THREAD_RUNNING: u32 = 2;
#[repr(C)]
#[derive(Debug, PartialEq)]
struct Timespec {
    tv_sec: i64,
    tv_nsec: i64,
}
struct ThreadControl {
    state: AtomicU32,
    native_id: AtomicU64,
    generation: AtomicU32,
}
static CONTROLS: [ThreadControl; 2] = [
    ThreadControl {
        state: AtomicU32::new(2),
        native_id: AtomicU64::new(100),
        generation: AtomicU32::new(1),
    },
    ThreadControl {
        state: AtomicU32::new(2),
        native_id: AtomicU64::new(200),
        generation: AtomicU32::new(1),
    },
];
struct RuntimeState {
    thread_clocks: Registry<2>,
}
static STATE: Mutex<RuntimeState> = Mutex::new(RuntimeState {
    thread_clocks: Registry::new(),
});
static SERIAL: Mutex<()> = Mutex::new(());
static REFERENCES: AtomicUsize = AtomicUsize::new(0);
static ERRNO: AtomicI32 = AtomicI32::new(77);
static WAITED: AtomicBool = AtomicBool::new(false);
fn state() -> MutexGuard<'static, RuntimeState> {
    STATE.lock().unwrap()
}
fn thread_control(thread: Pthread) -> Option<&'static ThreadControl> {
    let token = mochios_posix_client::thread::ThreadToken::from_raw(thread)?;
    let control = CONTROLS.get(token.slot())?;
    (control.generation.load(Ordering::Acquire) == token.generation()
        && control.state.load(Ordering::Acquire) != 0)
        .then_some(control)
}
fn current_thread_control() -> Option<(Pthread, &'static ThreadControl)> {
    Some((64, &CONTROLS[0]))
}
fn register_current_thread() -> Option<(Pthread, &'static ThreadControl)> {
    current_thread_control()
}
fn native_mutex_wait(word: &AtomicU32, expected: u32) {
    assert_eq!(expected, 1);
    word.store(2, Ordering::Release);
    WAITED.store(true, Ordering::Release);
}
fn map_kernel_errno(raw: i64) -> c_int {
    mochios_posix_client::newlib_errno::from_status(raw)
}
fn syscall_errno(raw: mochi_user_syscall::RawSyscallResult) -> Result<u64, c_int> {
    raw.into_result()
        .map_err(|error| map_kernel_errno(error.raw()))
}
mod thread_reference {
    use super::*;
    pub struct Reference(u32);
    impl Reference {
        pub fn handle(&self) -> u32 {
            self.0
        }
    }
    impl Drop for Reference {
        fn drop(&mut self) {
            REFERENCES.fetch_sub(1, Ordering::AcqRel);
        }
    }
    pub fn snapshot(thread: Pthread, rights: u64) -> Result<Reference, c_int> {
        assert!(
            rights == mnu_abi::HANDLE_RIGHT_WAIT
                || rights == mnu_abi::HANDLE_RIGHT_WAIT | mnu_abi::HANDLE_RIGHT_TRANSFER
        );
        let control = thread_control(thread).ok_or(ESRCH)?;
        if control.state.load(Ordering::Acquire) != 2 {
            return Err(ESRCH);
        }
        REFERENCES.fetch_add(1, Ordering::AcqRel);
        Ok(Reference(17 + (thread & 63)))
    }
}
struct Native {
    status: Option<mnu_abi::ThreadStatus>,
    status_error: Option<mnu_abi::status::Error>,
    clock_error: Option<mnu_abi::status::Error>,
    seconds: u64,
    nanos: u32,
    quantum: u64,
    reads: Vec<u32>,
}
static NATIVE: Mutex<Native> = Mutex::new(Native {
    status: None,
    status_error: None,
    clock_error: None,
    seconds: 7,
    nanos: 13,
    quantum: 1_000_000,
    reads: Vec::new(),
});
mod syscall {
    pub use mnu_abi::{HANDLE_RIGHT_TRANSFER, HANDLE_RIGHT_WAIT, SyscallNumber, ThreadStatus};
    pub fn raw_syscall2(
        number: SyscallNumber,
        handle: u64,
        output: u64,
    ) -> mochi_user_syscall::RawSyscallResult {
        assert_eq!(number, SyscallNumber::ThreadHandleStatus);
        assert!(crate::REFERENCES.load(crate::Ordering::Acquire) > 0);
        let native = crate::NATIVE.lock().unwrap();
        if let Some(error) = native.status_error {
            return mochi_user_syscall::RawSyscallResult::new(error.into_raw());
        }
        let status = native.status.unwrap_or(ThreadStatus {
            thread_id: if handle == 17 { 100 } else { 200 },
            process_id: 1,
            state: 2,
            reserved: 0,
        });
        unsafe { (output as *mut ThreadStatus).write(status) };
        mochi_user_syscall::RawSyscallResult::new(0)
    }
    pub fn raw_syscall3(
        number: SyscallNumber,
        clock: u64,
        output: u64,
        length: u64,
    ) -> mochi_user_syscall::RawSyscallResult {
        assert_eq!(number, SyscallNumber::ClockDescribe);
        assert_eq!(clock, mnu_abi::ClockId::ThreadCpu as u64);
        assert_eq!(length, 8);
        assert!(crate::REFERENCES.load(crate::Ordering::Acquire) > 0);
        unsafe {
            (output as *mut mnu_abi::ClockInfo).write(mnu_abi::ClockInfo {
                quantum_nanoseconds: crate::NATIVE.lock().unwrap().quantum,
            })
        };
        mochi_user_syscall::RawSyscallResult::new(0)
    }
    pub mod execution {
        pub fn thread_clock(
            handle: u32,
        ) -> Result<mnu_abi::ClockInstant, mochi_user_syscall::SysError> {
            assert!(crate::REFERENCES.load(crate::Ordering::Acquire) > 0);
            let mut native = crate::NATIVE.lock().unwrap();
            native.reads.push(handle);
            if let Some(error) = native.clock_error {
                return Err(mochi_user_syscall::SysError::from_raw(
                    error.into_raw() as i64
                ));
            }
            Ok(mnu_abi::ClockInstant {
                seconds: native.seconds,
                nanoseconds: native.nanos,
                reserved: 0,
            })
        }
    }
}
mod user_copy {
    pub fn write(output: *mut u8, bytes: &[u8]) -> Result<(), i32> {
        assert_eq!(crate::REFERENCES.load(crate::Ordering::Acquire), 0);
        assert!(crate::STATE.try_lock().is_ok());
        if (output as usize) < 4096 {
            return Err(crate::EFAULT);
        }
        unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), output, bytes.len()) };
        Ok(())
    }
}
mod time_memory {
    pub fn write_timespec(output: *mut crate::Timespec, value: crate::Timespec) -> Result<(), i32> {
        assert_eq!(crate::REFERENCES.load(crate::Ordering::Acquire), 0);
        assert!(crate::STATE.try_lock().is_ok());
        if (output as usize) < 4096 {
            return Err(crate::EFAULT);
        }
        unsafe { output.write_unaligned(value) };
        Ok(())
    }
}
#[path = "../../../user/crates/newlib-runtime/src/thread_clock.rs"]
mod actual;

fn reset() -> MutexGuard<'static, ()> {
    let serial = SERIAL.lock().unwrap();
    assert_eq!(REFERENCES.load(Ordering::Acquire), 0);
    state().thread_clocks = Registry::new();
    for (index, control) in CONTROLS.iter().enumerate() {
        control.state.store(2, Ordering::Release);
        control.generation.store(1, Ordering::Release);
        control
            .native_id
            .store(100 + index as u64 * 100, Ordering::Release);
    }
    *NATIVE.lock().unwrap() = Native {
        status: None,
        status_error: None,
        clock_error: None,
        seconds: 7,
        nanos: 13,
        quantum: 1_000_000,
        reads: Vec::new(),
    };
    WAITED.store(false, Ordering::Relaxed);
    ERRNO.store(77, Ordering::Relaxed);
    serial
}
fn create(thread: Pthread) -> u64 {
    let mut id = 0;
    assert_eq!(actual::pthread_getcpuclockid(thread, &mut id), 0);
    id
}

#[test]
fn actual_pthread_clock_creation_and_reads_use_the_bound_target_and_checked_outputs() {
    let _serial = reset();
    let id = create(65);
    assert_eq!(create(65), id);
    assert!(id >= 1 << 32);
    let mut value = Timespec {
        tv_sec: 99,
        tv_nsec: 98,
    };
    assert_eq!(actual::read(id, &mut value), Ok(0));
    assert_eq!(
        value,
        Timespec {
            tv_sec: 7,
            tv_nsec: 13
        }
    );
    assert_eq!(actual::resolution(id, &mut value), Ok(0));
    assert_eq!(
        value,
        Timespec {
            tv_sec: 0,
            tv_nsec: 1_000_000
        }
    );
    assert_eq!(actual::resolution(id, std::ptr::null_mut()), Ok(0));
    assert!(
        NATIVE
            .lock()
            .unwrap()
            .reads
            .iter()
            .all(|&handle| handle == 18)
    );
    assert_eq!(actual::read(id, 1usize as *mut _), Err(EFAULT));
    assert_eq!(actual::pthread_getcpuclockid(65, 1usize as *mut _), EFAULT);
    assert_eq!(
        actual::pthread_getcpuclockid(65, std::ptr::null_mut()),
        EFAULT
    );
    assert_eq!(ERRNO.load(Ordering::Acquire), 77);
    assert_eq!(REFERENCES.load(Ordering::Acquire), 0);
    CONTROLS[1].state.store(1, Ordering::Release);
    assert_eq!(create(65), id);
    assert!(WAITED.load(Ordering::Acquire));
    assert_eq!(
        actual::timer_source(id),
        Ok(posix_protocol::process_timer::Clock::ThreadCpu)
    );
    let (reference, native) = actual::timer_target(id).unwrap();
    assert_eq!(reference.handle(), 18);
    assert_eq!(native, 200);
    assert_eq!(REFERENCES.load(Ordering::Acquire), 1);
    drop(reference);
    assert_eq!(REFERENCES.load(Ordering::Acquire), 0);
    let own = create(64);
    assert_eq!(
        actual::timer_source(own),
        Ok(posix_protocol::process_timer::Clock::ThreadCpu)
    );
}

#[test]
fn old_clock_cannot_alias_a_reused_thread_or_survive_child_registry_reset() {
    let _serial = reset();
    let old = create(65);
    CONTROLS[1].state.store(3, Ordering::Release);
    let mut value = Timespec {
        tv_sec: 99,
        tv_nsec: 98,
    };
    assert_eq!(actual::read(old, &mut value), Err(EINVAL));
    CONTROLS[1].generation.store(2, Ordering::Release);
    CONTROLS[1].native_id.store(300, Ordering::Release);
    CONTROLS[1].state.store(2, Ordering::Release);
    assert_eq!(actual::pthread_getcpuclockid(65, &mut 0), ESRCH);
    NATIVE.lock().unwrap().status = Some(mnu_abi::ThreadStatus {
        thread_id: 300,
        process_id: 1,
        state: 2,
        reserved: 0,
    });
    let new = create(129);
    assert!(new > old);
    assert_eq!(actual::read(old, &mut value), Err(EINVAL));
    assert_eq!(actual::read(new, &mut value), Ok(0));
    // Even a buggy reused pthread generation cannot redirect an old clock.
    CONTROLS[1].native_id.store(400, Ordering::Release);
    assert_eq!(actual::read(new, &mut value), Err(EINVAL));
    state().thread_clocks.clear_for_fork();
    assert_eq!(actual::resolution(new, std::ptr::null_mut()), Err(EINVAL));
    NATIVE.lock().unwrap().status = None;
    let child = create(64);
    assert!(child > new);
    let source = include_str!("../../../user/crates/newlib-runtime/src/lib.rs");
    assert!(
        source
            .find("state().thread_clocks.clear_for_fork()")
            .unwrap()
            < source
                .find("setup_signal_delivery(thread_control, None)")
                .unwrap()
    );
}

#[test]
fn native_failures_and_stale_target_metadata_never_fabricate_a_timestamp() {
    let _serial = reset();
    let id = create(65);
    let mut value = Timespec {
        tv_sec: 99,
        tv_nsec: 98,
    };
    NATIVE.lock().unwrap().status = Some(mnu_abi::ThreadStatus {
        thread_id: 999,
        process_id: 1,
        state: 2,
        reserved: 0,
    });
    assert_eq!(actual::read(id, &mut value), Err(EINVAL));
    NATIVE.lock().unwrap().status = Some(mnu_abi::ThreadStatus {
        thread_id: 200,
        process_id: 1,
        state: 2,
        reserved: 1,
    });
    assert_eq!(actual::read(id, &mut value), Err(EIO));
    NATIVE.lock().unwrap().status = None;
    NATIVE.lock().unwrap().status_error = Some(mnu_abi::status::Error::NotFound);
    assert_eq!(actual::read(id, &mut value), Err(EINVAL));
    assert_eq!(actual::pthread_getcpuclockid(65, &mut 0), ESRCH);
    NATIVE.lock().unwrap().status_error = None;
    NATIVE.lock().unwrap().clock_error = Some(mnu_abi::status::Error::AccessDenied);
    assert_eq!(actual::read(id, &mut value), Err(13));
    assert_eq!(actual::pthread_getcpuclockid(65, &mut 0), 13);
    NATIVE.lock().unwrap().clock_error = None;
    NATIVE.lock().unwrap().seconds = u64::MAX;
    assert_eq!(actual::read(id, &mut value), Err(EOVERFLOW));
    assert_eq!(
        value,
        Timespec {
            tv_sec: 99,
            tv_nsec: 98
        }
    );
    NATIVE.lock().unwrap().quantum = 0;
    assert_eq!(actual::resolution(id, std::ptr::null_mut()), Err(EIO));
    assert_eq!(REFERENCES.load(Ordering::Acquire), 0);
    assert_eq!(ERRNO.load(Ordering::Acquire), 77);
}
