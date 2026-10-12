use std::io::Write;
use std::process::{Command, Stdio};

#[test]
fn actual_runtime_timed_mutex_obeys_clock_timeout_and_fast_path_semantics() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../user/crates")
        .canonicalize()
        .unwrap();
    let state = root.join("posix-client/src/pthread_mutex.rs");
    let runtime = root.join("newlib-runtime/src/pthread_mutex.rs");
    let time = root.join("newlib-runtime/src/pthread_time.rs");
    let mut program = format!(
        "extern crate self as mochios_posix_client;\n#[path = {state:?}] pub mod pthread_mutex;\n"
    );
    program.push_str(r#"
use std::sync::atomic::{AtomicI64, AtomicU64, AtomicUsize, Ordering};
type c_int = i32;
const EINVAL: i32 = 22;
const EBUSY: i32 = 16;
const EDEADLK: i32 = 45;
const EPERM: i32 = 1;
const EAGAIN: i32 = 11;
const EINTR: i32 = 4;
const EIO: i32 = 5;
const EOVERFLOW: i32 = 75;
const ETIMEDOUT: i32 = 116;
#[repr(C)] struct Timespec { tv_sec: i64, tv_nsec: i64 }
#[derive(Debug)] pub struct SysError(i64);
impl SysError { pub fn raw(&self) -> i64 { self.0 } }
fn native_thread_id() -> Result<u64, SysError> { Ok(2) }
fn map_kernel_errno(raw: i64) -> i32 { (-raw) as i32 }
fn syscall_errno(raw: u64) -> Result<u64, i32> {
    if (raw as i64) < 0 { Err(-(raw as i64) as i32) } else { Ok(raw) }
}
static MONO: AtomicU64 = AtomicU64::new(100);
static REAL: AtomicU64 = AtomicU64::new(1000);
static CLOCK_ERROR: AtomicI64 = AtomicI64::new(0);
static CLOCK_CALLS: AtomicUsize = AtomicUsize::new(0);
static WAITS: AtomicUsize = AtomicUsize::new(0);
static MODE: AtomicUsize = AtomicUsize::new(0);
static ACTIVE: AtomicUsize = AtomicUsize::new(0);
fn monotonic_nanoseconds() -> Result<u64, c_int> {
    CLOCK_CALLS.fetch_add(1, Ordering::Relaxed);
    Ok(MONO.load(Ordering::Acquire))
}
mod mnu_abi {
    #[derive(Default)] #[repr(C)] pub struct ClockInstant { pub seconds: u64, pub nanoseconds: u32, pub reserved: u32 }
    #[repr(u64)] pub enum ClockId { Realtime = 1 }
}
mod syscall {
    pub const ADDRESS_WAIT_INFINITE: u64 = u64::MAX;
    pub enum SyscallNumber { ClockRead }
    pub fn raw_syscall2(_: SyscallNumber, clock: u64, pointer: u64) -> u64 {
        assert_eq!(clock, 1);
        let error = super::CLOCK_ERROR.load(super::Ordering::Acquire);
        if error != 0 { return error as u64; }
        let real = super::REAL.load(super::Ordering::Acquire);
        unsafe { (pointer as *mut super::mnu_abi::ClockInstant).write(super::mnu_abi::ClockInstant {
            seconds: real / 1_000_000_000, nanoseconds: (real % 1_000_000_000) as u32, reserved: 0,
        }); }
        0
    }
}
pub mod synchronization {
    use super::*;
    use std::sync::atomic::AtomicU32;
    pub enum WaitStatus { Awoken, ValueChanged, DeadlineReached }
    pub fn wait_u32(_: &AtomicU32, expected: u32, deadline: u64) -> Result<WaitStatus, SysError> {
        assert_eq!(expected, 2);
        assert_ne!(deadline, u64::MAX);
        let call = WAITS.fetch_add(1, Ordering::Relaxed);
        match MODE.load(Ordering::Acquire) {
            1 => {
                MONO.store(deadline, Ordering::Release);
                REAL.store(1200, Ordering::Release);
                Ok(WaitStatus::DeadlineReached)
            }
            2 if call == 0 => Err(SysError(-4)),
            2 if call == 1 => Ok(WaitStatus::ValueChanged),
            2 => {
                let lock = unsafe { &*(ACTIVE.load(Ordering::Acquire) as *const pthread_mutex::Mutex) };
                lock.unlock(1, |_| {}).unwrap();
                Ok(WaitStatus::Awoken)
            }
            3 => Err(SysError(-5)),
            4 if call == 0 => {
                assert_eq!(deadline, 300);
                MONO.store(deadline, Ordering::Release);
                REAL.store(1100, Ordering::Release); // Clock moved back before the old deadline.
                Ok(WaitStatus::DeadlineReached)
            }
            4 => {
                assert_eq!(deadline, 400); // Recomputed, not mistaken for a timeout.
                MONO.store(deadline, Ordering::Release);
                REAL.store(1200, Ordering::Release);
                Ok(WaitStatus::DeadlineReached)
            }
            _ => panic!("unexpected wait"),
        }
    }
    pub fn wake_u32(_: &AtomicU32, count: usize) -> Result<usize, SysError> {
        assert_eq!(count, 1);
        Ok(0)
    }
}
mod runtime {
    use super::*;
"#);
    program.push_str(&format!(
        "#[path = {time:?}] mod pthread_time;\n#[path = {runtime:?}] pub mod mutex;\n"
    ));
    program.push_str(r#"
}
use runtime::mutex::{pthread_mutex_clocklock as clocklock, pthread_mutex_timedlock as timedlock};
fn reset(mode: usize) {
    MONO.store(100, Ordering::Release); REAL.store(1000, Ordering::Release);
    CLOCK_ERROR.store(0, Ordering::Release); CLOCK_CALLS.store(0, Ordering::Release);
    MODE.store(mode, Ordering::Release); WAITS.store(0, Ordering::Release);
}
fn main() {
    const _: unsafe extern "C" fn(*mut pthread_mutex::Mutex, u64, *const Timespec) -> i32 = clocklock;
    let mut lock = pthread_mutex::Mutex::new(pthread_mutex::NORMAL);
    let invalid = Timespec { tv_sec: -1, tv_nsec: 1_000_000_000 };
    reset(0);
    assert_eq!(unsafe { timedlock(&mut lock, &invalid) }, 0);
    assert_eq!(CLOCK_CALLS.load(Ordering::Relaxed), 0); // No clock access/capability on immediate acquisition.
    lock.unlock(2, |_| {}).unwrap();
    for clock in [0, 2, 3, 99, u64::MAX, (1 << 32) | 4, (1 << 32) | 1] {
        assert_eq!(unsafe { clocklock(&mut lock, clock, std::ptr::null()) }, EINVAL);
    }
    lock.try_lock(1).unwrap();
    assert_eq!(unsafe { clocklock(&mut lock, 4, &invalid) }, EINVAL);
    assert_eq!(unsafe { timedlock(&mut lock, std::ptr::null()) }, EINVAL);
    let past = Timespec { tv_sec: -1, tv_nsec: 0 };
    assert_eq!(unsafe { clocklock(&mut lock, 4, &past) }, ETIMEDOUT);
    let huge = Timespec { tv_sec: i64::MAX, tv_nsec: 0 };
    assert_eq!(unsafe { clocklock(&mut lock, 4, &huge) }, EOVERFLOW);
    let sentinel = Timespec { tv_sec: 18_446_744_073, tv_nsec: 709_551_615 };
    assert_eq!(unsafe { clocklock(&mut lock, 4, &sentinel) }, EOVERFLOW);
    let future = Timespec { tv_sec: 0, tv_nsec: 1200 };
    CLOCK_ERROR.store(-13, Ordering::Release);
    assert_eq!(unsafe { timedlock(&mut lock, &future) }, 13);
    for clock in [1, 4] {
        reset(1);
        assert_eq!(unsafe { clocklock(&mut lock, clock, &future) }, ETIMEDOUT);
        assert_eq!(WAITS.load(Ordering::Relaxed), 1);
        lock.check_owner(1).unwrap(); // Timeout did not acquire or abandon the mutex.
    }
    reset(4);
    assert_eq!(unsafe { timedlock(&mut lock, &future) }, ETIMEDOUT);
    assert_eq!(WAITS.load(Ordering::Relaxed), 2);
    reset(3);
    assert_eq!(unsafe { clocklock(&mut lock, 4, &future) }, EIO);
    lock.check_owner(1).unwrap();
    reset(2);
    ACTIVE.store(&lock as *const _ as usize, Ordering::Release);
    assert_eq!(unsafe { clocklock(&mut lock, 4, &future) }, 0);
    assert_eq!(WAITS.load(Ordering::Relaxed), 3); // EINTR and spurious wake did not escape.
    lock.check_owner(2).unwrap(); lock.unlock(2, |_| {}).unwrap(); lock.destroy().unwrap();
    let mut recursive = pthread_mutex::Mutex::new(pthread_mutex::RECURSIVE);
    recursive.try_lock(2).unwrap(); reset(0);
    assert_eq!(unsafe { timedlock(&mut recursive, &invalid) }, 0);
    assert_eq!(CLOCK_CALLS.load(Ordering::Relaxed), 0);
    recursive.unlock(2, |_| {}).unwrap(); recursive.unlock(2, |_| {}).unwrap();
    let mut checking = pthread_mutex::Mutex::new(pthread_mutex::ERRORCHECK);
    checking.try_lock(2).unwrap();
    assert_eq!(unsafe { timedlock(&mut checking, std::ptr::null()) }, EDEADLK);
}
"#);
    let directory = std::env::temp_dir().join(format!(
        "mochios-timed-mutex-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&directory).unwrap();
    let executable = directory.join("probe");
    let mut compiler = Command::new("rustc")
        .args(["--edition=2024", "-Awarnings", "-"])
        .arg("-o")
        .arg(&executable)
        .stdin(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    compiler
        .stdin
        .take()
        .unwrap()
        .write_all(program.as_bytes())
        .unwrap();
    let output = compiler.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let output = Command::new(executable).output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    std::fs::remove_dir_all(directory).unwrap();
}
