use std::io::Write;
use std::process::{Command, Stdio};

#[test]
fn actual_adapter_preserves_tokens_cancellation_errno_and_deadlines() {
    let mut program = String::from(
        r#"
use std::ffi::{c_int, c_void};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
const EINVAL: i32 = 22; const EOVERFLOW: i32 = 139;
const EAGAIN: i32 = 11; const EINTR: i32 = 4;
const PTHREAD_CANCEL_ENABLE: u32 = 0; const PTHREAD_CANCEL_DISABLE: u32 = 1;
#[repr(C)] struct Timespec { tv_sec: i64, tv_nsec: i64 }
struct Control { cancel_state: AtomicU32, cancel_pending: AtomicU32,
    multiplex_generation: AtomicU64, nonrestart_signal_generation: AtomicU64 }
static CONTROL: Control = Control { cancel_state: AtomicU32::new(0), cancel_pending: AtomicU32::new(0),
    multiplex_generation: AtomicU64::new(0), nonrestart_signal_generation: AtomicU64::new(0) };
static ERRNO: AtomicU32 = AtomicU32::new(123);
static ACTION: AtomicU32 = AtomicU32::new(0);
static WAKES: AtomicU32 = AtomicU32::new(0);
static TIME_ERROR: AtomicU32 = AtomicU32::new(0);
static OBJECT: AtomicU64 = AtomicU64::new(0);
fn set_errno(error: i32) { ERRNO.store(error as u32, Ordering::SeqCst); }
fn map_kernel_errno(raw: i64) -> i32 { -raw as i32 }
fn register_current_thread() -> Option<(usize, &'static Control)> { Some((1, &CONTROL)) }
fn pthread_testcancel() {
    if CONTROL.cancel_state.load(Ordering::Acquire) == 0 && CONTROL.cancel_pending.load(Ordering::Acquire) != 0 {
        finish_thread(&CONTROL, usize::MAX as *mut c_void);
    }
}
fn finish_thread(control: &Control, _: *mut c_void) -> ! {
    assert_eq!(control.cancel_state.load(Ordering::Acquire), 0);
    let semaphore = unsafe { &*(OBJECT.load(Ordering::Acquire) as *const mochios_posix_client::semaphore::Semaphore) };
    assert_eq!(semaphore.value().unwrap(), if ACTION.load(Ordering::Acquire) == 6 { 1 } else { 0 });
    std::process::exit(0);
}
fn monotonic_nanoseconds() -> Result<u64, i32> { Ok(10) }
mod pthread_time {
    pub fn deadline(clock: i32, value: u64) -> Result<u64, i32> {
        assert!(matches!(clock, 1 | 4));
        let error = crate::TIME_ERROR.load(crate::Ordering::Acquire);
        if error != 0 { Err(error as i32) } else { Ok(value) }
    }
}
mod syscall { pub const ADDRESS_WAIT_INFINITE: u64 = u64::MAX; }
mod mochios_posix_client {
    pub mod semaphore {
"#,
    );
    program.push_str(
        &include_str!("../../../user/crates/posix-client/src/semaphore.rs")
            .lines()
            .filter(|line| !line.starts_with("//!"))
            .collect::<Vec<_>>()
            .join("\n"),
    );
    program.push_str(r#"
    }
    pub mod synchronization {
        use crate::*;
        pub enum WaitStatus { Awoken, DeadlineReached }
        pub struct Error; impl Error { pub fn raw(&self) -> i64 { -5 } }
        pub fn wake_u64(_: &AtomicU64, count: usize) -> Result<usize, Error> {
            assert_eq!(count, usize::MAX); WAKES.fetch_add(1, Ordering::Relaxed); Ok(0)
        }
        pub fn wait_u64_guarded(word: &AtomicU64, expected: u64, notification: &AtomicU64,
            generation: u64, deadline: u64) -> Result<WaitStatus, Error> {
            assert_eq!(expected, 0); assert_eq!(word.load(Ordering::Acquire), 0);
            assert_eq!(notification.load(Ordering::Acquire), generation);
            assert_eq!(CONTROL.cancel_state.load(Ordering::Acquire), 1);
            match ACTION.load(Ordering::Acquire) {
                1 => { assert_eq!(deadline, u64::MAX); word.store(1, Ordering::Release); Ok(WaitStatus::Awoken) }
                2 | 6 => {
                    if ACTION.load(Ordering::Acquire) == 6 { word.store(1, Ordering::Release); }
                    CONTROL.cancel_pending.store(1, Ordering::Release);
                    notification.fetch_add(1, Ordering::Release); Ok(WaitStatus::Awoken)
                }
                3 => { CONTROL.nonrestart_signal_generation.fetch_add(1, Ordering::Release);
                    notification.fetch_add(1, Ordering::Release); Ok(WaitStatus::Awoken) }
                4 => { assert_eq!(deadline, 100); Ok(WaitStatus::DeadlineReached) }
                5 => Err(Error), _ => panic!("unexpected wait")
            }
        }
    }
}
mod adapter {
"#);
    program.push_str(
        &include_str!("../../../user/crates/newlib-runtime/src/semaphore.rs")
            .lines()
            .filter(|line| !line.starts_with("//!"))
            .collect::<Vec<_>>()
            .join("\n"),
    );
    program.push_str(r#"
}
use adapter::*;
use mochios_posix_client::semaphore::{Semaphore, VALUE_MAX};
fn main() { unsafe {
    let mut semaphore = Semaphore::new(0, false).unwrap();
    OBJECT.store(&mut semaphore as *mut Semaphore as u64, Ordering::Release);
    if let Some(mode) = std::env::args().nth(1) {
        ACTION.store(mode.parse().unwrap(), Ordering::Release);
        sem_wait(&mut semaphore); panic!("canceled wait returned");
    }
    assert_eq!(sem_init(std::ptr::null_mut(), 0, 0), -1);
    assert_eq!(sem_init(&mut semaphore, 0, VALUE_MAX + 1), -1);
    assert_eq!(ERRNO.load(Ordering::Acquire), 22);
    ERRNO.store(123, Ordering::Release);
    assert_eq!(sem_init(&mut semaphore, -7, 0), 0); // Any nonzero pshared means shared.
    assert_eq!(ERRNO.load(Ordering::Acquire), 123);
    assert_eq!(sem_trywait(&mut semaphore), -1);
    assert_eq!(ERRNO.load(Ordering::Acquire), 11);
    assert_eq!(sem_post(&mut semaphore), 0);
    let mut value = -7;
    assert_eq!(sem_getvalue(&mut semaphore, &mut value), 0); assert_eq!(value, 1);
    assert_eq!(sem_getvalue(&mut semaphore, std::ptr::null_mut()), -1);
    ERRNO.store(123, Ordering::Release);
    assert_eq!(sem_timedwait(&mut semaphore, std::ptr::null()), 0); // Immediate claim ignores timeout.
    assert_eq!(ERRNO.load(Ordering::Acquire), 123);
    assert_eq!(sem_timedwait(&mut semaphore, std::ptr::null()), -1);
    assert_eq!(ERRNO.load(Ordering::Acquire), 22);
    let invalid = Timespec { tv_sec: 0, tv_nsec: 1_000_000_000 };
    assert_eq!(sem_timedwait(&mut semaphore, &invalid), -1);
    assert_eq!(ERRNO.load(Ordering::Acquire), 22);
    assert_eq!(sem_clockwait(&mut semaphore, (1u64 << 32) | 4, &invalid), -1);
    let past = Timespec { tv_sec: -1, tv_nsec: 0 };
    assert_eq!(sem_timedwait(&mut semaphore, &past), -1);
    assert_eq!(ERRNO.load(Ordering::Acquire), 116);
    ACTION.store(1, Ordering::Release);
    assert_eq!(sem_wait(&mut semaphore), 0);
    assert_eq!(semaphore.value(), Ok(0));
    ACTION.store(3, Ordering::Release);
    assert_eq!(sem_wait(&mut semaphore), -1);
    assert_eq!(ERRNO.load(Ordering::Acquire), 4); assert_eq!(semaphore.value(), Ok(0));
    ACTION.store(4, Ordering::Release);
    let future = Timespec { tv_sec: 0, tv_nsec: 100 };
    assert_eq!(sem_clockwait(&mut semaphore, 4, &future), -1);
    assert_eq!(ERRNO.load(Ordering::Acquire), 116);
    TIME_ERROR.store(5, Ordering::Release);
    assert_eq!(sem_timedwait(&mut semaphore, &future), -1);
    assert_eq!(ERRNO.load(Ordering::Acquire), 5);
    TIME_ERROR.store(0, Ordering::Release); ACTION.store(5, Ordering::Release);
    assert_eq!(sem_wait(&mut semaphore), -1);
    assert_eq!(ERRNO.load(Ordering::Acquire), 5);
    assert_eq!(CONTROL.cancel_state.load(Ordering::Acquire), 0);
    assert_eq!(sem_init(&mut semaphore, 0, VALUE_MAX), 0);
    let wakes = WAKES.load(Ordering::Acquire);
    assert_eq!(sem_post(&mut semaphore), -1);
    assert_eq!(ERRNO.load(Ordering::Acquire), 139);
    assert_eq!(WAKES.load(Ordering::Acquire), wakes); assert_eq!(semaphore.value(), Ok(VALUE_MAX));
    assert_eq!(sem_destroy(&mut semaphore), 0);
    assert_eq!(sem_trywait(&mut semaphore), -1);
    assert_eq!(ERRNO.load(Ordering::Acquire), 22);
} }
"#);
    let directory = std::env::temp_dir().join(format!(
        "mochios-sem-public-{}-{}",
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
    let compiled = compiler.wait_with_output().unwrap();
    assert!(
        compiled.status.success(),
        "{}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    for mode in [None, Some("2"), Some("6")] {
        let mut command = Command::new(&executable);
        if let Some(mode) = mode {
            command.arg(mode);
        }
        let output = command.output().unwrap();
        assert!(
            output.status.success(),
            "mode {mode:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    std::fs::remove_dir_all(directory).unwrap();
}
