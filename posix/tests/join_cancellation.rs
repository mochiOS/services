use std::io::Write;
use std::process::{Command, Stdio};

#[test]
fn production_join_cancellation_releases_the_claim_before_cleanup_and_preserves_output() {
    let runtime = include_str!("../../../user/crates/newlib-runtime/src/lib.rs");
    let mut program = String::from(
        r#"
use std::ffi::c_void;
use std::sync::atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering};
type c_int = i32;
const ESRCH: i32 = 3;
const EAGAIN: i32 = 11;
const EINVAL: i32 = 22;
const EDEADLK: i32 = 35;
const THREAD_RUNNING: u32 = 2;
const THREAD_STARTING: u32 = 1;
const THREAD_EXITED: u32 = 3;
const THREAD_REAPING: u32 = 4;
const THREAD_JOINABLE: u32 = 0;
const THREAD_JOIN_CLAIMED: u32 = 2;
const PTHREAD_CANCEL_ENABLE: u32 = 0;
struct ThreadControl {
    state: AtomicU32, joinability: AtomicU32, join_waiter: AtomicU32, result: AtomicUsize,
    cancel_state: AtomicU32, cancel_pending: AtomicU32, wait_generation: AtomicU32,
    multiplex_generation: AtomicU64,
}
impl ThreadControl {
    const fn new() -> Self { Self {
        state: AtomicU32::new(THREAD_RUNNING), joinability: AtomicU32::new(THREAD_JOINABLE),
        join_waiter: AtomicU32::new(0), result: AtomicUsize::new(55), cancel_state: AtomicU32::new(0),
        cancel_pending: AtomicU32::new(0), wait_generation: AtomicU32::new(0),
        multiplex_generation: AtomicU64::new(0),
    } }
}
static CALLER: ThreadControl = ThreadControl::new();
static TARGET: ThreadControl = ThreadControl::new();
static CASE: AtomicU32 = AtomicU32::new(0);
static WAITS: AtomicU32 = AtomicU32::new(0);
static RELEASED: AtomicU32 = AtomicU32::new(0);
static mut OUTPUT: *mut c_void = 99usize as *mut c_void;
fn thread_control(token: Pthread) -> Option<&'static ThreadControl> {
    match token { 1 => Some(&CALLER), 2 => Some(&TARGET), _ => None }
}
fn register_current_thread() -> Option<(Pthread, &'static ThreadControl)> {
    if CASE.load(Ordering::Acquire) == 8 { TARGET.state.store(THREAD_EXITED, Ordering::Release); notify_join_waiter(&TARGET); }
    Some((1, &CALLER))
}
fn current_thread_control() -> Option<(Pthread, &'static ThreadControl)> { Some((1, &CALLER)) }
fn native_mutex_wake_all(_: &AtomicU32) {}
fn native_counter_wake_all(_: &AtomicU64) {}
fn release_thread_control(target: &ThreadControl) {
    assert_eq!(target.state.load(Ordering::Acquire), THREAD_REAPING);
    RELEASED.fetch_add(1, Ordering::AcqRel);
}
fn native_thread_retired(_: &ThreadControl) -> Result<bool, i32> {
    match CASE.load(Ordering::Acquire) { 6 => Ok(false), 7 => Err(5), _ => Ok(true) }
}
fn map_kernel_errno(raw: u64) -> i32 { -(raw as i64) as i32 }
fn finish_thread(_: &ThreadControl, result: *mut c_void) -> ! {
    assert_eq!(result as usize, usize::MAX);
    assert_eq!(TARGET.join_waiter.load(Ordering::Acquire), 0);
    assert_eq!(TARGET.joinability.load(Ordering::Acquire), THREAD_JOINABLE);
    assert_eq!(RELEASED.load(Ordering::Acquire), 0);
    assert_eq!(unsafe { OUTPUT } as usize, 99);
    // Model application cleanup attempting to claim the same target again.
    assert!(TARGET.joinability.compare_exchange(THREAD_JOINABLE, THREAD_JOIN_CLAIMED, Ordering::AcqRel, Ordering::Relaxed).is_ok());
    std::process::exit(73)
}
mod syscall {
    use super::*;
    pub const ADDRESS_WAIT_INFINITE: u64 = u64::MAX;
    pub enum SyscallNumber { ThreadYield }
    pub fn raw_syscall0(_: SyscallNumber) -> u64 { assert_eq!(CASE.load(Ordering::Acquire), 6); pthread_cancel(1); 0 }
}
mod mochios_posix_client { pub mod synchronization {
    use super::super::*;
    pub struct Error;
    impl Error { pub fn raw(&self) -> u64 { (-5i64) as u64 } }
    pub fn wait_u32(address: &AtomicU32, expected: u32, deadline: u64) -> Result<(), Error> {
        assert!(std::ptr::eq(address, &CALLER.wait_generation));
        assert_eq!(deadline, syscall::ADDRESS_WAIT_INFINITE);
        let count = WAITS.fetch_add(1, Ordering::AcqRel);
        assert!(count < 3, "join spun without completing");
        match CASE.load(Ordering::Acquire) {
            1 | 5 => { pthread_cancel(1); assert_ne!(address.load(Ordering::Acquire), expected); },
            3 if count == 0 => { pthread_cancel(1); },
            4 => return Err(Error),
            _ => { TARGET.state.store(THREAD_EXITED, Ordering::Release); notify_join_waiter(&TARGET); assert_ne!(address.load(Ordering::Acquire), expected); }
        }
        Ok(())
    }
} }
"#,
    );
    program.push_str(
        runtime
            .lines()
            .find(|line| line.starts_with("type Pthread ="))
            .unwrap(),
    );
    program.push('\n');
    for entry in [
        "pub unsafe extern \"C\" fn pthread_join(",
        "pub extern \"C\" fn pthread_cancel(",
        "pub extern \"C\" fn pthread_testcancel(",
        "fn notify_thread_waiter(",
        "fn release_join_claim(",
        "fn join_cancel_point(",
        "fn notify_join_waiter(",
    ] {
        let start = runtime.find(entry).unwrap();
        let end = start + runtime[start..].find("\n}\n").unwrap() + 3;
        program.push_str(&runtime[start..end]);
    }
    program.push_str(
        r#"
fn main() {
    let case: u32 = std::env::args().nth(1).unwrap().parse().unwrap();
    CASE.store(case, Ordering::Release);
    if case == 0 { pthread_cancel(1); }
    if case == 3 { CALLER.cancel_state.store(1, Ordering::Release); }
    if case == 6 || case == 7 { TARGET.state.store(THREAD_EXITED, Ordering::Release); }
    let result = unsafe { pthread_join(2, &raw mut OUTPUT) };
    assert!(!matches!(case, 0 | 1 | 5 | 6), "cancellation returned");
    if case == 4 || case == 7 {
        assert_eq!(result, 5);
        assert_eq!(unsafe { OUTPUT } as usize, 99);
        assert_eq!(TARGET.joinability.load(Ordering::Acquire), THREAD_JOINABLE);
        assert_eq!(TARGET.join_waiter.load(Ordering::Acquire), 0);
        assert_eq!(RELEASED.load(Ordering::Acquire), 0);
    } else {
        assert_eq!(result, 0);
        assert_eq!(unsafe { OUTPUT } as usize, 55);
        assert_eq!(RELEASED.load(Ordering::Acquire), 1);
        if case == 3 { assert_eq!(WAITS.load(Ordering::Acquire), 2); assert_eq!(CALLER.cancel_pending.load(Ordering::Acquire), 1); }
    }
}
"#,
    );
    let directory = std::env::temp_dir().join(format!(
        "mochios-join-cancel-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&directory).unwrap();
    let executable = directory.join("probe");
    let mut compiler = Command::new("rustc")
        .args(["--edition=2021", "-Awarnings", "-"])
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
    for case in 0..9 {
        let executed = Command::new(&executable)
            .arg(case.to_string())
            .output()
            .unwrap();
        let expected = if matches!(case, 0 | 1 | 5 | 6) { 73 } else { 0 };
        assert_eq!(
            executed.status.code(),
            Some(expected),
            "case {case}: {}",
            String::from_utf8_lossy(&executed.stderr)
        );
    }
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn exit_publishes_completion_before_notifying_joiner_and_recycled_slots_clear_waiter() {
    let source = include_str!("../../../user/crates/newlib-runtime/src/lib.rs");
    let exit = source
        .split("fn finish_thread(")
        .nth(1)
        .unwrap()
        .split("fn native_thread_retired(")
        .next()
        .unwrap();
    assert!(
        exit.find("state.store(THREAD_EXITED").unwrap()
            < exit.find("notify_join_waiter(control)").unwrap()
    );
    assert_eq!(
        source
            .matches("join_waiter.store(0, Ordering::Relaxed)")
            .count(),
        2
    );
}
