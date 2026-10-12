use std::io::Write;
use std::process::{Command, Stdio};

#[test]
fn actual_guarded_address_wait_admission_wakeup_timeout_and_error_cleanup() {
    let source = include_str!("../../../core/src/syscall/address_wait.rs");
    let mut program = String::from(
        r#"
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
type ThreadId = u64;
const EAGAIN: u64 = (-11i64) as u64;
const EFAULT: u64 = (-14i64) as u64;
const EINVAL: u64 = (-22i64) as u64;
const MAX_WAITERS: usize = 4;
struct SpinLock<T>(std::sync::Mutex<T>);
impl<T> SpinLock<T> {
    const fn new(value: T) -> Self { Self(std::sync::Mutex::new(value)) }
    fn lock(&self) -> std::sync::MutexGuard<'_, T> { self.0.lock().unwrap() }
}
mod mnu_abi {
    pub const ADDRESS_WAIT_INFINITE: u64 = u64::MAX;
    #[derive(Clone, Copy)] pub enum AddressWaitResult { Awoken = 0, ValueChanged = 1, DeadlineReached = 2 }
}
static NOW: AtomicU64 = AtomicU64::new(0);
static ACTION: AtomicU64 = AtomicU64::new(0);
static UPCALL: AtomicU32 = AtomicU32::new(0);
static ARM_OK: AtomicU32 = AtomicU32::new(1);
static DISARMS: AtomicU32 = AtomicU32::new(0);
mod syscall { pub mod time {
    pub fn monotonic_nanoseconds() -> u64 { crate::NOW.load(std::sync::atomic::Ordering::Acquire) }
    pub fn monotonic_deadline_tick(deadline: u64) -> u64 { deadline }
    pub fn arm_thread_deadline(_: u64, _: u64) -> bool { crate::ARM_OK.load(std::sync::atomic::Ordering::Acquire) != 0 }
    pub fn disarm_thread_deadline(_: u64) { crate::DISARMS.fetch_add(1, std::sync::atomic::Ordering::Relaxed); }
} }
mod task {
    pub fn current_thread_id() -> Option<u64> { Some(7) }
    pub struct Thread;
    impl Thread { pub fn has_deliverable_upcall(&self) -> bool { crate::UPCALL.load(std::sync::atomic::Ordering::Acquire) != 0 } }
    pub fn with_thread<T>(_: u64, callback: impl FnOnce(&Thread) -> T) -> Option<T> { Some(callback(&Thread)) }
    pub static WAKES: std::sync::Mutex<Vec<u64>> = std::sync::Mutex::new(Vec::new());
    pub fn wake_registered_waiter(thread: u64) { WAKES.lock().unwrap().push(thread); }
    pub fn sleep_thread_unless_woken(_: u64) -> bool {
        let action = crate::ACTION.swap(0, std::sync::atomic::Ordering::AcqRel);
        assert_ne!(action, 0, "unexpected indefinite wait");
        if action == 1 { crate::NOW.store(5, std::sync::atomic::Ordering::Release); }
        else if action == 2 { crate::UPCALL.store(1, std::sync::atomic::Ordering::Release); }
        else { assert_eq!(crate::actual::wake(action, 1), 1); }
        true
    }
    pub fn yield_now() {}
}
fn read_user_u64(address: u64) -> Result<u64, u64> {
    if address < 4096 { return Err(EFAULT); }
    Ok(unsafe { (address as *const u64).read_unaligned() })
}
mod actual {
use super::*;
fn resolve_key(address: u64, size: u64) -> Result<AddressKey, u64> {
    if !matches!(size, 1 | 2 | 4 | 8) { return Err(EINVAL); }
    if address < 4096 { return Err(EFAULT); }
    if address & (size - 1) != 0 { return Err(EINVAL); }
    Ok(AddressKey { page_table: 1, virtual_address: address, physical_address: address })
}
fn load_value(key: AddressKey, size: u64) -> Result<u64, u64> {
    match size {
        4 => Ok(unsafe { &*(key.physical_address as *const AtomicU32) }.load(Ordering::Acquire) as u64),
        8 => Ok(unsafe { &*(key.physical_address as *const AtomicU64) }.load(Ordering::Acquire)),
        _ => Err(EINVAL),
    }
}
static WAITERS: SpinLock<[Option<AddressWaiter>; MAX_WAITERS]> = SpinLock::new([None; MAX_WAITERS]);
"#,
    );
    for entry in [
        "struct AddressKey {",
        "impl AddressKey {",
        "struct AddressWaiter {",
        "fn expected_for_size(",
        "fn remove_waiter_locked(",
        "pub(crate) fn remove_waiter(",
        "pub fn wait(",
        "pub fn wait_guarded(",
        "fn wait_inner(",
        "pub fn wake(",
    ] {
        let start = source.find(entry).unwrap();
        let end = start + source[start..].find("\n}\n").unwrap() + 3;
        if matches!(entry, "struct AddressKey {" | "struct AddressWaiter {") {
            program.push_str("#[derive(Clone, Copy)]\n");
        }
        program.push_str(&source[start..end]);
    }
    program.push_str(
        r#"
pub fn test() {
    let word = AtomicU64::new(0);
    let notification = AtomicU64::new(0);
    let primary = &word as *const AtomicU64 as u64;
    let guard_address = &notification as *const AtomicU64 as u64;
    let descriptor = [guard_address, 0u64];
    let guard = descriptor.as_ptr() as u64;
    assert_eq!(wait_guarded(primary, 0, 8, u64::MAX, 0), EFAULT);
    assert_eq!(wait_guarded(primary, 0, 8, u64::MAX, u64::MAX), EFAULT);
    assert_eq!(wait_guarded(0, 0, 8, u64::MAX, guard), EFAULT);
    assert_eq!(wait_guarded(primary, 0, 3, u64::MAX, guard), EINVAL);
    let unaligned = [guard_address + 1, 0u64];
    assert_eq!(wait_guarded(primary, 0, 8, u64::MAX, unaligned.as_ptr() as u64), EINVAL);
    let missing = [0u64, 0u64];
    assert_eq!(wait_guarded(primary, 0, 8, u64::MAX, missing.as_ptr() as u64), EFAULT);
    word.store(1, Ordering::Release);
    assert_eq!(wait_guarded(primary, 0, 8, u64::MAX, guard), 1);
    word.store(0, Ordering::Release);
    notification.store(1, Ordering::Release);
    assert_eq!(wait_guarded(primary, 0, 8, u64::MAX, guard), 1);
    notification.store(0, Ordering::Release);
    assert_eq!(wait_guarded(primary, 0, 8, 0, guard), 2);
    for address in [primary, guard_address] {
        ACTION.store(address, Ordering::Release);
        assert_eq!(wait_guarded(primary, 0, 8, u64::MAX, guard), 0);
        assert_eq!(wake(primary, u64::MAX), 0);
        assert_eq!(wake(guard_address, u64::MAX), 0);
        assert!(WAITERS.lock().iter().all(Option::is_none));
    }
    // The same key in both positions still consumes/wakes only one waiter.
    let same = [primary, 0u64];
    ACTION.store(primary, Ordering::Release);
    assert_eq!(wait_guarded(primary, 0, 8, u64::MAX, same.as_ptr() as u64), 0);
    ACTION.store(1, Ordering::Release);
    assert_eq!(wait_guarded(primary, 0, 8, 5, guard), 2);
    NOW.store(0, Ordering::Release);
    ARM_OK.store(0, Ordering::Release);
    assert_eq!(wait_guarded(primary, 0, 8, 5, guard), EAGAIN);
    assert!(WAITERS.lock().iter().all(Option::is_none));
    ARM_OK.store(1, Ordering::Release);
    ACTION.store(2, Ordering::Release);
    assert_eq!(wait_guarded(primary, 0, 8, u64::MAX, guard), 0);
    UPCALL.store(0, Ordering::Release);
    assert!(WAITERS.lock().iter().all(Option::is_none));
    // Legacy single-address waits keep the same behavior and shared queue.
    ACTION.store(primary, Ordering::Release);
    assert_eq!(wait(primary, 0, 8, u64::MAX), 0);
    assert_eq!(*task::WAKES.lock().unwrap(), [7, 7, 7, 7]);
    assert_eq!(DISARMS.load(Ordering::Relaxed), 6);
    let small = AtomicU32::new(u32::MAX);
    ACTION.store(guard_address, Ordering::Release);
    assert_eq!(wait_guarded(&small as *const AtomicU32 as u64, u64::MAX, 4, u64::MAX, guard), 0);
    // Exhaustion and duplicate admission never replace another subscription.
    let key = resolve_key(primary, 8).unwrap();
    for (index, slot) in WAITERS.lock().iter_mut().enumerate() {
        *slot = Some(AddressWaiter { thread: index as u64 + 1, key, guard: None });
    }
    assert_eq!(wait_guarded(primary, 0, 8, u64::MAX, guard), EAGAIN);
    assert_eq!(WAITERS.lock().iter().flatten().count(), 4);
    WAITERS.lock()[0].as_mut().unwrap().thread = 7;
    assert_eq!(wait_guarded(primary, 0, 8, u64::MAX, guard), EAGAIN);
    assert_eq!(WAITERS.lock().iter().flatten().count(), 4);
    *WAITERS.lock() = [None; MAX_WAITERS];
}
}
fn main() { actual::test(); }
"#,
    );
    let directory = std::env::temp_dir().join(format!(
        "mochios-address-guard-{}-{}",
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
    let result = compiler.wait_with_output().unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let result = Command::new(executable).output().unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    std::fs::remove_dir_all(directory).unwrap();
}
