use std::io::Write;
use std::process::{Command, Stdio};

#[test]
fn actual_guard_registration_shares_wake_table_and_releases_every_subscription() {
    let source = include_str!("../../../core/src/syscall/address_wait.rs");
    let mut program = String::from(
        r#"
use std::sync::atomic::{AtomicU64, Ordering};
type ThreadId = u64;
const EAGAIN: u64 = Error::NotReady.into_raw();
const EFAULT: u64 = Error::InvalidAddress.into_raw();
const EINVAL: u64 = Error::InvalidArgument.into_raw();
const MAX_WAITERS: usize = 4;
struct SpinLock<T>(std::sync::Mutex<T>);
impl<T> SpinLock<T> {
    const fn new(value: T) -> Self { Self(std::sync::Mutex::new(value)) }
    fn lock(&self) -> std::sync::MutexGuard<'_, T> { self.0.lock().unwrap() }
}
mod task {
    pub static WAKES: std::sync::Mutex<Vec<u64>> = std::sync::Mutex::new(Vec::new());
    pub fn wake_registered_waiter(thread: u64) { WAKES.lock().unwrap().push(thread); }
}
fn resolve_key(address: u64, size: u64) -> Result<AddressKey, u64> {
    if address == 0 { return Err(EFAULT); }
    if address & (size - 1) != 0 { return Err(EINVAL); }
    Ok(AddressKey { page_table: 1, virtual_address: address, physical_address: address })
}
fn load_value(key: AddressKey, size: u64) -> Result<u64, u64> {
    assert_eq!(size, 8);
    Ok(unsafe { &*(key.physical_address as *const AtomicU64) }.load(Ordering::Acquire))
}
"#,
    );
    program.insert_str(
        0,
        &format!(
            "mod status {{\n{}\n}}\nuse status::Error;\n",
            include_str!("../../../core/crates/abi/src/status.rs")
        ),
    );
    for entry in [
        "struct AddressKey {",
        "impl AddressKey {",
        "struct AddressWaiter {",
        "fn remove_waiter_locked(",
        "pub(crate) fn remove_waiter(",
        "pub(crate) struct GuardWaiter {",
        "impl Drop for GuardWaiter {",
        "pub(crate) fn register_guard(",
        "pub fn wake(",
    ] {
        let start = source.find(entry).unwrap();
        let end = start + source[start..].find("\n}\n").unwrap() + 3;
        if matches!(entry, "struct AddressKey {" | "struct AddressWaiter {") {
            program.push_str("#[derive(Clone, Copy)]\n");
        }
        program.push_str(&source[start..end]);
    }
    program.push_str(r#"
static WAITERS: SpinLock<[Option<AddressWaiter>; MAX_WAITERS]> = SpinLock::new([None; MAX_WAITERS]);
fn main() {
    assert_eq!(wake(0,0),0);
    let word = AtomicU64::new(0);
    let other = AtomicU64::new(0);
    let address = &word as *const AtomicU64 as u64;
    let unrelated = &other as *const AtomicU64 as u64;
    assert_eq!(register_guard(7, 0, 0).err(), Some(EFAULT));
    assert_eq!(register_guard(7, address + 1, 0).err(), Some(EINVAL));
    let guard = register_guard(7, address, 0).unwrap();
    assert_eq!(register_guard(7, unrelated, 0).err(), Some(EAGAIN));
    assert_eq!(wake(unrelated, u64::MAX), 0);
    assert_eq!(wake(address, 0), 0);
    word.store(1, Ordering::Release);
    assert_eq!(wake(address, 1), 1);
    assert_eq!(*task::WAKES.lock().unwrap(), [7]);
    drop(guard);
    assert_eq!(register_guard(7, address, 0).err(), Some(EAGAIN));
    { let _guard = register_guard(7, address, 1).unwrap(); }
    // Drop is sufficient: retrying the same thread must not see a stale slot.
    { let _guard = register_guard(7, address, 1).unwrap(); }
    assert_eq!(wake(address, u64::MAX), 0);
    let mut guards: Vec<_> = (1..=4).map(|thread| register_guard(thread, address, 1).unwrap()).collect();
    assert_eq!(register_guard(5, address, 1).err(), Some(Error::ResourceUnavailable.into_raw()));
    assert_eq!(wake(address, 2), 2);
    assert_eq!(wake(address, u64::MAX), 2);
    guards.clear();
    assert!(WAITERS.lock().iter().all(Option::is_none));
}
"#);
    let directory = std::env::temp_dir().join(format!(
        "mochios-guard-wake-{}-{}",
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
    let executed = Command::new(&executable).output().unwrap();
    assert!(
        executed.status.success(),
        "{}",
        String::from_utf8_lossy(&executed.stderr)
    );
    std::fs::remove_dir_all(directory).unwrap();
}
