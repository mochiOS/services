use mochios_posix_client::pthread_spin::{self as state, DESTROYED, Error};
use std::sync::atomic::{AtomicU32, Ordering};

#[test]
fn exclusive_state_lifecycle_rejects_busy_destroy_and_dead_or_corrupt_words() {
    let word = AtomicU32::new(0);
    assert_eq!(state::try_lock(&word), Ok(()));
    assert_eq!(state::try_lock(&word), Err(Error::Busy));
    assert_eq!(state::destroy(&word), Err(Error::Busy));
    assert_eq!(state::unlock(&word), Ok(()));
    assert_eq!(state::destroy(&word), Ok(()));
    assert_eq!(word.load(Ordering::Acquire), DESTROYED);
    assert_eq!(state::try_lock(&word), Err(Error::Invalid));
    assert_eq!(state::unlock(&word), Err(Error::Invalid));
    state::initialize(&word);
    assert_eq!(state::try_lock(&word), Ok(()));
    assert_eq!(state::try_lock(&AtomicU32::new(2)), Err(Error::Invalid));
}

#[test]
fn contending_threads_publish_protected_relaxed_updates_without_losing_writes() {
    let word = AtomicU32::new(0);
    let value = AtomicU32::new(0);
    std::thread::scope(|scope| {
        for _ in 0..8 {
            scope.spawn(|| {
                for _ in 0..1000 {
                    loop {
                        match state::try_lock(&word) {
                            Ok(()) => break,
                            Err(Error::Busy) => std::thread::yield_now(),
                            Err(error) => panic!("unexpected acquisition error: {error:?}"),
                        }
                    }
                    value.store(value.load(Ordering::Relaxed) + 1, Ordering::Relaxed);
                    state::unlock(&word).unwrap();
                }
            });
        }
    });
    assert_eq!(value.load(Ordering::Acquire), 8000);
}

#[test]
fn adapter_has_no_cancellation_point_or_service_rpc_and_yields_on_long_contention() {
    let source = include_str!("../../../user/crates/newlib-runtime/src/pthread_spin.rs");
    assert!(!source.contains("pthread_testcancel("));
    assert!(!source.contains("posix_client("));
    assert!(source.contains("SyscallNumber::ThreadYield"));
    assert!(source.contains("pointer.write(AtomicU32::new(0))"));
}

#[test]
fn actual_adapter_yields_before_retrying_and_validates_lifecycle_without_tls() {
    use std::io::Write;
    use std::process::{Command, Stdio};
    let mut program = String::from(
        r#"
use std::sync::atomic::{AtomicU32, Ordering};
type c_int = i32; const EINVAL: i32 = 22; const EBUSY: i32 = 16;
static WORD: AtomicU32 = AtomicU32::new(1);
static YIELDS: AtomicU32 = AtomicU32::new(0);
mod syscall {
    pub enum SyscallNumber { ThreadYield }
    pub fn raw_syscall0(_: SyscallNumber) -> u64 {
        crate::YIELDS.fetch_add(1, crate::Ordering::Relaxed);
        crate::WORD.store(0, crate::Ordering::Release); 0
    }
}
mod mochios_posix_client { pub mod pthread_spin {
"#,
    );
    program.push_str(
        &include_str!("../../../user/crates/posix-client/src/pthread_spin.rs")
            .lines()
            .filter(|line| !line.starts_with("//!"))
            .collect::<Vec<_>>()
            .join("\n"),
    );
    program.push_str("\n} }\nmod adapter {\n");
    program.push_str(
        &include_str!("../../../user/crates/newlib-runtime/src/pthread_spin.rs")
            .lines()
            .filter(|line| !line.starts_with("//!"))
            .collect::<Vec<_>>()
            .join("\n"),
    );
    program.push_str(
        r#"
}
use adapter::*;
fn main() { unsafe {
    let pointer = &WORD as *const AtomicU32 as *mut AtomicU32;
    assert_eq!(pthread_spin_lock(pointer), 0);
    assert_eq!(YIELDS.load(Ordering::Acquire), 1);
    assert_eq!(pthread_spin_trylock(pointer), 16);
    assert_eq!(pthread_spin_destroy(pointer), 16);
    assert_eq!(pthread_spin_unlock(pointer), 0);
    assert_eq!(pthread_spin_destroy(pointer), 0);
    assert_eq!(pthread_spin_lock(pointer), 22);
    assert_eq!(pthread_spin_lock(std::ptr::null_mut()), 22);
    assert_eq!(pthread_spin_init(std::ptr::null_mut(), 0), 22);
    let mut local = std::mem::MaybeUninit::<AtomicU32>::uninit();
    assert_eq!(pthread_spin_init(local.as_mut_ptr(), 99), 22);
    assert_eq!(pthread_spin_init(local.as_mut_ptr(), 1), 0);
    assert_eq!(pthread_spin_trylock(local.as_mut_ptr()), 0);
    assert_eq!(pthread_spin_unlock(local.as_mut_ptr()), 0);
    assert_eq!(pthread_spin_destroy(local.as_mut_ptr()), 0);
} }
"#,
    );
    let directory = std::env::temp_dir().join(format!(
        "mochios-spin-adapter-{}-{}",
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
    let result = compiler.wait_with_output().unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let result = Command::new(&executable).output().unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    std::fs::remove_dir_all(directory).unwrap();
}
