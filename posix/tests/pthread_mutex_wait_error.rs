use std::io::Write;
use std::process::{Command, Stdio};

#[test]
fn public_mutex_lock_retries_interrupts_and_preserves_the_failed_wait_error() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../user/crates/posix-client/src/pthread_mutex.rs")
        .canonicalize()
        .unwrap();
    let mut program = format!(
        "extern crate self as mochios_posix_client;\n#[path = {root:?}] pub mod pthread_mutex;\n"
    );
    program.push_str(
        r#"
use std::sync::atomic::{AtomicI32, AtomicUsize, Ordering};
type c_int = i32;
const EINVAL: i32 = 22;
const EBUSY: i32 = 16;
const EDEADLK: i32 = 45;
const EPERM: i32 = 1;
const EAGAIN: i32 = 11;
const EINTR: i32 = 4;
static ERRNO: AtomicI32 = AtomicI32::new(123);
static WAITS: AtomicUsize = AtomicUsize::new(0);
static WAKES: AtomicUsize = AtomicUsize::new(0);
static LOCK: pthread_mutex::Mutex = pthread_mutex::Mutex::new(pthread_mutex::NORMAL);
#[derive(Debug)] pub struct SysError(i64);
impl SysError { pub fn raw(&self) -> i64 { self.0 } }
fn native_thread_id() -> Result<u64, SysError> { Ok(2) }
fn map_kernel_errno(raw: i64) -> i32 { (-raw) as i32 }
mod syscall { pub const ADDRESS_WAIT_INFINITE: u64 = u64::MAX; }
pub mod synchronization {
    use super::*;
    use std::sync::atomic::AtomicU32;
    pub fn wait_u32(word: &AtomicU32, expected: u32, deadline: u64) -> Result<(), SysError> {
        assert_eq!(word.load(Ordering::Acquire), 2);
        assert_eq!(expected, 2);
        assert_eq!(deadline, u64::MAX);
        if WAITS.fetch_add(1, Ordering::Relaxed) == 0 {
            Err(SysError(-4))
        } else {
            LOCK.unlock(1, |_| {}).unwrap(); // This caller consumed the owner's wake.
            Err(SysError(-5))
        }
    }
    pub fn wake_u32(word: &AtomicU32, count: usize) -> Result<usize, SysError> {
        assert_eq!(word.load(Ordering::Acquire), 0);
        assert_eq!(count, 1);
        WAKES.fetch_add(1, Ordering::Relaxed);
        Err(SysError(-75)) // Must not replace the original acquisition error.
    }
}
mod runtime {
    use super::*;
    use mochios_posix_client::pthread_mutex::{self as state, Error, Mutex};
"#,
    );
    let source = include_str!("../../../user/crates/newlib-runtime/src/pthread_mutex.rs");
    for entry in [
        "fn error(",
        "fn owner(",
        "pub unsafe extern \"C\" fn pthread_mutex_lock(",
    ] {
        let start = source.find(entry).unwrap();
        let end = start + source[start..].find("\n}\n").unwrap() + 3;
        program.push_str(&source[start..end]);
    }
    program.push_str(
        r#"
}
fn main() {
    assert_eq!(unsafe { runtime::pthread_mutex_lock(std::ptr::null_mut()) }, EINVAL);
    LOCK.try_lock(1).unwrap();
    let pointer = &LOCK as *const pthread_mutex::Mutex as *mut pthread_mutex::Mutex;
    assert_eq!(unsafe { runtime::pthread_mutex_lock(pointer) }, 5);
    assert_eq!(WAITS.load(Ordering::Relaxed), 2);
    assert_eq!(WAKES.load(Ordering::Relaxed), 1);
    assert_eq!(ERRNO.load(Ordering::Relaxed), 123);
    LOCK.try_lock(2).unwrap(); // Failed acquisition left no owner behind.
    LOCK.unlock(2, |_| {}).unwrap();
    LOCK.destroy().unwrap(); // Neither the retry nor failure leaked a waiter.
}
"#,
    );
    let directory = std::env::temp_dir().join(format!(
        "mochios-mutex-wait-error-{}-{}",
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
