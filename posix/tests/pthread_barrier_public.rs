use std::io::Write;
use std::process::{Command, Stdio};

#[test]
fn actual_public_adapter_handles_attributes_resets_native_errors_and_committed_participants() {
    let mut program = String::from(
        r#"
use std::ffi::c_int;
use std::sync::atomic::{AtomicU64, AtomicU32, Ordering};
const EINVAL: i32 = 22; const EBUSY: i32 = 16; const EINTR: i32 = 4; const EAGAIN: i32 = 11;
fn map_kernel_errno(raw: i64) -> i32 { -raw as i32 }
static ERROR: AtomicU32 = AtomicU32::new(0);
mod syscall {
    pub const ADDRESS_WAIT_INFINITE: u64 = u64::MAX;
    pub enum SyscallNumber { ThreadYield }
    pub fn raw_syscall0(_: SyscallNumber) -> u64 { std::thread::yield_now(); 0 }
}
mod mochios_posix_client {
    pub mod pthread_barrier {
"#,
    );
    // Exercise the real state/adapter with frequent resets instead of needing
    // u64::MAX/2 arrivals. Representation and state transitions are unchanged.
    program.push_str(
        &include_str!("../../../user/crates/posix-client/src/pthread_barrier.rs")
            .lines()
            .filter(|line| !line.starts_with("//!"))
            .collect::<Vec<_>>()
            .join("\n")
            .replace("{ u64::MAX / 2 }", "4"),
    );
    program.push_str(r#"
    }
    pub mod synchronization {
        use crate::*;
        pub struct Error(i64); impl Error { pub fn raw(&self) -> i64 { self.0 } }
        pub fn wait_u64(_: &AtomicU64, _: u64, deadline: u64) -> Result<(), Error> {
            assert_eq!(deadline, u64::MAX);
            std::thread::yield_now();
            match ERROR.swap(0, Ordering::AcqRel) { 1 => Err(Error(-4)), 2 => Err(Error(-11)), 3 => Err(Error(-5)), _ => Ok(()) }
        }
        pub fn wake_u64(_: &AtomicU64, count: usize) -> Result<usize, Error> { assert_eq!(count, usize::MAX); Ok(0) }
    }
}
mod adapter {
"#);
    program.push_str(
        &include_str!("../../../user/crates/newlib-runtime/src/pthread_barrier.rs")
            .lines()
            .filter(|line| !line.starts_with("//!"))
            .collect::<Vec<_>>()
            .join("\n"),
    );
    program.push_str(r#"
}
use adapter::*;
use mochios_posix_client::pthread_barrier::Barrier;
fn main() { unsafe {
    let mut attr = std::mem::MaybeUninit::<Attribute>::uninit();
    assert_eq!(std::mem::size_of::<Attribute>(), 8);
    assert_eq!(pthread_barrierattr_init(attr.as_mut_ptr()), 0);
    let mut sharing = -1;
    assert_eq!(pthread_barrierattr_getpshared(attr.as_ptr(), &mut sharing), 0); assert_eq!(sharing, 0);
    assert_eq!(pthread_barrierattr_setpshared(attr.as_mut_ptr(), 99), 22);
    assert_eq!(pthread_barrierattr_setpshared(attr.as_mut_ptr(), 1), 0);
    assert_eq!(pthread_barrierattr_getpshared(attr.as_ptr(), &mut sharing), 0); assert_eq!(sharing, 1);
    let mut uninitialized = std::mem::MaybeUninit::<Barrier>::uninit();
    assert_eq!(pthread_barrier_init(uninitialized.as_mut_ptr(), attr.as_ptr(), 0), 22);
    assert_eq!(pthread_barrier_init(uninitialized.as_mut_ptr(), attr.as_ptr(), 2), 0);
    let barrier = std::sync::Arc::new(uninitialized.assume_init());
    let serial = AtomicU32::new(0);
    std::thread::scope(|scope| {
        for _ in 0..2 {
            let barrier = &barrier; let serial = &serial;
            scope.spawn(move || {
                for _ in 0..600 {
                    let result = pthread_barrier_wait(std::sync::Arc::as_ptr(barrier).cast_mut());
                    assert!(matches!(result, 0 | -1));
                    if result == -1 { serial.fetch_add(1, Ordering::Relaxed); }
                }
            });
        }
    });
    assert_eq!(serial.load(Ordering::Acquire), 600);
    assert_eq!(pthread_barrier_destroy(std::sync::Arc::as_ptr(&barrier).cast_mut()), 0);
    assert_eq!(pthread_barrier_wait(std::sync::Arc::as_ptr(&barrier).cast_mut()), 22);
    assert_eq!(pthread_barrierattr_destroy(attr.as_mut_ptr()), 0);
    assert_eq!(pthread_barrierattr_getpshared(attr.as_ptr(), &mut sharing), 22);
    for mode in 1..=3 {
        let barrier = std::sync::Arc::new(Barrier::new(2).unwrap());
        ERROR.store(mode, Ordering::Release);
        let other = std::sync::Arc::clone(&barrier);
        let worker = std::thread::spawn(move || pthread_barrier_wait(std::sync::Arc::as_ptr(&other).cast_mut()));
        while ERROR.load(Ordering::Acquire) != 0 { std::thread::yield_now(); }
        assert_eq!(pthread_barrier_destroy(std::sync::Arc::as_ptr(&barrier).cast_mut()), 16);
        assert_eq!(pthread_barrier_wait(std::sync::Arc::as_ptr(&barrier).cast_mut()), -1);
        assert_eq!(worker.join().unwrap(), if mode == 3 { 5 } else { 0 });
        assert_eq!(pthread_barrier_destroy(std::sync::Arc::as_ptr(&barrier).cast_mut()), 0);
    }
} }
"#);
    let directory = std::env::temp_dir().join(format!(
        "mochios-barrier-public-{}-{}",
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
