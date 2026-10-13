use std::io::Write;
use std::process::{Command, Stdio};

#[test]
fn actual_exec_path_guard_requires_the_live_callers_authority() {
    let source = include_str!("../../../core/src/syscall/exec.rs");
    assert!(!source.contains("access_process_override"));
    let function = &source[source.find("fn exec_internal(").unwrap()..];
    let start = function.find("    if enforce_path_access {").unwrap();
    let end = function
        .find("    if let Some((data, source)) = load_exec_image(")
        .unwrap();
    let mut program = String::from(
        r#"
use std::sync::atomic::{AtomicUsize, Ordering};
static THREAD: AtomicUsize = AtomicUsize::new(0);
static PROCESS: AtomicUsize = AtomicUsize::new(0);
static CHECKS: AtomicUsize = AtomicUsize::new(0);
static LOADS: AtomicUsize = AtomicUsize::new(0);
static ERROR: AtomicUsize = AtomicUsize::new(0);
mod task {
    pub struct Thread;
    impl Thread {
        pub fn process_id(&self) -> usize {
            crate::PROCESS.load(crate::Ordering::Relaxed)
        }
    }
    pub fn current_thread_id() -> Option<usize> {
        match crate::THREAD.load(crate::Ordering::Relaxed) {
            0 => None,
            value => Some(value),
        }
    }
    pub fn with_thread<T>(id: usize, f: impl FnOnce(&Thread) -> T) -> Option<T> {
        assert_eq!(id, 7);
        if crate::PROCESS.load(crate::Ordering::Relaxed) == 0 { None }
        else { Some(f(&Thread)) }
    }
}
mod syscall {
    pub mod types { pub const EACCES: u64 = (-13i64) as u64; }
    pub mod fs {
        pub fn ensure_fs_path_executable_for_process(path: &str, pid: usize) -> Result<(), u64> {
            assert_eq!(path, "/image");
            assert_eq!(pid, 42);
            crate::CHECKS.fetch_add(1, crate::Ordering::Relaxed);
            match crate::ERROR.load(crate::Ordering::Relaxed) {
                0 => Ok(()),
                error => Err(error as u64),
            }
        }
    }
}
fn exec_guard(enforce_path_access: bool) -> u64 {
    let path = "/image";
"#,
    );
    program.push_str(&function[start..end]);
    program.push_str(
        r#"
    LOADS.fetch_add(1, Ordering::Relaxed);
    0
}
fn main() {
    // An absent caller must never reach either the path check or image loading.
    assert_eq!(exec_guard(true), syscall::types::EACCES);
    assert_eq!(CHECKS.load(Ordering::Relaxed), 0);
    assert_eq!(LOADS.load(Ordering::Relaxed), 0);
    THREAD.store(7, Ordering::Relaxed);
    assert_eq!(exec_guard(true), syscall::types::EACCES);
    assert_eq!(CHECKS.load(Ordering::Relaxed), 0);
    assert_eq!(LOADS.load(Ordering::Relaxed), 0);

    // The path check receives only the current thread's process, and its error
    // is preserved before any attempt to load an executable.
    PROCESS.store(42, Ordering::Relaxed);
    ERROR.store(123, Ordering::Relaxed);
    assert_eq!(exec_guard(true), 123);
    assert_eq!(CHECKS.load(Ordering::Relaxed), 1);
    assert_eq!(LOADS.load(Ordering::Relaxed), 0);
    ERROR.store(0, Ordering::Relaxed);
    assert_eq!(exec_guard(true), 0);
    assert_eq!(CHECKS.load(Ordering::Relaxed), 2);
    assert_eq!(LOADS.load(Ordering::Relaxed), 1);

    // Explicit kernel bootstrap is not a user request and has no caller yet.
    THREAD.store(0, Ordering::Relaxed);
    PROCESS.store(0, Ordering::Relaxed);
    assert_eq!(exec_guard(false), 0);
    assert_eq!(CHECKS.load(Ordering::Relaxed), 2);
    assert_eq!(LOADS.load(Ordering::Relaxed), 2);
}
"#,
    );
    let directory = std::env::temp_dir().join(format!(
        "mochios-exec-authority-{}-{}",
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
