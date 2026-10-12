use std::io::Write;
use std::process::{Command, Stdio};

#[test]
fn actual_vector_apis_release_their_buffer_before_cancelling_and_preserve_progress() {
    let runtime = include_str!("../../../user/crates/newlib-runtime/src/lib.rs");
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut program = format!(
        r#"
use std::ffi::c_void;
use std::ptr;
use std::sync::atomic::{{AtomicU32, Ordering}};
type c_int = i32;
const EFAULT: i32 = 14;
const EINVAL: i32 = 22;
const ENOMEM: i32 = 12;
const EIO: i32 = 5;
const EINTR: i32 = 4;
struct IoVec {{ iov_base: *const c_void, iov_len: usize }}
struct IoVecMut {{ iov_base: *mut c_void, iov_len: usize }}
#[derive(Clone, Copy)] struct FdEntry;
static PENDING: AtomicU32 = AtomicU32::new(0);
static CHECKS: AtomicU32 = AtomicU32::new(0);
static CASE: AtomicU32 = AtomicU32::new(0);
static ALLOCATIONS: std::sync::Mutex<std::collections::BTreeMap<usize, usize>> = std::sync::Mutex::new(std::collections::BTreeMap::new());
unsafe fn malloc(length: usize) -> *mut c_void {{
    let layout = std::alloc::Layout::from_size_align(length, 16).unwrap();
    let pointer = unsafe {{ std::alloc::alloc(layout) }};
    ALLOCATIONS.lock().unwrap().insert(pointer as usize, length);
    pointer.cast()
}}
unsafe fn free(pointer: *mut c_void) {{
    let length = ALLOCATIONS.lock().unwrap().remove(&(pointer as usize)).unwrap();
    unsafe {{ std::alloc::dealloc(pointer.cast(), std::alloc::Layout::from_size_align(length, 16).unwrap()) }};
}}
fn pthread_testcancel() {{
    let checks = CHECKS.fetch_add(1, Ordering::AcqRel) + 1;
    if PENDING.load(Ordering::Acquire) != 0 {{
        assert!(ALLOCATIONS.lock().unwrap().is_empty(), "cancellation leaked the vector buffer");
        assert_eq!(checks, if CASE.load(Ordering::Acquire) == 2 {{ 1 }} else {{ 2 }});
        std::process::exit(73)
    }}
}}
fn set_errno(_: i32) {{}}
fn result_with_errno(result: Result<isize, i32>, failed: isize) -> isize {{ result.unwrap_or(failed) }}
fn with_fd_entry(_: i32) -> Result<FdEntry, i32> {{ Ok(FdEntry) }}
fn syscall_write(_: FdEntry, buffer: *const c_void, length: usize) -> Result<isize, i32> {{
    assert_eq!(unsafe {{ std::slice::from_raw_parts(buffer.cast::<u8>(), length) }}, b"abcDEFG");
    assert_eq!(ALLOCATIONS.lock().unwrap().len(), 1);
    PENDING.store(1, Ordering::Release);
    Err(EINTR)
}}
fn syscall_read(_: FdEntry, _: *mut c_void, length: usize) -> Result<isize, i32> {{
    assert_eq!(length, 7);
    assert_eq!(ALLOCATIONS.lock().unwrap().len(), 1);
    PENDING.store(1, Ordering::Release);
    Err(EINTR)
}}
mod mochios_posix_client {{ #[path = "{}"] pub mod io_vector; }}
"#,
        root.join("user/crates/posix-client/src/io_vector.rs")
            .canonicalize()
            .unwrap()
            .display()
    );
    for entry in [
        "fn vector_errno(",
        "struct VectorBuffer {",
        "impl VectorBuffer {",
        "impl Drop for VectorBuffer {",
        "fn finish_io_cancellation(",
        "pub unsafe extern \"C\" fn writev(",
        "pub unsafe extern \"C\" fn readv(",
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
    if case == 2 {
        PENDING.store(1, Ordering::Release);
        assert_eq!(finish_io_cancellation(17), 17);
        assert_eq!(CHECKS.load(Ordering::Acquire), 0);
        finish_io_cancellation(0);
    } else if case == 0 {
        let vectors = [IoVec { iov_base: b"abc".as_ptr().cast(), iov_len: 3 },
                       IoVec { iov_base: b"DEFG".as_ptr().cast(), iov_len: 4 }];
        unsafe { writev(3, vectors.as_ptr(), 2) };
    } else {
        let mut first = [0u8; 3]; let mut second = [0u8; 4];
        let vectors = [IoVecMut { iov_base: first.as_mut_ptr().cast(), iov_len: 3 },
                       IoVecMut { iov_base: second.as_mut_ptr().cast(), iov_len: 4 }];
        unsafe { readv(3, vectors.as_ptr(), 2) };
    }
    panic!("cancellation point returned");
}
"#,
    );
    let directory = std::env::temp_dir().join(format!(
        "mochios-vector-cancel-{}-{}",
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
    for case in 0..3 {
        let executed = Command::new(&executable)
            .arg(case.to_string())
            .output()
            .unwrap();
        assert_eq!(
            executed.status.code(),
            Some(73),
            "case {case}: {}",
            String::from_utf8_lossy(&executed.stderr)
        );
    }
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn internal_io_returns_through_owned_resources_instead_of_exiting_under_a_stdio_lock() {
    let source = include_str!("../../../user/crates/newlib-runtime/src/lib.rs");
    for entry in ["fn _write(", "fn _read("] {
        let start = source.find(entry).unwrap();
        let end = start + source[start..].find("\n}\n").unwrap();
        assert!(!source[start..end].contains("pthread_testcancel()"));
    }
    let stream = source
        .split("fn stream_io_since<")
        .nth(1)
        .unwrap()
        .split("fn io_cancellation_requested(")
        .next()
        .unwrap();
    assert!(stream.find("io_cancellation_requested(control)").unwrap() < stream.find("operation()").unwrap());
    assert!(!stream.contains("pthread_testcancel()"));
    let wait = source
        .split("fn wait_for_handle_capacity(")
        .nth(1)
        .unwrap()
        .split("fn stream_io<")
        .next()
        .unwrap();
    assert!(wait.contains("wait_cancellable("));
    assert!(wait.contains("minimum_write_bytes,"));
    assert!(wait.contains("nonrestart_signal_generation.load"));
    assert!(!wait.contains("pthread_testcancel()"));
}
