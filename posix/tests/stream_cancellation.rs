use std::io::Write;
use std::process::{Command, Stdio};

struct TemporaryDirectory(std::path::PathBuf);
impl Drop for TemporaryDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn actual_vector_apis_release_their_buffer_before_cancelling_and_preserve_progress() {
    let runtime = include_str!("../../../user/crates/newlib-runtime/src/lib.rs");
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut program = format!(
        r#"
use std::ffi::c_void;
use std::ptr;
extern crate self as mochios_posix_client;
use std::sync::atomic::{{AtomicU32, AtomicU64, Ordering}};
type c_int = i32;
const EFAULT: i32 = 14;
const EINVAL: i32 = 22;
const ENOMEM: i32 = 12;
const EIO: i32 = 5;
const EINTR: i32 = 4;
const EAGAIN: i32 = 11;
struct IoVec {{ iov_base: *const c_void, iov_len: usize }}
struct IoVecMut {{ iov_base: *mut c_void, iov_len: usize }}
#[derive(Clone, Copy)] struct FdEntry;
struct Lease(FdEntry);
impl std::ops::Deref for Lease {{ type Target = FdEntry; fn deref(&self)->&FdEntry {{ &self.0 }} }}
impl Drop for Lease {{ fn drop(&mut self) {{
    assert_ne!(CONTROL.native.load(Ordering::Relaxed), 0);
    assert_eq!(PINS.fetch_sub(1, Ordering::Relaxed), 1);
}} }}
static PINS: AtomicU32 = AtomicU32::new(0);
struct ThreadControl {{ native: AtomicU32, active_signal_scope_id: AtomicU64, callback_resources: callback_resources::Chain }}
static CONTROL: ThreadControl = ThreadControl {{ native: AtomicU32::new(0), active_signal_scope_id: AtomicU64::new(0), callback_resources: callback_resources::Chain::new() }};
fn register_current_thread()->Option<(u32, &'static ThreadControl)> {{Some((1,&CONTROL))}}
fn defer_native_delivery()->Option<upcall_guard::Guard<'static>> {{upcall_guard::Guard::enter(&CONTROL.native)}}
unsafe extern "C" {{
    fn mochios_test_io_escape(operation: extern "C" fn(u32), mode: u32)->i32;
    fn mochios_test_io_jump()->!;
}}
static PENDING: AtomicU32 = AtomicU32::new(0);
static CHECKS: AtomicU32 = AtomicU32::new(0);
static CASE: AtomicU32 = AtomicU32::new(0);
static ALLOCATIONS: std::sync::Mutex<std::collections::BTreeMap<usize, usize>> = std::sync::Mutex::new(std::collections::BTreeMap::new());
unsafe fn malloc(length: usize) -> *mut c_void {{
    if CASE.load(Ordering::Relaxed) == 7 {{ return std::ptr::null_mut(); }}
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
        assert_eq!(PINS.load(Ordering::Relaxed), 0);
        assert_eq!(checks, if matches!(CASE.load(Ordering::Acquire), 2 | 12 | 16) {{ 1 }} else {{ 2 }});
        std::process::exit(73)
    }}
}}
fn set_errno(_: i32) {{}}
fn result_with_errno(result: Result<isize, i32>, failed: isize) -> isize {{ result.unwrap_or(failed) }}
fn with_fd_entry(_: i32) -> Result<Lease, i32> {{
    if CASE.load(Ordering::Relaxed) == 8 {{return Err(9)}}
    PINS.fetch_add(1,Ordering::Relaxed); Ok(Lease(FdEntry))
}}
fn record_stdio_io(_: &Result<isize,i32>) {{}}
fn positioned_file_io(fd:i32, _: *mut c_void, length:usize, offset:i64, writing:bool)->Result<isize,i32> {{
    let case = CASE.load(Ordering::Relaxed);
    assert_eq!((fd, length, offset, writing), (3, 7, 11, case >= 16));
    io_resources::with(|| with_fd_entry(fd), |_| {{
        PENDING.store(1,Ordering::Release);
        match case % 4 {{1 => Err(EINTR), 2 => Ok(3), 3 => Ok(0), _ => panic!("pending entry reached native I/O")}}
    }})
}}
fn escape_if_requested() {{
    if (3..=6).contains(&CASE.load(Ordering::Relaxed)) {{
        CONTROL.active_signal_scope_id.store(7, Ordering::Relaxed);
        {{ let _native = defer_native_delivery(); unsafe {{ CONTROL.callback_resources.abandon_from(0) }}; }}
        unsafe {{ mochios_test_io_jump() }}
    }}
}}
fn syscall_write(_: FdEntry, buffer: *const c_void, length: usize) -> Result<isize, i32> {{
    assert_eq!(unsafe {{ std::slice::from_raw_parts(buffer.cast::<u8>(), length) }}, b"abcDEFG");
    assert_eq!(ALLOCATIONS.lock().unwrap().len(), usize::from(CASE.load(Ordering::Relaxed) != 5));
    escape_if_requested();
    PENDING.store(1, Ordering::Release);
    if CASE.load(Ordering::Relaxed) == 9 {{return Ok(3)}}
    Err(EINTR)
}}
fn syscall_read(_: FdEntry, _: *mut c_void, length: usize) -> Result<isize, i32> {{
    assert_eq!(length, 7);
    assert_eq!(ALLOCATIONS.lock().unwrap().len(), usize::from(CASE.load(Ordering::Relaxed) != 6));
    escape_if_requested();
    PENDING.store(1, Ordering::Release);
    Err(EINTR)
}}
#[path = "{root_dir}/user/crates/posix-client/src/io_vector.rs"] pub mod io_vector;
#[path = "{root_dir}/user/crates/posix-client/src/upcall_guard.rs"] pub mod upcall_guard;
#[path = "{root_dir}/user/crates/newlib-runtime/src/callback_resources.rs"] mod callback_resources;
#[path = "{root_dir}/user/crates/newlib-runtime/src/io_resources.rs"] mod io_resources;
"#,
        root_dir = root.canonicalize().unwrap().display()
    );
    for entry in [
        "fn vector_errno(",
        "struct VectorBuffer {",
        "impl VectorBuffer {",
        "impl Drop for VectorBuffer {",
        "fn finish_io_cancellation(",
        "pub extern \"C\" fn _read(",
        "pub extern \"C\" fn _write(",
        "pub extern \"C\" fn pread(",
        "pub extern \"C\" fn pwrite(",
        "pub unsafe extern \"C\" fn writev(",
        "pub unsafe extern \"C\" fn readv(",
    ] {
        let start = runtime.find(entry).unwrap();
        let end = start + runtime[start..].find("\n}\n").unwrap() + 3;
        program.push_str(&runtime[start..end]);
    }
    program.push_str(
        r#"
extern "C" fn operation(case: u32) {
    if case >= 12 {
        let mut bytes = [0u8;7];
        if case % 4 == 0 {PENDING.store(1,Ordering::Release);}
        let result = if case < 16 { pread(3,bytes.as_mut_ptr().cast(),7,11) }
                     else { pwrite(3,bytes.as_ptr().cast(),7,11) };
        assert_eq!(result,3); assert_eq!(CHECKS.load(Ordering::Relaxed),1);
        return;
    }
    if case >= 7 {
        let vectors = [IoVec { iov_base:b"abcDEFG".as_ptr().cast(), iov_len:7 }];
        let result = unsafe { writev(3, vectors.as_ptr(), 1) };
        assert_eq!(result, if case == 9 {3} else {-1});
        assert_eq!(CHECKS.load(Ordering::Relaxed), if case == 9 {1} else {2});
        return;
    }
    if case == 2 {
        PENDING.store(1, Ordering::Release);
        assert_eq!(finish_io_cancellation(17), 17);
        assert_eq!(CHECKS.load(Ordering::Acquire), 0);
        finish_io_cancellation(0);
    } else if case == 0 || case == 3 {
        let vectors = [IoVec { iov_base: b"abc".as_ptr().cast(), iov_len: 3 },
                       IoVec { iov_base: b"DEFG".as_ptr().cast(), iov_len: 4 }];
        unsafe { writev(3, vectors.as_ptr(), 2) };
    } else if case == 1 || case == 4 {
        let mut first = [0u8; 3]; let mut second = [0u8; 4];
        let vectors = [IoVecMut { iov_base: first.as_mut_ptr().cast(), iov_len: 3 },
                       IoVecMut { iov_base: second.as_mut_ptr().cast(), iov_len: 4 }];
        unsafe { readv(3, vectors.as_ptr(), 2) };
    } else if case == 5 {
        _write(3, b"abcDEFG".as_ptr().cast(), 7);
    } else {
        let mut bytes = [0u8;7]; _read(3,bytes.as_mut_ptr().cast(),7);
    }
    panic!("cancellation point returned");
}
fn main() {
    let case: u32 = std::env::args().nth(1).unwrap().parse().unwrap();
    CASE.store(case, Ordering::Release);
    if (3..=6).contains(&case) {
        assert_eq!(unsafe { mochios_test_io_escape(operation, case) }, 73);
        assert_eq!(PINS.load(Ordering::Relaxed), 0);
        assert!(ALLOCATIONS.lock().unwrap().is_empty(), "nonlocal exit leaked allocation");
        assert!(CONTROL.callback_resources.is_empty());
        assert_eq!(CONTROL.native.load(Ordering::Relaxed), 0);
    } else {
        operation(case);
        assert_eq!(PINS.load(Ordering::Relaxed), 0);
        assert!(ALLOCATIONS.lock().unwrap().is_empty());
        assert!(CONTROL.callback_resources.is_empty());
        assert_eq!(PENDING.load(Ordering::Relaxed), u32::from(matches!(case, 9 | 14 | 18)));
    }
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
    let _cleanup = TemporaryDirectory(directory.clone());
    let executable = directory.join("probe");
    let trampoline = directory.join("escape.o");
    let compiled_c = Command::new("cc")
        .args(["-Wall", "-Wextra", "-Werror", "-c"])
        .arg(root.join("services/posix/tests/runtime_io_escape.c"))
        .arg("-o")
        .arg(&trampoline)
        .output()
        .unwrap();
    assert!(
        compiled_c.status.success(),
        "{}",
        String::from_utf8_lossy(&compiled_c.stderr)
    );
    let mut compiler = Command::new("rustc")
        .args(["--edition=2021", "-Awarnings", "-"])
        .arg(format!("-Clink-arg={}", trampoline.display()))
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
    for case in (0..10).chain(12..20) {
        let executed = Command::new(&executable)
            .arg(case.to_string())
            .output()
            .unwrap();
        assert_eq!(
            executed.status.code(),
            Some(if matches!(case, 0..=2 | 12 | 13 | 15 | 16 | 17 | 19) {
                73
            } else {
                0
            }),
            "case {case}: {}",
            String::from_utf8_lossy(&executed.stderr)
        );
    }
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
    assert!(
        stream.find("io_cancellation_requested(control)").unwrap()
            < stream.find("operation()").unwrap()
    );
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
