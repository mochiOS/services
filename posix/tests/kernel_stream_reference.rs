use std::io::Write;
use std::process::{Command, Stdio};

#[test]
fn actual_native_stream_references_share_options_and_close_only_at_last_reference() {
    let source = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../core/src/task/fd_table.rs")
        .canonicalize()
        .unwrap();
    let mut program = String::from(
        r#"
extern crate alloc;
extern crate self as mnu_abi;
pub const HANDLE_OPTION_NONBLOCKING: u64 = 1;
use std::sync::atomic::{AtomicUsize, Ordering};
static READ_CLOSED: AtomicUsize = AtomicUsize::new(0);
static WRITE_CLOSED: AtomicUsize = AtomicUsize::new(0);
mod vfs { pub struct Vnode; }
mod interrupt { pub mod spinlock {
    pub struct SpinLock<T>(std::sync::Mutex<T>);
    impl<T> SpinLock<T> {
        pub fn new(value: T) -> Self { Self(std::sync::Mutex::new(value)) }
        pub fn lock(&self) -> std::sync::MutexGuard<'_, T> { self.0.lock().unwrap() }
    }
} }
mod syscall { pub mod fs {
    pub fn close_pipe_endpoint_from_kernel(stream: usize, write: bool) {
        assert_eq!(stream, 42);
        if write { crate::WRITE_CLOSED.fetch_add(1, crate::Ordering::Relaxed); }
        else { crate::READ_CLOSED.fetch_add(1, crate::Ordering::Relaxed); }
    }
} }
"#,
    );
    program.push_str(&format!("#[path = {source:?}] mod objects;\n"));
    program.push_str(
        r#"
fn main() {
    use objects::{FileHandle, FileHandleCap};
    let reader = FileHandle::new_pipe_read(42);
    let duplicate = reader.duplicate();
    let writer = FileHandle::new_pipe_write(42);
    assert!(std::sync::Arc::ptr_eq(&reader.open, &duplicate.open));
    assert!(!std::sync::Arc::ptr_eq(&reader.open, &writer.open));
    assert_eq!(reader.stream_endpoint(), Some((42, false)));
    assert_eq!(writer.stream_endpoint(), Some((42, true)));
    assert!(reader.cap.contains(FileHandleCap::READ));
    assert!(!reader.cap.contains(FileHandleCap::WRITE));
    assert!(writer.cap.contains(FileHandleCap::WRITE));
    assert!(!writer.cap.contains(FileHandleCap::READ));
    assert_eq!(reader.cap, duplicate.cap);
    reader.open.lock().io_options = HANDLE_OPTION_NONBLOCKING;
    assert_eq!(duplicate.open.lock().io_options, HANDLE_OPTION_NONBLOCKING);
    assert_eq!(writer.open.lock().io_options, 0);
    drop(reader);
    assert_eq!(READ_CLOSED.load(Ordering::Relaxed), 0);
    assert_eq!(WRITE_CLOSED.load(Ordering::Relaxed), 0);
    drop(duplicate);
    assert_eq!(READ_CLOSED.load(Ordering::Relaxed), 1);
    assert_eq!(WRITE_CLOSED.load(Ordering::Relaxed), 0);
    drop(writer);
    assert_eq!(READ_CLOSED.load(Ordering::Relaxed), 1);
    assert_eq!(WRITE_CLOSED.load(Ordering::Relaxed), 1);
}
"#,
    );
    let directory = std::env::temp_dir().join(format!(
        "mochios-stream-reference-{}-{}",
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
