//! Run logger's directory branch with real native error encoding and mock IPC.
#[path = "support/native_error_probe.rs"]
mod probe;

#[test]
fn logger_creates_only_missing_directories_and_preserves_other_failures() {
    let source = include_str!("../../logger/src/posix_io.rs");
    let start = source.find("pub fn ensure_directory(").unwrap();
    let end = start + source[start..].find("\npub fn append_and_sync(").unwrap();
    let mut program = probe::program();
    program.push_str(r#"
use std::cell::{Cell, RefCell};
use mochios_posix_protocol as posix;
enum StatAtBase { ProcessRoot }
enum OpenAtBase { ProcessRoot }
struct Status { mode: u32 }
struct Client;
thread_local! {
    static STAT: Cell<Result<u32, SysError>> = const { Cell::new(Ok(0x4000)) };
    static MKDIR: Cell<Result<(), SysError>> = const { Cell::new(Ok(())) };
    static EVENTS: RefCell<Vec<&'static str>> = const { RefCell::new(Vec::new()) };
}
fn sys_error(raw: u64) -> SysError { SysError::from_raw(raw as i64) }
fn with_client<T>(operation: impl FnOnce(&Client) -> Result<T, SysError>) -> Result<T, SysError> { operation(&Client) }
impl Client {
    fn stat_at(&self, _: StatAtBase, flags: u32, path: &str) -> Result<Status, SysError> {
        assert_eq!(flags, 0); assert_eq!(path, "/var/log");
        EVENTS.with_borrow_mut(|events| events.push("stat"));
        STAT.get().map(|mode| Status { mode })
    }
    fn mkdir_at(&self, _: OpenAtBase, mode: u32, path: &str) -> Result<(), SysError> {
        assert_eq!(mode, 0o750); assert_eq!(path, "/var/log");
        EVENTS.with_borrow_mut(|events| events.push("mkdir"));
        MKDIR.get()
    }
}
fn run(stat: Result<u32, SysError>, mkdir: Result<(), SysError>, expected: Result<(), SysError>, events: &[&str]) {
    STAT.set(stat); MKDIR.set(mkdir); EVENTS.with_borrow_mut(Vec::clear);
    assert_eq!(ensure_directory("/var/log", 0o750), expected);
    EVENTS.with_borrow(|actual| assert_eq!(actual.as_slice(), events));
}
"#);
    program.push_str(&source[start..end]);
    program.push_str(r#"
fn main() {
    run(Ok(0x4000 | 0o755), Err(sys_error(EIO)), Ok(()), &["stat"]);
    for mode in [0x8000 | 0o644, 0xa000 | 0o777, 0] {
        run(Ok(mode), Ok(()), Err(sys_error(posix::STATUS_ENOTDIR as u64)), &["stat"]);
    }
    run(Err(sys_error(ENOENT)), Ok(()), Ok(()), &["stat", "mkdir"]);
    for status in [EACCES, EIO, EAGAIN] {
        run(Err(sys_error(status)), Ok(()), Err(sys_error(status)), &["stat"]);
    }
    for status in [EACCES, EIO, (-17_i64) as u64, NativeError::AlreadyExists.into_raw()] {
        run(Err(sys_error(ENOENT)), Err(sys_error(status)), Err(sys_error(status)), &["stat", "mkdir"]);
    }
}
"#);
    probe::run(&program);
}
