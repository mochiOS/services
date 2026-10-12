use std::io::Write;
use std::process::{Command, Stdio};

#[test]
fn production_state_transition_defers_pending_request_and_exit_disables_cleanup_reentry() {
    let source = include_str!("../../../user/crates/newlib-runtime/src/lib.rs");
    let mut program = String::from(
        r#"
use std::ffi::c_void;
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
type c_int = i32;
const EINVAL: i32 = 22;
const EAGAIN: i32 = 11;
const PTHREAD_CANCEL_ENABLE: u32 = 0;
const PTHREAD_CANCEL_DISABLE: u32 = 1;
const PTHREAD_CANCEL_DEFERRED: u32 = 0;
const THREAD_EXITED: u32 = 3;
struct ThreadControl {
    cancel_state: AtomicU32, cancel_type: AtomicU32, cancel_pending: AtomicU32,
    result: AtomicUsize, state: AtomicU32,
}
static CONTROL: ThreadControl = ThreadControl {
    cancel_state: AtomicU32::new(PTHREAD_CANCEL_ENABLE),
    cancel_type: AtomicU32::new(PTHREAD_CANCEL_DEFERRED), cancel_pending: AtomicU32::new(0),
    result: AtomicUsize::new(0), state: AtomicU32::new(2),
};
static AFTER_ENABLE: AtomicU32 = AtomicU32::new(0);
static DESTRUCTOR_RETURNED: AtomicU32 = AtomicU32::new(0);
fn register_current_thread() -> Option<((), &'static ThreadControl)> { Some(((), &CONTROL)) }
fn current_thread_control() -> Option<((), &'static ThreadControl)> { Some(((), &CONTROL)) }
fn native_mutex_wake_all(_: &AtomicU32) {}
fn run_thread_specific_destructors(control: &ThreadControl) {
    assert_eq!(control.cancel_state.load(Ordering::Acquire), PTHREAD_CANCEL_DISABLE);
    assert_eq!(control.cancel_type.load(Ordering::Acquire), PTHREAD_CANCEL_DEFERRED);
    pthread_testcancel(); // Must return rather than recursively exiting.
    DESTRUCTOR_RETURNED.store(1, Ordering::Release);
}
mod syscall {
    use super::*;
    pub enum SyscallNumber { ThreadExit }
    pub fn raw_syscall1(_: SyscallNumber, _: u64) -> u64 {
        assert_eq!(AFTER_ENABLE.load(Ordering::Acquire), 1);
        assert_eq!(DESTRUCTOR_RETURNED.load(Ordering::Acquire), 1);
        assert_eq!(CONTROL.state.load(Ordering::Acquire), THREAD_EXITED);
        assert_eq!(CONTROL.result.load(Ordering::Acquire), usize::MAX);
        std::process::exit(0)
    }
}
"#,
    );
    for entry in [
        "fn finish_thread(",
        "pub unsafe extern \"C\" fn pthread_setcancelstate(",
        "pub extern \"C\" fn pthread_testcancel(",
    ] {
        let start = source.find(entry).unwrap();
        let end = source[start..].find("\n}\n").unwrap() + start + 3;
        program.push_str(&source[start..end]);
    }
    program.push_str(
        r#"
fn main() {
    let mut previous = 99;
    assert_eq!(unsafe { pthread_setcancelstate(99, &mut previous) }, EINVAL);
    assert_eq!(previous, 99);
    assert_eq!(unsafe { pthread_setcancelstate(1, &mut previous) }, 0);
    assert_eq!(previous, 0);
    CONTROL.cancel_pending.store(1, Ordering::Release);
    pthread_testcancel();
    assert_eq!(CONTROL.cancel_pending.load(Ordering::Acquire), 1);
    assert_eq!(unsafe { pthread_setcancelstate(0, &mut previous) }, 0);
    assert_eq!(previous, 1);
    assert_eq!(CONTROL.cancel_pending.load(Ordering::Acquire), 1);
    AFTER_ENABLE.store(1, Ordering::Release);
    pthread_testcancel();
    panic!("explicit cancellation point returned");
}
"#,
    );
    let directory = std::env::temp_dir().join(format!(
        "mochios-deferred-cancel-{}-{}",
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
    std::fs::remove_dir_all(directory).unwrap();
    assert!(
        executed.status.success(),
        "{}",
        String::from_utf8_lossy(&executed.stderr)
    );
}
