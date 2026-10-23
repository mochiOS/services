use std::io::Write;
use std::process::{Command, Stdio};

#[test]
fn production_state_transition_defers_pending_request_and_exit_disables_cleanup_reentry() {
    let source = include_str!("../../../user/crates/newlib-runtime/src/lib.rs");
    let mut program = String::from(
        r#"
use std::ffi::c_void;
use std::sync::atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering};
type c_int = i32;
const EINVAL: i32 = 22;
const EAGAIN: i32 = 11;
const EOVERFLOW: i32 = 139;
const PTHREAD_CANCEL_ENABLE: u32 = 0;
const PTHREAD_CANCEL_DISABLE: u32 = 1;
const PTHREAD_CANCEL_DEFERRED: u32 = 0;
const THREAD_EXITED: u32 = 3;
struct ThreadControl {
    cancel_state: AtomicU32, cancel_type: AtomicU32, cancel_pending: AtomicU32,
    result: AtomicUsize, state: AtomicU32, cleanup_head: AtomicUsize,
    native_delivery_defer: AtomicU32, callback_resources: callback_resources::Chain,
    native_id: AtomicU64,
}
static CONTROL: ThreadControl = ThreadControl {
    cancel_state: AtomicU32::new(PTHREAD_CANCEL_ENABLE),
    cancel_type: AtomicU32::new(PTHREAD_CANCEL_DEFERRED), cancel_pending: AtomicU32::new(0),
    result: AtomicUsize::new(0), state: AtomicU32::new(2), cleanup_head: AtomicUsize::new(0),
    native_delivery_defer: AtomicU32::new(0), callback_resources: callback_resources::Chain::new(),
    native_id: AtomicU64::new(17),
};
static AFTER_ENABLE: AtomicU32 = AtomicU32::new(0);
static DESTRUCTOR_RETURNED: AtomicU32 = AtomicU32::new(0);
static RESOURCES_DROPPED: AtomicU32 = AtomicU32::new(0);
static TIMERS_RETIRED: AtomicU32 = AtomicU32::new(0);
static CLOCKS_RETIRED: AtomicU32 = AtomicU32::new(0);
struct Clocks;
impl Clocks {
    fn retire_native(&mut self,owner:u64) {
        assert_eq!(owner,17);
        assert_eq!(DESTRUCTOR_RETURNED.load(Ordering::Acquire),1);
        assert_eq!(CONTROL.native_delivery_defer.load(Ordering::Acquire),1);
        assert_ne!(CONTROL.state.load(Ordering::Acquire),THREAD_EXITED);
        assert_eq!(CLOCKS_RETIRED.fetch_add(1,Ordering::AcqRel),0);
    }
}
struct RuntimeState {thread_clocks:Clocks}
static STATE:std::sync::Mutex<RuntimeState>=std::sync::Mutex::new(RuntimeState{thread_clocks:Clocks});
fn state()->std::sync::MutexGuard<'static,RuntimeState>{STATE.lock().unwrap()}
fn defer_native_delivery()->Option<upcall_guard::Guard<'static>> {
    upcall_guard::Guard::enter(&CONTROL.native_delivery_defer)
}
mod process_timer {
    use super::*;
    pub fn thread_exit(owner:u64, publish_exit:impl FnOnce()) {
        assert_eq!(owner,17);
        assert_eq!(DESTRUCTOR_RETURNED.load(Ordering::Acquire),1);
        assert_eq!(CONTROL.native_delivery_defer.load(Ordering::Acquire),1);
        assert_ne!(CONTROL.state.load(Ordering::Acquire),THREAD_EXITED);
        assert_eq!(TIMERS_RETIRED.fetch_add(1,Ordering::AcqRel),0);
        let mut state=state();
        state.thread_clocks.retire_native(owner);
        publish_exit();
    }
}
mod timer_callbacks { pub fn finish_if_last_application() {} }
struct Resource;
impl Drop for Resource {
    fn drop(&mut self) {
        assert_eq!(CONTROL.native_delivery_defer.load(Ordering::Acquire), 1);
        assert_eq!(CONTROL.cancel_state.load(Ordering::Acquire), PTHREAD_CANCEL_DISABLE);
        assert_eq!(RESOURCES_DROPPED.fetch_add(1, Ordering::AcqRel), 0);
    }
}
fn process_exit(error:c_int)->! {panic!("unexpected process exit {error}")}
fn register_current_thread() -> Option<((), &'static ThreadControl)> { Some(((), &CONTROL)) }
fn current_thread_control() -> Option<((), &'static ThreadControl)> { Some(((), &CONTROL)) }
mod user_copy {
    pub fn write(destination:*mut u8, bytes:&[u8])->Result<(),i32> {
        assert_eq!(super::CONTROL.native_delivery_defer.load(super::Ordering::Acquire),1);
        unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(),destination,bytes.len()); }
        Ok(())
    }
}
fn native_mutex_wake_all(_: &AtomicU32) {}
fn notify_join_waiter(_: &ThreadControl) {}
mod thread_cleanup {
    use super::*;
    pub unsafe fn drain(head: &AtomicUsize) {
        assert_eq!(head.load(Ordering::Acquire), 0);
        assert_eq!(RESOURCES_DROPPED.load(Ordering::Acquire), 1);
        assert!(CONTROL.callback_resources.is_empty());
        assert_eq!(CONTROL.native_delivery_defer.load(Ordering::Acquire), 0);
    }
}
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
        assert_eq!(RESOURCES_DROPPED.load(Ordering::Acquire), 1);
        assert_eq!(TIMERS_RETIRED.load(Ordering::Acquire), 1);
        assert_eq!(CLOCKS_RETIRED.load(Ordering::Acquire), 1);
        std::process::exit(0)
    }
}
"#,
    );
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap();
    program.push_str(&format!(
        "extern crate self as mochios_posix_client;\n#[path={:?}]pub mod upcall_guard;\n#[path={:?}]mod callback_resources;\n",
        root.join("user/crates/posix-client/src/upcall_guard.rs"),
        root.join("user/crates/newlib-runtime/src/callback_resources.rs"),
    ));
    for entry in [
        "fn finish_thread(",
        "fn update_cancel_control(",
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
    let mut resource=core::pin::pin!(callback_resources::Scope::new(&CONTROL.callback_resources,1,Resource));
    {
        let _guard=upcall_guard::Guard::enter(&CONTROL.native_delivery_defer).unwrap();
        unsafe{resource.as_mut().activate()};
    }
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
