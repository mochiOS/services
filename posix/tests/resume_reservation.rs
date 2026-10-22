//! Execute the actual resume transition with allocation failure at admission.
#[allow(dead_code)]
#[path = "support/native_error_probe.rs"]
mod probe;

#[test]
fn notification_storage_is_reserved_before_native_resume_and_retry_keeps_ownership() {
    let service = include_str!("../src/lib.rs");
    let mut program = String::from(
        r#"
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
static FAIL: AtomicBool = AtomicBool::new(false);
static AFTER_RESUME: AtomicBool = AtomicBool::new(false);
static RESUMES: AtomicU32 = AtomicU32::new(0);
struct Allocator;
unsafe impl std::alloc::GlobalAlloc for Allocator {
    unsafe fn alloc(&self, layout: std::alloc::Layout) -> *mut u8 {
        if FAIL.swap(false, Ordering::Relaxed) || AFTER_RESUME.load(Ordering::Relaxed) {
            std::ptr::null_mut()
        } else {
            unsafe { std::alloc::System.alloc(layout) }
        }
    }
    unsafe fn dealloc(&self, pointer: *mut u8, layout: std::alloc::Layout) {
        unsafe { std::alloc::System.dealloc(pointer, layout) }
    }
}
#[global_allocator] static ALLOCATOR: Allocator = Allocator;
mod protocol { pub const STATUS_ESRCH: i32 = -3; pub const STATUS_ENOMEM: i32 = -12; }
enum ProcessLifecycle { Running, Exited { exit_code: u64 } }
trait ProcessBackend<H: Copy> {
    fn status(&mut self, handle: H) -> Result<ProcessLifecycle, i32>;
    fn resume(&mut self, handle: H) -> Result<(), i32>;
}
struct Backend;
impl ProcessBackend<u32> for Backend {
    fn status(&mut self, handle: u32) -> Result<ProcessLifecycle, i32> {
        assert_eq!(handle, 42);
        Ok(ProcessLifecycle::Running)
    }
    fn resume(&mut self, handle: u32) -> Result<(), i32> {
        assert_eq!(handle, 42);
        RESUMES.fetch_add(1, Ordering::Relaxed);
        AFTER_RESUME.store(true, Ordering::Relaxed);
        Ok(())
    }
}
struct State {
    stopped: bool, stop_reported: bool, continued_pending: bool, resume_continued: bool,
}
impl State {
"#,
    );
    program.push_str(probe::between(
        service,
        "    fn continued(",
        "    fn begin_delivery(",
    ));
    program.push_str(
        r#"
}
struct PosixService<H: Copy> {
    processes: BTreeMap<u64, H>,
    process_resume_notifications: BTreeSet<u64>,
    process_wait_states: BTreeMap<u64, State>,
    deferred_child_notifications: VecDeque<u64>,
}
impl<H: Copy> PosixService<H> {
    fn prepare_child_resume(&self, process: u64) -> Result<Option<u64>, i32> {
        assert_eq!(process, 7);
        Ok(Some(99))
    }
"#,
    );
    program.push_str(probe::between(
        service,
        "    pub fn apply_process_resume<",
        "    fn enqueue_signal(",
    ));
    program.push_str(
        r#"
}
fn main() {
    let mut service = PosixService {
        processes: BTreeMap::from([(7, 42)]),
        process_resume_notifications: BTreeSet::from([7]),
        process_wait_states: BTreeMap::from([(7, State {
            stopped: true, stop_reported: true, continued_pending: false, resume_continued: true,
        })]),
        deferred_child_notifications: VecDeque::new(),
    };
    FAIL.store(true, Ordering::Relaxed);
    let result = service.apply_process_resume(7, &mut Backend);
    assert!(!FAIL.load(Ordering::Relaxed));
    assert_eq!(result, Err(protocol::STATUS_ENOMEM));
    assert_eq!(RESUMES.load(Ordering::Relaxed), 0);
    assert!(service.process_resume_notifications.contains(&7));
    let state = &service.process_wait_states[&7];
    assert!(state.stopped && state.stop_reported && state.resume_continued);
    assert!(!state.continued_pending);
    assert!(service.deferred_child_notifications.is_empty());
    let result = service.apply_process_resume(7, &mut Backend);
    AFTER_RESUME.store(false, Ordering::Relaxed);
    assert_eq!(result, Ok(true));
    assert_eq!(RESUMES.load(Ordering::Relaxed), 1);
    assert!(service.process_resume_notifications.is_empty());
    assert_eq!(service.deferred_child_notifications.len(), 1);
    assert_eq!(service.deferred_child_notifications.front(), Some(&99));
    let state = &service.process_wait_states[&7];
    assert!(!state.stopped && !state.resume_continued);
    assert!(state.continued_pending);
}
"#,
    );
    probe::run(&program);
}
