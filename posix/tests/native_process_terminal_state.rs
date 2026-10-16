//! Execute the kernel's publication/termination bodies on the host. Only the
//! surrounding process table, scheduler and revocation backend are substituted.
use std::io::Write;
use std::process::{Command, Stdio};

struct TemporaryDirectory(std::path::PathBuf);
impl Drop for TemporaryDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn body<'a>(source: &'a str, signature: &str, indent: &str) -> &'a str {
    let start = source.find(signature).unwrap();
    let end = start + source[start..].find(&format!("\n{indent}}}")).unwrap();
    &source[start..end + indent.len() + 2]
}

#[test]
fn terminal_publication_is_immutable_and_termination_reports_the_winner() {
    let process = include_str!("../../../core/src/task/process.rs");
    let handles = include_str!("../../../core/src/syscall/handle.rs");
    let threads = include_str!("../../../core/src/task/thread.rs");
    let scheduler = include_str!("../../../core/src/task/scheduler.rs");
    let mut program = String::from(
        r#"
extern crate alloc;
use std::sync::{Arc, Barrier, Mutex, MutexGuard};
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, AtomicUsize, Ordering};
type ProcessId = u64;
type ThreadId = u64;
mod mnu_abi { pub const PROCESS_STATE_RUNNING: u64 = 1; pub const PROCESS_STATE_EXITED: u64 = 2; }
#[macro_export] macro_rules! warn { ($($arg:tt)*) => {{ let _ = format_args!($($arg)*); }}; }
"#,
    );
    program.push_str(body(process, "pub struct ProcessObject {", ""));
    program.push('\n');
    // pub(super) on note_cpu_tick requires a module parent.
    program.push_str(
        body(process, "impl ProcessObject {", "")
            .replace("pub(super)", "pub")
            .as_str(),
    );
    program.push_str(
        r#"
#[derive(Debug, PartialEq)] enum ProcessState { Running, Zombie }
struct Process { state: ProcessState, exit_code: Option<u64>, object: Arc<ProcessObject> }
impl Process {
    fn process_object(&self) -> Arc<ProcessObject> { self.object.clone() }
    fn resource_limits(&self) -> Limits { Limits { max_threads: 64 } }
"#,
    );
    program.push_str(body(process, "pub fn mark_exited(&mut self,", "    "));
    program.push_str(
        r#"
}
struct Table(Option<Process>);
impl Table {
    fn get_mut(&mut self, id: ProcessId) -> Option<&mut Process> {
        self.0.as_mut().filter(|p| p.object.id() == id)
    }
}
struct LockedTable(Mutex<Table>);
impl LockedTable { fn lock(&self) -> MutexGuard<'_, Table> { self.0.lock().unwrap() } }
static PROCESS_TABLE: LockedTable = LockedTable(Mutex::new(Table(None)));
static WAKES: AtomicUsize = AtomicUsize::new(0);
static RECLAIMS: AtomicUsize = AtomicUsize::new(0);
static CLEANUPS: AtomicUsize = AtomicUsize::new(0);
static TERMINATED: AtomicUsize = AtomicUsize::new(0);
static CASE: AtomicUsize = AtomicUsize::new(0);
static YIELDS: AtomicUsize = AtomicUsize::new(0);
static CPU_REFERENCE: AtomicU64 = AtomicU64::new(0);
static NATURAL_RACE: AtomicBool = AtomicBool::new(false);
struct Limits { max_threads: usize }
mod audit { pub enum AuditEventKind { Fault } pub fn log(_: AuditEventKind, _: &str) {} }
#[derive(Clone, Copy, PartialEq)] enum ThreadState { Running, Ready, Terminated }
struct Thread { id: u64, state: ThreadState, process_object: Option<Arc<ProcessObject>> }
impl Thread {
    fn id(&self) -> u64 { self.id }
    fn state(&self) -> ThreadState { self.state }
    fn process_id(&self) -> u64 { self.process_object.as_ref().unwrap().id() }
    fn kernel_stack_base(&self) -> u64 { self.id * 4096 }
    fn is_scheduling_suspended(&self) -> bool { false }
}
struct ThreadQueue {
    threads: [Option<Thread>; 64], count: usize, slot_generations: [u64; 64], ready_bitmap: u64, rr_cursor: usize,
}
impl ThreadQueue {
    const MAX_THREADS: usize = 64;
    const fn new() -> Self { Self { threads: [const { None }; 64], count: 0, slot_generations: [0; 64], ready_bitmap: 0, rr_cursor: 0 } }
    fn get(&self, id: u64) -> Option<&Thread> { self.iter().find(|t| t.id == id) }
    fn iter(&self) -> impl Iterator<Item=&Thread> { self.threads.iter().filter_map(Option::as_ref) }
    fn set_state(&mut self, id: u64, state: ThreadState) {
        self.threads.iter_mut().filter_map(Option::as_mut).find(|t| t.id == id).unwrap().state = state;
    }
    fn remove(&mut self, id: u64) -> Option<Thread> {
        let slot = self.threads.iter_mut().find(|t| t.as_ref().is_some_and(|t| t.id == id))?;
        let removed = slot.take(); self.count -= 1; removed
    }
}
struct LockedQueue(Mutex<ThreadQueue>);
impl LockedQueue { fn lock(&self) -> MutexGuard<'_, ThreadQueue> { self.0.lock().unwrap() } }
static THREAD_QUEUE: LockedQueue = LockedQueue(Mutex::new(ThreadQueue::new()));
fn wake_process_exit_waiters(_: u64) { WAKES.fetch_add(1, Ordering::Relaxed); }
fn defer_process_reclaim(_: u64) { RECLAIMS.fetch_add(1, Ordering::Relaxed); }
"#,
    );
    program.push_str("impl ThreadQueue {\n");
    program.push_str(body(threads, "pub fn push(&mut self,", "    "));
    program.push_str("\n}\n");
    program.push_str(body(process, "pub fn mark_process_exited(", ""));
    program.push_str(
        r#"
const SUCCESS: u64 = 0;
const ESRCH: u64 = mnu_abi::status::Error::NotFound.into_raw();
const EBADF: u64 = mnu_abi::status::Error::InvalidArgument.into_raw();
const EACCES: u64 = mnu_abi::status::Error::AccessDenied.into_raw();
const EAGAIN: u64 = mnu_abi::status::Error::NotReady.into_raw();
struct HandleRights;
impl HandleRights { const SIGNAL: Self = Self; }
enum KernelObject { Process(Arc<ProcessObject>), Other }
fn object_native(raw: u64, _: HandleRights) -> Result<KernelObject, mnu_abi::status::Error> {
    match raw {
        0 => Err(mnu_abi::status::Error::AccessDenied),
        1 => Ok(KernelObject::Other),
        _ => {
            if CASE.load(Ordering::Relaxed) == 1 { NATURAL_RACE.store(true, Ordering::Relaxed); }
            Ok(KernelObject::Process(Arc::clone(&PROCESS_TABLE.lock().0.as_ref().unwrap().object)))
        }
    }
}
mod syscall { pub mod security { pub fn current_process_id() -> Option<u64> { None } } }
mod percpu { pub fn thread_is_cpu_referenced(id: u64) -> bool { crate::CPU_REFERENCE.load(crate::Ordering::Acquire) == id } }
impl ThreadIdExt for u64 { fn as_u64(self) -> u64 { self } }
trait ThreadIdExt { fn as_u64(self) -> u64; }
mod syscall_address_wait { pub fn remove_waiter(_: u64) {} }
mod task {
    use super::*;
    pub use super::mark_process_exited;
    pub fn with_process<R>(id: u64, f: impl FnOnce(&Process) -> R) -> Option<R> {
        let result = PROCESS_TABLE.lock().0.as_ref().filter(|p| p.object.id() == id).map(f);
        if NATURAL_RACE.swap(false, Ordering::Relaxed) {
            let object = PROCESS_TABLE.lock().0.as_ref().unwrap().object.clone();
            assert!(object.begin_termination()); assert!(mark_process_exited(id, 42));
        }
        result
    }
    pub fn for_each_thread(mut f: impl FnMut(&Thread)) { for thread in THREAD_QUEUE.lock().iter() { f(thread); } }
    pub fn with_thread<R>(id: u64, f: impl FnOnce(&Thread) -> R) -> Option<R> { THREAD_QUEUE.lock().get(id).map(f) }
    pub fn free_kernel_stack(_: u64) {}
    pub fn release_process_borrowed_mappings(id: u64) -> Result<(), u64> {
        CLEANUPS.fetch_add(1, Ordering::Relaxed);
        if CASE.load(Ordering::Relaxed) == 2 { Err(12) } else { Ok(()) }
    }
    pub mod thread {
        use super::*;
        fn clear_thread_wait_registrations(_: u64) {}
"#,
    );
    program.push_str(
        &body(threads, "pub(super) fn begin_thread_exit(", "").replace("pub(super)", "pub"),
    );
    program.push_str(
        &body(
            threads,
            "pub(super) fn remove_quiescent_terminated_thread(",
            "",
        )
        .replace("pub(super)", "pub"),
    );
    program.push_str(
        r#"
    }
    pub mod scheduler {
        use super::*;
        pub fn exit_current_process(_: i32) -> ! { unreachable!() }
        fn terminate_thread(id: u64) {
            let mut queue = THREAD_QUEUE.lock();
            if queue.get(id).is_some() { queue.set_state(id, ThreadState::Terminated); }
            TERMINATED.fetch_add(1, Ordering::Relaxed);
        }
        fn yield_now() {
            assert!(!PROCESS_TABLE.lock().0.as_ref().unwrap().object.is_exited());
            YIELDS.fetch_add(1, Ordering::Relaxed);
            CPU_REFERENCE.store(0, Ordering::Release);
        }
"#,
    );
    program.push_str(
        &body(scheduler, "pub(crate) fn retire_process_threads(", "")
            .replace("super::thread::ThreadQueue", "crate::ThreadQueue")
            .replace(
                "crate::syscall::address_wait",
                "crate::syscall_address_wait",
            ),
    );
    program.push_str(
        r#"
    }
}
"#,
    );
    program = program.replace(
        "mod mnu_abi {",
        &format!(
            "mod mnu_abi {{pub mod status {{\n{}\n}}\n",
            include_str!("../../../core/crates/abi/src/status.rs")
        ),
    );
    program.push_str(body(handles, "pub fn process_terminate(", ""));
    program.push_str(
        r#"
fn reset(case: usize) -> Arc<ProcessObject> {
    CASE.store(case, Ordering::Relaxed);
    NATURAL_RACE.store(false, Ordering::Relaxed);
    for counter in [&WAKES, &RECLAIMS, &CLEANUPS, &TERMINATED] { counter.store(0, Ordering::Relaxed); }
    let object = Arc::new(ProcessObject::new(7));
    YIELDS.store(0, Ordering::Relaxed);
    CPU_REFERENCE.store(2, Ordering::Release);
    PROCESS_TABLE.lock().0 = Some(Process { state: ProcessState::Running, exit_code: None, object: object.clone() });
    let mut queue = THREAD_QUEUE.lock(); *queue = ThreadQueue::new();
    for id in 1..=2 { assert_eq!(queue.push(Thread { id, state: ThreadState::Running, process_object: Some(object.clone()) }), Some(id)); }
    object
}
fn terminal(object: &ProcessObject, code: u64) {
    assert!(object.is_exited());
    assert_eq!(object.exit_code(), code);
    let table = PROCESS_TABLE.lock();
    let process = table.0.as_ref().unwrap();
    assert_eq!(process.state, ProcessState::Zombie);
    assert_eq!(process.exit_code, Some(code));
    assert_eq!(WAKES.load(Ordering::Relaxed), 1);
    assert_eq!(RECLAIMS.load(Ordering::Relaxed), 1);
}
#[test] fn zero_is_a_real_terminal_code() {
    let object = reset(0);
    assert!(mark_process_exited(7, 0));
    assert!(!mark_process_exited(7, 137));
    terminal(&object, 0);
}
#[test] fn retained_handle_keeps_full_width_code_after_reclaim() {
    let object = reset(0);
    assert!(mark_process_exited(7, u64::MAX));
    terminal(&object, u64::MAX);
    PROCESS_TABLE.lock().0 = None;
    assert!(!mark_process_exited(7, 1));
    assert!(object.is_exited());
    assert_eq!(object.exit_code(), u64::MAX);
    assert_eq!(WAKES.load(Ordering::Relaxed), 1);
}
#[test] fn missing_process_does_not_notify_or_reclaim() {
    reset(0);
    assert!(!mark_process_exited(99, 1));
    assert_eq!(WAKES.load(Ordering::Relaxed), 0);
    assert_eq!(RECLAIMS.load(Ordering::Relaxed), 0);
}
#[test] fn concurrent_terminal_publishers_have_exactly_one_winner() {
    let object = reset(0);
    let barrier = Arc::new(Barrier::new(16));
    let threads: Vec<_> = (0..16u64).map(|code| {
        let barrier = barrier.clone();
        std::thread::spawn(move || { barrier.wait(); (code, mark_process_exited(7, code)) })
    }).collect();
    let winners: Vec<_> = threads.into_iter().map(|t| t.join().unwrap()).filter(|(_, won)| *won).collect();
    assert_eq!(winners.len(), 1);
    terminal(&object, winners[0].0);
}
#[test] fn repeated_termination_cannot_replace_natural_exit() {
    let object = reset(0);
    assert!(mark_process_exited(7, 23));
    assert_eq!(process_terminate(2, 137), ESRCH);
    assert_eq!(TERMINATED.load(Ordering::Relaxed), 0);
    assert_eq!(CLEANUPS.load(Ordering::Relaxed), 0);
    terminal(&object, 23);
}
#[test] fn natural_exit_winning_during_termination_is_not_reported_as_a_kill() {
    let object = reset(1);
    assert_eq!(process_terminate(2, 137), ESRCH);
    terminal(&object, 42);
}
#[test] fn failed_revocation_does_not_hide_committed_termination() {
    let object = reset(2);
    assert_eq!(process_terminate(2, 137), SUCCESS);
    assert_eq!(TERMINATED.load(Ordering::Relaxed), 2);
    assert_eq!(CLEANUPS.load(Ordering::Relaxed), 1);
    terminal(&object, 137);
}
#[test] fn authorization_and_object_type_are_still_enforced() {
    let object = reset(0);
    assert_eq!(process_terminate(0, 137), EACCES);
    assert_eq!(process_terminate(1, 137), EBADF);
    assert!(!object.is_exited());
    assert_eq!(TERMINATED.load(Ordering::Relaxed), 0);
}
#[test] fn closing_is_not_observable_as_exit_and_second_owner_is_busy() {
    let object = reset(0);
    assert!(object.accepts_threads());
    assert!(object.begin_termination());
    assert!(!object.accepts_threads());
    assert!(!object.is_exited());
    assert_eq!(process_terminate(2, 137), EAGAIN);
    assert_eq!(TERMINATED.load(Ordering::Relaxed), 0);
    assert_eq!(WAKES.load(Ordering::Relaxed), 0);
}
#[test] fn external_termination_waits_for_remote_handoff_before_publication() {
    let object = reset(0);
    assert_eq!(process_terminate(2, 137), 0);
    assert_eq!(YIELDS.load(Ordering::Relaxed), 1);
    assert_eq!(THREAD_QUEUE.lock().count, 0);
    terminal(&object, 137);
}
#[test] fn concurrent_thread_exits_elect_exactly_one_owner() {
    let object = reset(0);
    let barrier = Arc::new(Barrier::new(2));
    let threads: Vec<_> = (1..=2).map(|id| {
        let barrier = barrier.clone();
        std::thread::spawn(move || { barrier.wait(); task::thread::begin_thread_exit(id) })
    }).collect();
    let winners: Vec<_> = threads.into_iter().filter_map(|t| t.join().unwrap()).collect();
    assert_eq!(winners, [7]);
    assert_eq!(THREAD_QUEUE.lock().iter().filter(|t| t.state() == ThreadState::Running).count(), 1,
        "the owner must stay schedulable while waiting for remote handoff");
    assert!(!object.accepts_threads());
    assert!(!object.is_exited());
    assert_eq!(WAKES.load(Ordering::Relaxed), 0);
}
#[test] fn natural_thread_exit_cannot_publish_over_an_external_owner() {
    let object = reset(0);
    assert!(object.begin_termination());
    assert_eq!(task::thread::begin_thread_exit(1), None);
    assert_eq!(task::thread::begin_thread_exit(2), None);
    assert!(!object.is_exited());
    assert_eq!(WAKES.load(Ordering::Relaxed), 0);
}
#[test] fn admission_racing_the_last_exit_is_included_or_refused_never_lost() {
    for _ in 0..100 {
        let object = reset(0);
        THREAD_QUEUE.lock().set_state(2, ThreadState::Terminated);
        let pending = Thread { id: 3, state: ThreadState::Ready, process_object: Some(object.clone()) };
        let barrier = Arc::new(Barrier::new(2));
        let other = barrier.clone();
        let creator = std::thread::spawn(move || { other.wait(); THREAD_QUEUE.lock().push(pending) });
        barrier.wait();
        let owner = task::thread::begin_thread_exit(1);
        let admitted = creator.join().unwrap();
        assert_eq!(owner.is_some(), admitted.is_none());
        if admitted.is_some() {
            assert!(object.accepts_threads());
            assert_eq!(task::thread::begin_thread_exit(3), Some(7));
        }
        assert!(!object.accepts_threads());
        assert!(!object.is_exited());
    }
}
"#,
    );
    let directory = std::env::temp_dir().join(format!(
        "mochios-terminal-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&directory).unwrap();
    let _cleanup = TemporaryDirectory(directory.clone());
    let executable = directory.join("probe");
    let mut compiler = Command::new("rustc")
        .args([
            "--edition=2024",
            "--test",
            "-Cdebuginfo=0",
            "-Cstrip=symbols",
            "-o",
        ])
        .arg(&executable)
        .arg("-")
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
    let built = compiler.wait_with_output().unwrap();
    assert!(
        built.status.success(),
        "{}",
        String::from_utf8_lossy(&built.stderr)
    );
    let run = Command::new(&executable)
        .arg("--test-threads=1")
        .output()
        .unwrap();
    assert!(
        run.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&run.stdout),
        String::from_utf8_lossy(&run.stderr)
    );
    assert!(String::from_utf8_lossy(&run.stdout).contains("13 passed"));
}
