//! Execute the kernel's publication/termination bodies on the host. Only the
//! surrounding process table, scheduler and revocation backend are substituted.
use std::io::Write;
use std::process::{Command, Stdio};

fn body<'a>(source: &'a str, signature: &str, indent: &str) -> &'a str {
    let start = source.find(signature).unwrap();
    let end = start + source[start..].find(&format!("\n{indent}}}")).unwrap();
    &source[start..end + indent.len() + 2]
}

#[test]
fn terminal_publication_is_immutable_and_termination_reports_the_winner() {
    let process = include_str!("../../../core/src/task/process.rs");
    let handles = include_str!("../../../core/src/syscall/handle.rs");
    let mut program = String::from(
        r#"
extern crate alloc;
use std::sync::{Arc, Barrier, Mutex, MutexGuard};
use std::sync::atomic::{AtomicU8, AtomicU64, AtomicUsize, Ordering};
type ProcessId = u64;
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
fn wake_process_exit_waiters(_: u64) { WAKES.fetch_add(1, Ordering::Relaxed); }
fn defer_process_reclaim(_: u64) { RECLAIMS.fetch_add(1, Ordering::Relaxed); }
"#,
    );
    program.push_str(body(process, "pub fn mark_process_exited(", ""));
    program.push_str(
        r#"
const SUCCESS: u64 = 0;
const ESRCH: u64 = 3;
const EBADF: u64 = 9;
const EACCES: u64 = 13;
struct HandleRights;
impl HandleRights { const SIGNAL: Self = Self; }
enum KernelObject { Process(Arc<ProcessObject>), Other }
fn object(raw: u64, _: HandleRights) -> Result<KernelObject, u64> {
    match raw {
        0 => Err(EACCES),
        1 => Ok(KernelObject::Other),
        _ => Ok(KernelObject::Process(Arc::clone(&PROCESS_TABLE.lock().0.as_ref().unwrap().object))),
    }
}
mod syscall { pub mod security { pub fn current_process_id() -> Option<u64> { None } } }
mod task {
    use super::*;
    pub use super::mark_process_exited;
    pub fn with_process<R>(id: u64, f: impl FnOnce(&Process) -> R) -> Option<R> {
        PROCESS_TABLE.lock().0.as_ref().filter(|p| p.object.id() == id).map(f)
    }
    pub struct Thread(u64);
    impl Thread { pub fn process_id(&self) -> u64 { 7 } pub fn id(&self) -> u64 { self.0 } }
    pub fn for_each_thread(mut f: impl FnMut(&Thread)) { f(&Thread(1)); f(&Thread(2)); }
    pub fn terminate_thread(_: u64) { TERMINATED.fetch_add(1, Ordering::Relaxed); }
    pub fn release_process_borrowed_mappings(id: u64) -> Result<(), u64> {
        CLEANUPS.fetch_add(1, Ordering::Relaxed);
        if CASE.load(Ordering::Relaxed) == 1 { assert!(mark_process_exited(id, 42)); }
        if CASE.load(Ordering::Relaxed) == 2 { Err(12) } else { Ok(()) }
    }
    pub mod scheduler { pub fn exit_current_process(_: i32) -> ! { unreachable!() } }
}
"#,
    );
    program.push_str(body(handles, "pub fn process_terminate(", ""));
    program.push_str(
        r#"
fn reset(case: usize) -> Arc<ProcessObject> {
    CASE.store(case, Ordering::Relaxed);
    for counter in [&WAKES, &RECLAIMS, &CLEANUPS, &TERMINATED] { counter.store(0, Ordering::Relaxed); }
    let object = Arc::new(ProcessObject::new(7));
    PROCESS_TABLE.lock().0 = Some(Process { state: ProcessState::Running, exit_code: None, object: object.clone() });
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
"#,
    );
    let directory = std::env::temp_dir().join(format!("mochios-terminal-{}", std::process::id()));
    std::fs::create_dir(&directory).unwrap();
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
    assert!(String::from_utf8_lossy(&run.stdout).contains("8 passed"));
    std::fs::remove_dir_all(directory).unwrap();
}
