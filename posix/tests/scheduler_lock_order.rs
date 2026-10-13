use std::io::Write;
use std::process::{Command, Stdio};

#[test]
fn actual_selection_releases_queue_before_process_lookup_and_scheduler_update() {
    let source = include_str!("../../../core/src/task/scheduler.rs");
    let start = source.find("fn select_next_thread()").unwrap();
    let end = start + source[start..].find("\n}\n").unwrap() + 3;
    let mut program = String::from(
        r#"
use std::sync::Mutex;
type ThreadId = u64;
#[derive(Clone, Copy, PartialEq, Eq, Debug)] enum ThreadState { Running, Ready }
struct Thread { id: u64, pid: u64, state: ThreadState, affinity: Option<usize> }
impl Thread {
    fn state(&self) -> ThreadState { self.state }
    fn id(&self) -> u64 { self.id }
    fn process_id(&self) -> u64 { self.pid }
    fn cpu_affinity(&self) -> Option<usize> { self.affinity }
    fn set_cpu_affinity(&mut self, cpu: Option<usize>) { self.affinity = cpu; }
    fn interactive_score(&self) -> u32 { 11 }
    fn cpu_burst_score(&self) -> u32 { 12 }
}
struct Queue { threads: [Thread; 2] }
impl Queue {
    fn slot_index(&self, id: u64) -> Option<usize> { self.threads.iter().position(|thread| thread.id == id) }
    fn get_slot(&self, slot: usize) -> Option<&Thread> { self.threads.get(slot) }
    fn get_slot_mut(&mut self, slot: usize) -> Option<&mut Thread> { self.threads.get_mut(slot) }
    fn set_state_at_slot(&mut self, slot: usize, state: ThreadState) { self.threads[slot].state = state; }
    fn next_ready_slot_for_cpu_after(&self, current: Option<usize>, cpu: usize) -> Option<usize> {
        assert_eq!(current, Some(0)); assert_eq!(cpu, 0);
        assert_eq!(self.threads[0].state, ThreadState::Ready); Some(1)
    }
}
struct QueueLock(Mutex<Queue>);
impl QueueLock { fn lock(&self) -> std::sync::MutexGuard<'_, Queue> { self.0.lock().unwrap() } }
static THREAD_QUEUE: QueueLock = QueueLock(Mutex::new(Queue { threads: [
    Thread { id: 1, pid: 10, state: ThreadState::Running, affinity: Some(0) },
    Thread { id: 2, pid: 20, state: ThreadState::Ready, affinity: None }
] }));
static MISSING: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
mod percpu { pub fn current_cpu_id() -> usize { 0 } }
mod task {
    pub struct Process;
    impl Process { pub fn priority(&self) -> u32 { 7 } pub fn is_foreground(&self) -> bool { true } }
    pub fn with_process<R>(pid: u64, callback: impl FnOnce(&Process) -> R) -> Option<R> {
        assert_eq!(pid, 20);
        assert!(crate::THREAD_QUEUE.0.try_lock().is_ok(), "queue -> process lock inversion");
        if crate::MISSING.load(std::sync::atomic::Ordering::Acquire) { None } else { Some(callback(&Process)) }
    }
}
#[macro_export] macro_rules! debug { ($($tokens:tt)*) => {} }
fn current_thread_id() -> Option<u64> { Some(1) }
fn time_slice_ticks_for_thread(foreground: bool, priority: u32, interactive: u32, burst: u32) -> u64 {
    assert_eq!((interactive, burst), (11, 12));
    if MISSING.load(std::sync::atomic::Ordering::Acquire) { assert_eq!((foreground, priority), (false, 0)); 1 }
    else { assert_eq!((foreground, priority), (true, 7)); 2 }
}
struct Scheduler { slice: u64, resets: u32 }
impl Scheduler { fn set_time_slice(&mut self, slice: u64) { self.slice = slice; } fn reset_slice(&mut self) { self.resets += 1; } }
struct SchedulerLock(Mutex<Scheduler>);
impl SchedulerLock { fn lock(&self) -> std::sync::MutexGuard<'_, Scheduler> {
    assert!(THREAD_QUEUE.0.try_lock().is_ok(), "queue held during scheduler update"); self.0.lock().unwrap()
} }
static SCHEDULER: SchedulerLock = SchedulerLock(Mutex::new(Scheduler { slice: 0, resets: 0 }));
fn scheduler() -> &'static SchedulerLock { &SCHEDULER }
"#,
    );
    program.push_str(&source[start..end]);
    program.push_str(
        r#"
fn main() {
    for missing in [false, true] {
        MISSING.store(missing, std::sync::atomic::Ordering::Release);
        assert_eq!(select_next_thread(), Some((2, 1)));
        let queue = THREAD_QUEUE.lock();
        assert_eq!(queue.threads[1].state, ThreadState::Running);
        assert_eq!(queue.threads[1].affinity, Some(0)); drop(queue);
        assert_eq!(SCHEDULER.lock().slice, if missing { 1 } else { 2 });
    }
    assert_eq!(SCHEDULER.lock().resets, 2);
}
"#,
    );
    let directory = std::env::temp_dir().join(format!(
        "mochios-scheduler-lock-{}-{}",
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
    let result = compiler.wait_with_output().unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let result = Command::new(&executable).output().unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    std::fs::remove_dir_all(directory).unwrap();
}
