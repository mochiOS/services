use std::io::Write;
use std::process::{Command, Stdio};

#[test]
fn image_entry_drops_preparation_and_input_allocations_before_abandoning_stack() {
    let source = include_str!("../../../core/src/syscall/exec.rs");
    let preparation = source
        .split("fn replace_current_process_image(")
        .nth(1)
        .unwrap()
        .split("pub fn process_image_replace_syscall(")
        .next()
        .unwrap();
    assert!(preparation.contains("Ok((new_pt_phys, entry, initial_rsp))"));
    assert!(!preparation.contains("jump_to_usermode("));
    let syscall = source
        .split("pub fn process_image_replace_syscall(")
        .nth(1)
        .unwrap()
        .split("pub fn process_create_syscall(")
        .next()
        .unwrap();
    let prepared = syscall
        .find("match replace_current_process_image(")
        .unwrap();
    let jump = syscall
        .find("jump_to_usermode(entry, stack_pointer, 0)")
        .unwrap();
    for allocation in ["executable", "startup_bytes", "identity_bytes"] {
        let release = syscall.find(&format!("drop({allocation})")).unwrap();
        assert!(prepared < release && release < jump);
    }
    assert!(syscall.contains("Err(errno) => return errno"));
}

#[test]
fn production_thread_removal_reclaims_wait_slots_without_holding_queue_lock() {
    let thread = include_str!("../../../core/src/task/thread.rs");
    let time = include_str!("../../../core/src/syscall/time.rs");
    let process = include_str!("../../../core/src/task/process.rs");
    let mut program = String::from(
        r#"
use std::sync::{Mutex, MutexGuard};
use std::sync::atomic::{AtomicU64, Ordering};
type ThreadId = u64;
struct SpinLock<T>(Mutex<T>);
impl<T> SpinLock<T> {
    const fn new(value:T)->Self { Self(Mutex::new(value)) }
    fn lock(&self)->MutexGuard<'_,T> { self.0.lock().unwrap() }
}
mod task { pub struct ThreadQueue; impl ThreadQueue { pub const MAX_THREADS:usize=64; } }
mod percpu { pub fn thread_is_cpu_referenced(id:u64)->bool { id==3 } }
const NO_DEADLINE:u64=u64::MAX;
mod syscall {
    pub mod ipc {
        pub struct IpcEndpoint {pub thread_id:u64,pub slot:u16,pub generation:u64}
        pub mod lifetime {
            pub fn remove_waiter(_:u64) {assert!(crate::THREAD_QUEUE.0.try_lock().is_ok());}
        }
        pub fn retire_endpoint(endpoint:IpcEndpoint) {
            assert!(crate::THREAD_QUEUE.0.try_lock().is_ok());
            assert_eq!(endpoint.generation,123);
        }
    }
    pub mod address_wait {
        pub fn remove_waiter(_:u64) { assert!(crate::THREAD_QUEUE.0.try_lock().is_ok()); }
    }
    pub mod time {
        use super::super::*;
"#,
    );
    let hint = time.find("pub(super) struct DeadlineHint(").unwrap();
    let hint_end = time
        .find("#[derive(Clone, Copy, Debug, PartialEq, Eq)]")
        .unwrap();
    program.push_str(&time[hint..hint_end]);
    let sleeps = time
        .find("#[derive(Clone, Copy)]\nstruct SleepEntry")
        .unwrap();
    let sleeps_end = time.find("pub fn wake_due_sleepers(").unwrap();
    program.push_str(&time[sleeps..sleeps_end]);
    program.push_str(
        r#"
    }
}
mod process {
    use super::*;
    struct ProcessExitWaiter { thread:ThreadId, processes:Vec<u64> }
    static PROCESS_EXIT_WAITERS:SpinLock<[Option<ProcessExitWaiter>;64]>=
        SpinLock::new([const {None};64]);
    pub fn register(thread:ThreadId) {
        let mut slots=PROCESS_EXIT_WAITERS.lock();
        *slots.iter_mut().find(|slot|slot.is_none()).expect("wait slots exhausted")=
            Some(ProcessExitWaiter{thread,processes:vec![90]});
    }
"#,
    );
    let start = process.find("pub fn remove_process_exit_waiters(").unwrap();
    let end = process.find("pub fn remove_process_exit_waiter(").unwrap();
    program.push_str(&process[start..end]);
    program.push_str(
        r#"
}
#[derive(PartialEq)] enum ThreadState { Ready, Terminated }
struct Thread { id:ThreadId, state:ThreadState }
impl Thread { fn state(&self)->ThreadState {
    match self.state { ThreadState::Ready=>ThreadState::Ready, _=>ThreadState::Terminated }
} }
struct Queue(Vec<Thread>);
impl Queue {
    fn slot_index_and_generation(&self,id:ThreadId)->Option<(usize,u64)> {
        self.0.iter().position(|t|t.id==id).map(|slot|(slot,123))
    }
    fn remove(&mut self,id:ThreadId)->Option<Thread> {
        let index=self.0.iter().position(|t|t.id==id)?; Some(self.0.remove(index))
    }
    fn get(&self,id:ThreadId)->Option<&Thread> { self.0.iter().find(|t|t.id==id) }
}
static THREAD_QUEUE:SpinLock<Queue>=SpinLock::new(Queue(Vec::new()));
mod implementation {
    use super::*;
"#,
    );
    let start = thread.find("pub fn remove_thread(").unwrap();
    let end = thread.find("/// 次に実行すべきスレッドIDを取得").unwrap();
    program.push_str(&thread[start..end].replace("id.as_u64()", "id"));
    let start = thread
        .find("pub(super) fn remove_quiescent_terminated_thread(")
        .unwrap();
    let end = thread[start..]
        .find("/// 指定スロットのスレッド状態を更新")
        .unwrap()
        + start;
    program.push_str(&thread[start..end].replace("id.as_u64()", "id"));
    program.push_str(
        r#"
}
fn add(id:u64,state:ThreadState) { THREAD_QUEUE.lock().0.push(Thread{id,state}); }
fn main() {
    use syscall::time::{arm_thread_deadline,disarm_thread_deadline};
    // Demonstrate the finite capacity and that cleanup preserves other owners.
    for id in 100..164 { assert!(arm_thread_deadline(id,u64::MAX-1)); }
    assert!(!arm_thread_deadline(164,u64::MAX-1));
    add(120,ThreadState::Terminated);
    assert!(implementation::remove_thread(120).is_some());
    assert!(arm_thread_deadline(164,u64::MAX-1));
    assert!(!arm_thread_deadline(165,u64::MAX-1));
    for id in 100..165 { disarm_thread_deadline(id); }
    add(2,ThreadState::Ready); add(3,ThreadState::Terminated);
    assert!(implementation::remove_quiescent_terminated_thread(2).is_none());
    assert!(implementation::remove_quiescent_terminated_thread(3).is_none());
    // Repeated exec/exit retirement must not exhaust either 64-entry registry.
    for id in 1000..1200 {
        add(id,ThreadState::Terminated);
        assert!(arm_thread_deadline(id,u64::MAX-1));
        process::register(id);
        if id%2==0 { assert!(implementation::remove_thread(id).is_some()); }
        else { assert!(implementation::remove_quiescent_terminated_thread(id).is_some()); }
        assert!(implementation::remove_thread(id).is_none());
    }
    // A live thread's registrations survive an unsuccessful reap.
    assert!(arm_thread_deadline(2,u64::MAX-1));
    assert!(implementation::remove_quiescent_terminated_thread(2).is_none());
    for id in 2000..2063 { assert!(arm_thread_deadline(id,u64::MAX-1)); }
    assert!(!arm_thread_deadline(2063,u64::MAX-1));
}
"#,
    );
    let directory = std::env::temp_dir().join(format!(
        "mochios-wait-retirement-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&directory).unwrap();
    let binary = directory.join("probe");
    let mut compiler = Command::new("rustc")
        .args(["--edition=2021", "-Awarnings", "-"])
        .arg("-o")
        .arg(&binary)
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
    let executed = Command::new(&binary).output().unwrap();
    std::fs::remove_dir_all(directory).unwrap();
    assert!(
        executed.status.success(),
        "{}",
        String::from_utf8_lossy(&executed.stderr)
    );
}
