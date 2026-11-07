#[allow(dead_code)]
#[path = "support/native_error_probe.rs"]
mod probe;

#[test]
fn remote_wake_is_sent_after_queue_unlock_and_preserves_wake_latches() {
    let mut program = String::from(r#"
#![allow(dead_code)]
use std::sync::{Mutex, MutexGuard};
#[derive(Clone,Copy,PartialEq,Eq,Debug)] enum ThreadState { Sleeping, Blocked, Ready, Running, Terminated }
#[derive(Clone,Copy)] struct ThreadId(u64);
struct Thread { state: ThreadState, cpu: Option<usize>, pending: bool, interactive: bool }
impl Thread {
    fn state(&self) -> ThreadState { self.state }
    fn cpu_affinity(&self) -> Option<usize> { self.cpu }
    fn note_interactive_wakeup(&mut self) { self.interactive = true; }
    fn set_pending_wakeup(&mut self) { self.pending = true; }
}
struct Queue(Thread);
impl Queue {
    fn slot_index(&self, id: ThreadId) -> Option<usize> { (id.0 == 1).then_some(0) }
    fn get_slot_mut(&mut self, _: usize) -> Option<&mut Thread> { Some(&mut self.0) }
    fn set_state_at_slot(&mut self, _: usize, state: ThreadState) { self.0.state = state; }
}
struct Lock(Mutex<Queue>);
impl Lock { fn lock(&self) -> MutexGuard<'_, Queue> { self.0.lock().unwrap() } }
static THREAD_QUEUE: Lock = Lock(Mutex::new(Queue(Thread {
    state: ThreadState::Sleeping, cpu: Some(1), pending: false, interactive: false,
})));
static INTERRUPTS: Mutex<Vec<(u32,u8)>> = Mutex::new(Vec::new());
mod percpu { pub fn current_cpu_id() -> usize { 0 } }
mod smp {
    pub fn send_fixed_ipi(cpu: u32, vector: u8) -> bool {
        assert!(crate::THREAD_QUEUE.0.try_lock().is_ok(), "IPI was sent under the queue lock");
        crate::INTERRUPTS.lock().unwrap().push((cpu,vector));
        true
    }
}
"#);
    program.push_str(probe::between(
        include_str!("../../../core/src/task/scheduler.rs"),
        "pub fn wake_thread(",
        "/// 現在のスレッドをスリープ状態にする。",
    ));
    program.push_str(r#"
fn main() {
    for state in [ThreadState::Sleeping, ThreadState::Blocked, ThreadState::Ready, ThreadState::Running, ThreadState::Terminated] {
        for cpu in [None, Some(0), Some(1)] {
            for registered in [false, true] {
                THREAD_QUEUE.lock().0 = Thread { state, cpu, pending: false, interactive: false };
                INTERRUPTS.lock().unwrap().clear();
                if registered { wake_registered_waiter(ThreadId(1)); } else { wake_thread(ThreadId(1)); }
                let queue = THREAD_QUEUE.lock();
                let transitioned = matches!(state, ThreadState::Sleeping | ThreadState::Blocked);
                assert_eq!(queue.0.state, if transitioned { ThreadState::Ready } else { state });
                assert_eq!(queue.0.interactive, transitioned);
                assert_eq!(queue.0.pending, state == ThreadState::Ready || state == ThreadState::Running && registered);
                assert_eq!(*INTERRUPTS.lock().unwrap(), if transitioned && cpu == Some(1) { vec![(1,WAKE_VECTOR)] } else { vec![] });
            }
        }
    }
    INTERRUPTS.lock().unwrap().clear();
    wake_registered_waiter(ThreadId(99));
    assert!(INTERRUPTS.lock().unwrap().is_empty());
}
"#);
    probe::run(&program);
}
