use std::io::Write;
use std::process::{Command, Stdio};

#[test]
fn production_cpu_reference_tracks_both_sides_of_a_stack_handoff() {
    let source = include_str!("../../../core/src/percpu.rs");
    let begin = source.find("pub(crate) fn begin_thread_switch(").unwrap();
    let end = source[begin..]
        .find("pub fn set_current_thread_raw_id(")
        .unwrap()
        + begin;
    let mut program = String::from(
        r#"
use std::sync::atomic::{AtomicU64, Ordering};
struct PerCpuState { current_thread_id: AtomicU64, switching_from_thread_id: AtomicU64 }
static CPU_STATES: [PerCpuState; 2] = [const {
    PerCpuState { current_thread_id: AtomicU64::new(0), switching_from_thread_id: AtomicU64::new(0) }
}; 2];
fn state_for_current_cpu() -> &'static PerCpuState { &CPU_STATES[0] }
"#,
    );
    program.push_str(&source[begin..end]);
    program.push_str(
        r#"
fn main() {
    assert!(!thread_is_cpu_referenced(0));
    assert!(!thread_is_cpu_referenced(7));
    CPU_STATES[0].current_thread_id.store(7, Ordering::SeqCst);
    CPU_STATES[1].current_thread_id.store(9, Ordering::SeqCst);
    assert!(thread_is_cpu_referenced(7));
    assert!(thread_is_cpu_referenced(9));
    let marker = begin_thread_switch(7);
    assert_eq!(marker, CPU_STATES[0].switching_from_thread_id.as_ptr());
    CPU_STATES[0].current_thread_id.store(8, Ordering::SeqCst);
    assert!(thread_is_cpu_referenced(7), "outgoing stack still protected after incoming publication");
    assert!(thread_is_cpu_referenced(8));
    CPU_STATES[0].switching_from_thread_id.swap(0, Ordering::SeqCst);
    assert!(!thread_is_cpu_referenced(7));
    assert!(thread_is_cpu_referenced(8));
    assert!(thread_is_cpu_referenced(9));
    CPU_STATES[0].current_thread_id.store(0, Ordering::SeqCst);
    assert!(!thread_is_cpu_referenced(8));
}
"#,
    );
    let directory = std::env::temp_dir().join(format!(
        "mochios-thread-cpu-reference-{}-{}",
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

#[test]
fn outgoing_reference_is_released_only_after_assembly_switches_stacks() {
    let context = include_str!("../../../core/src/task/context.rs");
    let assembly = context
        .split("pub unsafe extern \"C\" fn switch_context(")
        .nth(1)
        .unwrap()
        .split("pub unsafe fn switch_to_thread(")
        .next()
        .unwrap();
    assert!(
        assembly.find("mov rsp, [rsi + 0x00]").unwrap() < assembly.find("xchg [rdx], rcx").unwrap()
    );
    let switching = context
        .split("let outgoing_marker = crate::percpu::begin_thread_switch(")
        .nth(1)
        .unwrap();
    assert!(
        switching.find("set_current_thread(").unwrap() < switching.find("drop(queue)").unwrap()
    );
    let thread = include_str!("../../../core/src/task/thread.rs");
    let termination = thread
        .split("pub(super) fn mark_thread_terminated(")
        .nth(1)
        .unwrap()
        .split("pub fn set_thread_state_at_slot(")
        .next()
        .unwrap();
    assert!(termination.contains("previous == ThreadState::Running"));
    assert!(termination.contains("thread_is_cpu_referenced(id.as_u64())"));
    assert!(
        termination.find("THREAD_QUEUE.lock()").unwrap()
            < termination.find("thread_is_cpu_referenced").unwrap()
    );
}
