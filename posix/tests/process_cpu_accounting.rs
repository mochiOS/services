use std::io::Write;
use std::process::{Command, Stdio};

#[test]
fn native_counter_accumulates_concurrent_threads_and_survives_retirement() {
    let source = include_str!("../../../core/src/task/process.rs");
    let start = source.find("pub struct ProcessObject {").unwrap();
    let end = source[start..]
        .find("#[derive(Clone, Copy, Debug, PartialEq, Eq)]")
        .unwrap()
        + start;
    let mut program = String::from(
        r#"
mod native {
use std::sync::{Arc, atomic::{AtomicU8, AtomicU64, Ordering}};
type ProcessId = u64;
mod mnu_abi {
    pub const PROCESS_STATE_RUNNING: u32 = 1;
    pub const PROCESS_STATE_EXITED: u32 = 2;
}
"#,
    );
    program.push_str(&source[start..end]);
    program.push_str(
        r#"
pub fn exercise() {
    let process = Arc::new(ProcessObject::new(101));
    let foreign = Arc::new(ProcessObject::new(102));
    assert_eq!(process.cpu_ticks(), 0);
    let threads: Vec<_> = (0..8).map(|_| {
        let owner = Arc::clone(&process);
        std::thread::spawn(move || {
            for tick in 0..10000 { owner.note_cpu_tick(tick % 2 == 0); }
        })
    }).collect();
    for thread in threads { thread.join().unwrap(); }
    assert_eq!(process.cpu_ticks(), 80000);
    assert_eq!(process.user_cpu_ticks(), 40000);
    assert_eq!(process.kernel_cpu_ticks(), 40000);
    assert_eq!(Arc::strong_count(&process), 1, "thread references were reclaimed");
    assert_eq!(foreign.cpu_ticks(), 0, "native process counters are independent");
    process.mark_exited(7);
    assert_eq!(process.cpu_ticks(), 80000, "native exit does not reset accounting");
    assert_eq!(process.exit_code(), 7);
    process.user_cpu_ticks.store(u64::MAX - 1, Ordering::Relaxed);
    process.note_cpu_tick(true);
    process.note_cpu_tick(true);
    assert_eq!(process.user_cpu_ticks(), u64::MAX);
    assert_eq!(process.kernel_cpu_ticks(), 40000);
    assert_eq!(process.cpu_ticks(), u64::MAX, "overflow cannot make CPU time decrease");
}
}
fn main() { native::exercise(); }
"#,
    );
    let directory = std::env::temp_dir().join(format!(
        "mochios-process-cpu-{}-{}",
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

#[test]
fn timer_records_both_clocks_and_native_readers_use_stable_owner_accounting() {
    let thread = include_str!("../../../core/src/task/thread.rs");
    let tick = thread
        .split("pub fn note_cpu_tick(")
        .nth(1)
        .unwrap()
        .split("pub fn set_in_syscall(")
        .next()
        .unwrap();
    assert!(tick.contains("self.cpu_ticks.saturating_add(1)"));
    assert!(tick.contains("process.note_cpu_tick(user_mode)"));
    assert!(tick.contains("self.process_object.as_ref()"));
    let push = thread
        .split("pub fn push(")
        .nth(1)
        .unwrap()
        .split("pub fn get(")
        .next()
        .unwrap();
    assert!(push.contains("p.process_object()"));
    assert!(
        push.find("thread.process_object = Some(object)").unwrap()
            < push.find("*slot = Some(thread)").unwrap()
    );
    let clock = include_str!("../../../core/src/syscall/time.rs");
    let cpu = clock
        .split("mnu_abi::ClockId::ProcessCpu =>")
        .nth(1)
        .unwrap()
        .split("mnu_abi::ClockId::Realtime =>")
        .next()
        .unwrap();
    assert!(cpu.contains("current_thread_id()"));
    assert!(cpu.contains("thread.process_cpu_ticks()"));
    assert!(!cpu.contains("for_each_thread"));
    let metrics = include_str!("../../../core/src/syscall/process.rs");
    assert!(metrics.contains("let cpu_ticks = proc.process_object().cpu_ticks()"));
}

#[test]
fn both_timer_sources_classify_the_interrupted_cpu_mode_before_switching_address_spaces() {
    let source = include_str!("../../../core/src/interrupt/timer.rs");
    assert!(source.contains("timer_entry!(timer_interrupt_handler, 0)"));
    assert!(source.contains("timer_entry!(local_timer_interrupt_handler, 1)"));
    let handler = source
        .split("fn handle_timer(")
        .nth(1)
        .unwrap()
        .split("/// 現在")
        .next()
        .unwrap();
    let mode = handler.find("frame[16] & 3 == 3").unwrap();
    assert!(mode < handler.find("kpti_enter_for_trap(user_mode)").unwrap());
    assert!(mode < handler.find("frame[16] =").unwrap());
    assert!(handler.contains("scheduler_tick(user_mode)"));
    let scheduler = include_str!("../../../core/src/task/scheduler.rs");
    let tick = scheduler
        .split("fn scheduler_tick(")
        .nth(1)
        .unwrap()
        .split("let should_schedule")
        .next()
        .unwrap();
    assert_eq!(tick.matches("thread.note_cpu_tick(user_mode)").count(), 2);
    assert!(
        tick.find("thread.note_cpu_tick(user_mode)").unwrap()
            < tick.find("t.in_syscall()").unwrap()
    );
}
