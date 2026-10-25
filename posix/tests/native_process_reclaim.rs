use std::fs;
use std::io::Write;
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

struct Temporary(std::path::PathBuf);

impl Drop for Temporary {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn production_reclaim_is_independent_of_creator_and_preserves_handle_status() {
    let source = include_str!("../../../core/src/task/process.rs");
    let object_start = source
        .find("#[derive(Debug)]\npub struct ProcessObject {")
        .unwrap();
    let object_end = source[object_start..]
        .find("#[derive(Clone, Copy, Debug, PartialEq, Eq)]")
        .unwrap()
        + object_start;
    let method_start = source.find("    fn take_exited(").unwrap();
    let method_end = source[method_start..]
        .find("    /// 現在のプロセス数を取得")
        .unwrap()
        + method_start;
    let mut probe = format!(
        "mod native {{\nuse std::sync::{{Arc, atomic::{{AtomicU8, AtomicU64, Ordering}}}};\n\
         type ProcessId = u64;\n\
         mod mnu_abi {{ pub const PROCESS_STATE_RUNNING:u32={}; pub const PROCESS_STATE_EXITED:u32={}; }}\n",
        mnu_abi::PROCESS_STATE_RUNNING, mnu_abi::PROCESS_STATE_EXITED,
    );
    probe.push_str(&source[object_start..object_end]);
    probe.push_str(
        r#"
#[derive(PartialEq)] enum ProcessState { Running, Zombie }
struct Process { object: Arc<ProcessObject>, creator: Option<ProcessId> }
impl Process {
    fn id(&self) -> ProcessId { self.object.id() }
    fn state(&self) -> ProcessState {
        if self.object.is_exited() { ProcessState::Zombie } else { ProcessState::Running }
    }
    fn parent_id(&self) -> Option<ProcessId> { panic!("reclaim must not inspect creator") }
}
struct Table { processes: Vec<Option<Process>>, count: usize }
impl Table {
"#,
    );
    probe.push_str(&source[method_start..method_end]);
    probe.push_str(
        r#"
}
pub fn run() {
    let retained = Arc::new(ProcessObject::new(1));
    retained.mark_exited(37);
    let other = Arc::new(ProcessObject::new(2));
    other.mark_exited(7);
    let live = Arc::new(ProcessObject::new(3));
    let mut table = Table { processes: vec![
        Some(Process { object: retained.clone(), creator: Some(9) }),
        Some(Process { object: other, creator: None }),
        Some(Process { object: live, creator: Some(9) }),
    ], count: 3 };
    assert!(table.take_exited(99).is_none());
    assert!(table.take_exited(3).is_none());
    assert_eq!(table.count, 3);
    drop(table.take_exited(1).unwrap());
    assert!(retained.is_exited());
    assert_eq!(retained.exit_code(), 37);
    assert_eq!(Arc::strong_count(&retained), 1);
    assert!(table.take_exited(1).is_none());
    drop(table.take_exited(2).unwrap());
    assert_eq!(table.count, 1);
    assert!(table.processes[2].is_some());
}
"#,
    );
    probe.push_str("\n}\nfn main() { native::run(); }\n");
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let temporary = Temporary(std::env::temp_dir().join(format!(
        "mochios-process-reclaim-{}-{nonce}",
        std::process::id()
    )));
    fs::create_dir(&temporary.0).unwrap();
    let binary = temporary.0.join("probe");
    probe.insert_str(0, include_str!("support/unmeasured_memory.inc"));
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
        .write_all(probe.as_bytes())
        .unwrap();
    let output = compiler.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let output = Command::new(binary).output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn exit_uses_explicit_waiters_and_defers_execution_resource_reclamation() {
    let process = include_str!("../../../core/src/task/process.rs");
    let scheduler = include_str!("../../../core/src/task/scheduler.rs");
    for legacy in [
        "is_child_match",
        "has_child_process",
        "reap_zombie_child",
        "take_handle_managed_exited",
    ] {
        assert!(!process.contains(legacy));
    }
    assert!(!scheduler.contains("wake_parent_ipc_waiter"));
    let start = process.find("pub fn mark_process_exited(").unwrap();
    let end = process[start..].find("fn destroy_exited_process(").unwrap() + start;
    let exit = &process[start..end];
    assert!(exit.contains("wake_process_exit_waiters(id)"));
    assert!(exit.contains("defer_process_reclaim(id)"));
    assert!(!exit.contains("parent_id"));
    let start = process
        .find("pub fn flush_deferred_process_reclaims()")
        .unwrap();
    let reclaim = &process[start..];
    assert!(reclaim.contains("current_process_id()"));
    assert!(reclaim.contains("thread.process_id() == process_id"));
    assert!(reclaim.contains("defer_process_reclaim(process_id)"));
}
