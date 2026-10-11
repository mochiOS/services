#[path = "../../../applications/system-monitor/src/processes.rs"]
mod monitor;

#[test]
fn compact_inspection_record_preserves_metrics_and_full_length_names() {
    assert_eq!(monitor::RECORD_SIZE, mnu_abi::PROCESS_INFO_RECORD_SIZE);
    assert_eq!(mnu_abi::PROCESS_INFO_RECORD_SIZE, 104);
    let mut bytes = [0u8; mnu_abi::PROCESS_INFO_RECORD_SIZE];
    bytes[0..8].copy_from_slice(&71u64.to_ne_bytes());
    bytes[16..24].copy_from_slice(&1u64.to_ne_bytes());
    bytes[24..32].copy_from_slice(&250u64.to_ne_bytes());
    bytes[32..40].copy_from_slice(&8192u64.to_ne_bytes());
    bytes[40..48].copy_from_slice(&3u64.to_ne_bytes());
    bytes[48..].fill(b'x');
    let decoded = monitor::decode_records(&bytes, 1);
    assert_eq!(decoded.len(), 1);
    assert_eq!(decoded[0].pid, 71);
    assert_eq!(decoded[0].cpu_ticks, 250);
    assert_eq!(decoded[0].memory_bytes, 8192);
    assert_eq!(decoded[0].thread_count, 3);
    assert_eq!(decoded[0].name, "x".repeat(56));
}

#[test]
fn kernel_has_no_parent_state_and_inspection_consumers_use_compact_layout() {
    let process = include_str!("../../../core/src/task/process.rs");
    assert!(!process.contains("parent_id"));
    let exec = include_str!("../../../core/src/syscall/exec.rs");
    assert!(!exec.contains("parent_override"));
    // Native access checks are retained, not deleted with parent metadata.
    assert!(exec.contains("access_process_override.or_else"));
    assert!(exec.contains("ensure_fs_path_executable_for_process(path, pid)"));
    let platform = include_str!("../../../user/crates/platform/src/lib.rs");
    assert!(!platform.contains("parent_pid"));
    assert!(platform.contains("RECORD_SIZE: usize = syscall::PROCESS_INFO_RECORD_SIZE"));
    assert!(platform.contains("cpu_ticks: read_u64(record, 24)"));
    assert!(platform.contains("memory_bytes: read_u64(record, 32)"));
    assert!(platform.contains("thread_count: read_u64(record, 40)"));
    let binder = include_str!("../../../applications/binder/src/platform/mochios.rs");
    assert!(binder.contains("PROCESS_RECORD_SIZE: usize = 104"));
    let kernel = include_str!("../../../core/src/syscall/process.rs");
    assert!(kernel.contains("RECORD_SIZE: usize = mnu_abi::PROCESS_INFO_RECORD_SIZE"));
    assert!(!kernel.contains("proc.parent_id()"));
    assert!(kernel.contains("if !caller_has_process_inspect_capability()"));
}
