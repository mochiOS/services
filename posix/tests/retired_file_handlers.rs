#[test]
fn retired_path_syscalls_leave_no_unused_kernel_policy_helpers() {
    let filesystem = include_str!("../../../core/src/syscall/fs.rs");
    for name in [
        "resolve_relative_to_cwd",
        "resolve_path",
        "ensure_fs_path_readable",
        "ensure_fs_path_access",
        "ensure_fs_path_access_for_process",
        "ensure_fs_path_executable_for_process",
        "ensure_fs_capability_access",
        "ensure_fs_capability_access_for_process",
        "path_owner_allows",
        "process_has_cap",
        "capability_requirement_satisfied",
        "enforce_required_capability",
        "enforce_fs_capabilities_for_process",
        "current_effective_ids",
        "ensure_unix_mode_access",
        "ensure_unix_traversal",
        "ensure_unix_parent_write_for_process",
        "sticky_directory_allows_delete",
        "ensure_unix_sticky_delete_for_process",
        "open_required_rights",
        "open_path_required_rights",
        "access_mode_rights",
        "readdir_rootfs_first",
        "errno_from_cext",
        "vnode_kind_from_protocol",
    ] {
        assert!(
            !filesystem.contains(&format!("fn {name}(")),
            "retired policy helper restored: {name}"
        );
    }
}

#[test]
fn descriptor_numbers_and_cloexec_are_not_kernel_process_state() {
    let objects = include_str!("../../../core/src/task/fd_table.rs");
    let process = include_str!("../../../core/src/task/process.rs");
    let exec = include_str!("../../../core/src/syscall/exec.rs");
    let task = include_str!("../../../core/src/task/mod.rs");
    for source in [objects, process, exec, task] {
        for retired in [
            "FdTable",
            "FD_BASE",
            "PROCESS_MAX_FDS",
            "FD_CLOEXEC",
            "close_cloexec_fds",
            "max_fds",
        ] {
            assert!(
                !source.contains(retired),
                "kernel descriptor policy restored: {retired}"
            );
        }
    }
    assert!(!objects.contains("from_open_flags"));
    assert!(!objects.contains("fd_remote"));
    assert!(!objects.contains("is_remote"));
    assert!(!include_str!("../../../core/src/syscall/fs.rs").contains("close_remote_fd_from_kernel"));
    assert!(objects.contains("pub struct FileHandle"));
    assert!(objects.contains("pub open: Arc<SpinLock<OpenFile>>"));
    assert!(process.contains("object_handles:"));
    assert!(process.contains("retain_launch_context_handles_for_exec"));
}

#[test]
fn retired_posix_descriptor_and_stat_handlers_do_not_remain_in_the_kernel() {
    let filesystem = include_str!("../../../core/src/syscall/fs.rs");
    let dispatch = include_str!("../../../core/src/syscall/mod.rs");
    for name in [
        "open",
        "close",
        "read",
        "getdents64",
        "file_open",
        "file_close",
        "file_read",
        "file_read_dir",
        "fcntl",
        "dup",
        "dup2",
        "fsync",
        "fdatasync",
        "ftruncate",
        "stat",
        "fstat",
        "newfstatat",
        "statfs",
        "openat",
        "file_open_at",
    ] {
        assert!(
            !filesystem.contains(&format!("pub fn {name}(")),
            "retired kernel handler {name} was restored"
        );
        assert!(
            !dispatch.contains(&format!("fs::{name}(")),
            "retired handler {name} gained a syscall dispatch"
        );
    }
    assert!(!filesystem.contains("LINUX_STAT_SIZE"));
    assert!(!filesystem.contains("fn write_stat_buf("));
    assert!(!filesystem.contains("fn stat_resolved("));
}

#[test]
fn retired_openat_has_no_native_abi_wrapper_or_reserved_number() {
    let abi = include_str!("../../../core/crates/abi/src/lib.rs");
    let platform = include_str!("../../../user/crates/platform/src/lib.rs");
    let example = include_str!("../../../core/examples/user/src/lib.rs");
    assert!(!abi.contains("FileOpenAt"));
    assert!(!abi.contains("= 561"));
    assert!(!platform.contains("pub fn openat("));
    assert!(!platform.contains("pub fn openat_path("));
    assert!(!example.contains("SYS_FILE_OPEN_AT"));
}
