#[test]
fn retired_posix_descriptor_and_stat_handlers_do_not_remain_in_the_kernel() {
    let filesystem = include_str!("../../../core/src/syscall/fs.rs");
    let dispatch = include_str!("../../../core/src/syscall/mod.rs");
    for name in [
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
