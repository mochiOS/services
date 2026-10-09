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
