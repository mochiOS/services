#[test]
fn transitional_kernel_transport_cannot_construct_removed_posix_requests() {
    let source = include_str!("../../../core/src/vfs/userspace.rs");
    let functions: Vec<_> = source
        .lines()
        .filter_map(|line| {
            line.strip_prefix("pub fn ")
                .and_then(|line| line.split('(').next())
        })
        .collect();
    assert_eq!(functions, ["lookup_size"]);
    for opcode in [
        "OP_MOUNT",
        "OP_OPEN",
        "OP_SETATTR",
        "OP_CREATE",
        "OP_UNLINK",
        "OP_SYMLINK",
        "OP_RENAME",
        "OP_TRUNCATE",
        "OP_READLINK",
        "OP_READDIR",
        "OP_SYNC",
        "LOOKUP_FOLLOW_SYMLINKS",
    ] {
        assert!(
            !source.contains(&format!("protocol::{opcode}")),
            "{opcode} returned to kernel transport"
        );
    }
    assert!(!source.contains("uid:") && !source.contains("gid:") && !source.contains("mode:"));
    assert!(!source.contains("DirectoryBatch"));
}

#[test]
fn filesystem_namespace_operations_still_exist_in_user_space() {
    let service = include_str!("../../filesystem/src/service.rs");
    for opcode in [
        "OP_SETATTR",
        "OP_CREATE",
        "OP_UNLINK",
        "OP_SYMLINK",
        "OP_RENAME",
        "OP_TRUNCATE",
        "OP_READLINK",
        "OP_READDIR",
        "OP_SYNC",
    ] {
        assert!(
            service.contains(&format!("protocol::{opcode}")),
            "user-space {opcode} was removed"
        );
    }
    let posix = include_str!("../src/main.rs");
    assert!(posix.contains("OP_RENAME_AT"));
    assert!(posix.contains("OP_UNLINK_AT"));
}
