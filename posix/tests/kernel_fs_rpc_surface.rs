#[test]
fn kernel_has_no_filesystem_mount_registration_or_wire_protocol() {
    let abi = include_str!("../../../core/crates/abi/src/lib.rs");
    let dispatch = include_str!("../../../core/src/syscall/mod.rs");
    let fs = include_str!("../../../core/src/syscall/fs.rs");
    let protocol = include_str!("../../../user/crates/filesystem-protocol/src/lib.rs");
    for source in [abi, dispatch, fs, protocol] {
        for removed in [
            "FilesystemRegister",
            "FilesystemMount",
            "SYS_FILESYSTEM_REGISTER",
            "SYS_FILESYSTEM_MOUNT",
            "fn filesystem_register(",
            "fn filesystem_mount(",
        ] {
            assert!(
                !source.contains(removed),
                "retired filesystem interface {removed} returned"
            );
        }
    }
    assert!(!abi.contains("= 624") && !abi.contains("= 625"));
    assert!(!include_str!("../../../core/src/lib.rs").contains("pub mod vfs;"));
    assert!(!include_str!("../../../core/Cargo.toml").contains("mochios-filesystem-protocol"));
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../core/src/vfs");
    assert!(!root.join("mod.rs").exists());
    assert!(!root.join("userspace.rs").exists());
}

#[test]
fn filesystem_service_owns_namespace_and_delegates_only_a_generic_endpoint() {
    let source = include_str!("../../filesystem/src/main.rs");
    for removed in [
        "register_filesystem(",
        "mount_filesystem(",
        "legacy_endpoint",
        "COMPATIBILITY_ROOT_FILESYSTEM_ID",
        "SYS_FILESYSTEM_",
    ] {
        assert!(!source.contains(removed));
    }
    assert!(source.contains("FilesystemService::new(fs)"));
    assert!(source.contains("mount_named_volume(b\"/\", b\"system\", system, b\"/system\")"));
    assert!(source.contains("platform::ipc::create_handle()"));
    assert!(source.contains(
        "platform::service_ready::notify_handle(ready_target, 0, endpoint, delegated_rights)"
    ));
    assert!(source.contains("platform::ipc::wait_object_handles("));
    assert!(source.contains("protocol::decode_credentials_payload(payload)"));
    assert!(source.contains("decode_path_anchors("));
    assert!(source.contains("close_attached_handles(&attached)"));
    assert!(!include_str!("../../filesystem/manifest.toml").contains("service.register"));
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
