#[test]
fn legacy_seek_is_removed_from_abi_dispatch_and_kernel_fd_semantics() {
    let abi = include_str!("../../../core/crates/abi/src/lib.rs");
    let dispatch = include_str!("../../../core/src/syscall/mod.rs");
    let filesystem = include_str!("../../../core/src/syscall/fs.rs");
    let platform = include_str!("../../../user/crates/platform/src/lib.rs");
    assert!(!abi.contains("FileSeek"));
    assert!(!abi.contains("= 565"));
    assert!(!dispatch.contains("SyscallNumber::FileSeek"));
    assert!(!filesystem.contains("pub fn file_seek("));
    assert!(!filesystem.contains("pub fn seek(fd:"));
    assert!(!platform.contains("SyscallNumber::FileSeek"));
    assert!(!platform.contains("mod file_read;"));
    assert!(dispatch.contains("SyscallNumber::HandleSeek"));
    assert!(!filesystem.contains("fn seek_file_handle("));
    let handles = include_str!("../../../core/src/syscall/handle.rs");
    let seek = handles
        .split("pub fn seek(")
        .nth(1)
        .unwrap()
        .split("pub fn read_at(")
        .next()
        .unwrap();
    assert!(!seek.contains("KernelObject::File("));
    assert!(seek.contains("object_native(raw, HandleRights::SEEK)"));
    assert!(handles.contains("KernelObject::Provider(provider) => provider_seek("));
}
