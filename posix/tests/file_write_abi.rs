#[test]
fn legacy_file_write_is_removed_without_a_compatibility_entry() {
    let abi = include_str!("../../../core/crates/abi/src/lib.rs");
    let dispatch = include_str!("../../../core/src/syscall/mod.rs");
    let filesystem = include_str!("../../../core/src/syscall/fs.rs");
    let platform = include_str!("../../../user/crates/platform/src/lib.rs");
    assert!(!abi.contains("FileWrite"));
    assert!(!abi.contains("= 564,"));
    assert!(!dispatch.contains("SyscallNumber::FileWrite"));
    assert!(!filesystem.contains("pub fn file_write("));
    assert!(!filesystem.contains("fn write_impl("));
    assert!(!platform.contains("SyscallNumber::FileWrite"));
    assert!(abi.contains("HandleWrite"));
    assert!(dispatch.contains("SyscallNumber::HandleWrite"));
    let handles = include_str!("../../../core/src/syscall/handle.rs");
    assert!(handles.contains("crate::syscall::fs::write_file_handle"));
    assert!(filesystem.contains("pub(crate) fn write_file_handle("));
    assert!(filesystem.contains("handle.cap.contains(FileHandleCap::WRITE)"));
}
