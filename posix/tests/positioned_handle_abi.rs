use mnu_abi::SyscallNumber;
use mochios_posix_client::fd::positioned_offset;

#[test]
fn posix_offsets_are_validated_before_unsigned_native_io() {
    assert_eq!(positioned_offset(-1, 1), None);
    assert_eq!(positioned_offset(i64::MIN, 0), None);
    assert_eq!(positioned_offset(0, usize::MAX), None);
    assert_eq!(positioned_offset(0, 0), Some(0));
    assert_eq!(positioned_offset(i64::MAX, 1), Some(i64::MAX as u64));
}

#[test]
fn positioned_io_uses_native_handles_not_seek_or_posix_rpc() {
    assert_eq!(SyscallNumber::HandleReadAt as u64, 673);
    assert_eq!(SyscallNumber::HandleWriteAt as u64, 674);
    let runtime = include_str!("../../../user/crates/newlib-runtime/src/lib.rs");
    let start = runtime.find("fn positioned_file_io(").unwrap();
    let end = runtime[start..]
        .find("pub unsafe extern \"C\" fn readv(")
        .unwrap();
    let implementation = &runtime[start..start + end];
    assert!(implementation.contains("SyscallNumber::HandleReadAt"));
    assert!(implementation.contains("SyscallNumber::HandleWriteAt"));
    assert!(!implementation.contains("HandleSeek"));
    assert!(!implementation.contains("posix_client()"));
    let kernel = include_str!("../../../core/src/syscall/handle.rs");
    assert!(kernel.contains("object_native(raw, required)"));
    assert!(kernel.contains("HandleRights::WRITE } else { HandleRights::READ"));
}

#[test]
fn native_probe_constants_match_the_current_handle_abi() {
    let source = include_str!("native_positioned_io.c");
    for (name, number) in [
        ("HANDLE_CLOSE", SyscallNumber::HandleClose),
        ("HANDLE_DUPLICATE", SyscallNumber::HandleDuplicate),
        ("MEMORY_OBJECT_CREATE", SyscallNumber::MemoryObjectCreate),
        ("HANDLE_READ_AT", SyscallNumber::HandleReadAt),
        ("HANDLE_WRITE_AT", SyscallNumber::HandleWriteAt),
    ] {
        assert!(source.contains(&format!("{name} = {}", number as u64)));
    }
}
