use mnu_abi::{
    SyscallNumber, HANDLE_RIGHT_DUPLICATE, HANDLE_RIGHT_MAP, HANDLE_RIGHT_TRANSFER,
    MEMORY_MAP_SHARED,
};

#[test]
fn native_probe_uses_the_current_generic_handle_and_memory_abi() {
    let source = include_str!("native_shared_memory.c");
    for (name, number) in [
        ("MEMORY_MAP", SyscallNumber::MemoryMap),
        ("MEMORY_UNMAP", SyscallNumber::MemoryUnmap),
        ("MEMORY_PROTECT", SyscallNumber::MemoryProtect),
        ("IPC_REPLY", SyscallNumber::IpcReply),
        ("HANDLE_CLOSE", SyscallNumber::HandleClose),
        ("HANDLE_DUPLICATE", SyscallNumber::HandleDuplicate),
        ("IPC_CREATE", SyscallNumber::IpcCreateHandle),
        ("IPC_SEND_HANDLES", SyscallNumber::IpcSendObjectHandles),
        ("IPC_RECV_HANDLES", SyscallNumber::IpcRecvObjectHandles),
        ("IPC_CALL_HANDLES", SyscallNumber::IpcCallObjectHandles),
        ("MEMORY_OBJECT_CREATE", SyscallNumber::MemoryObjectCreate),
        ("MEMORY_OBJECT_LENGTH", SyscallNumber::MemoryObjectLength),
    ] {
        assert!(
            source.contains(&format!("{name} = {}", number as u64)),
            "stale native probe constant {name}"
        );
    }
    assert_eq!(MEMORY_MAP_SHARED, 2);
    assert_eq!(HANDLE_RIGHT_MAP, 64);
    assert_eq!(HANDLE_RIGHT_DUPLICATE, 1 << 62);
    assert_eq!(HANDLE_RIGHT_TRANSFER, 1 << 63);
    assert_eq!(mnu_abi::IPC_MAX_OBJECT_HANDLES, 4);
    assert_eq!(core::mem::size_of::<mnu_abi::IpcObjectHandles>(), 72);
}
