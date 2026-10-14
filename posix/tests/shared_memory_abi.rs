use mnu_abi::{
    HANDLE_RIGHT_DUPLICATE, HANDLE_RIGHT_MAP, HANDLE_RIGHT_TRANSFER, MEMORY_MAP_SHARED,
    SyscallNumber,
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
    assert_eq!(mnu_abi::IPC_DELIVERY_ENDPOINT_HANDLE, 2);
    assert_eq!(core::mem::size_of::<mnu_abi::IpcObjectHandles>(), 72);
}

#[test]
fn mutable_mapping_share_entry_has_no_abi_dispatch_or_sample_wrapper() {
    let abi = include_str!("../../../core/crates/abi/src/lib.rs");
    for source in [
        abi,
        include_str!("../../../core/src/syscall/mod.rs"),
        include_str!("../../../core/src/syscall/process.rs"),
        include_str!("../../../core/examples/user/src/lib.rs"),
        include_str!("../../../core/examples/user/src/main.rs"),
    ] {
        assert!(!source.contains("MemoryShare"));
        assert!(!source.contains("memory_share"));
    }
    let region = include_str!("../../../core/src/task/process.rs");
    assert!(!region.contains("fn set_shared("));
    let enumeration = abi
        .split("pub enum SyscallNumber {")
        .nth(1)
        .unwrap()
        .split('}')
        .next()
        .unwrap();
    assert!(!enumeration.lines().any(|line| {
        line.split('=')
            .nth(1)
            .is_some_and(|value| value.trim().trim_end_matches(',') == "585")
    }));
    let sample = include_str!("../../../core/examples/user/src/main.rs");
    assert!(sample.contains("MemoryObject::create(PAGE_SIZE)"));
    assert!(sample.contains("object.map(0, PAGE_SIZE, 3)"));
    assert!(sample.contains("drop(object)"));
    assert!(sample.contains("mapping.unmap()"));
    assert!(sample.contains("alias.unmap()"));
}
