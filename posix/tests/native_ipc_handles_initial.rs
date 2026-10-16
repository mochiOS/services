#[test]
fn freestanding_ipc_probe_matches_current_native_abi() {
    use mnu_abi::{SyscallNumber as S, status::Error};
    let source = include_str!("native_ipc_handles_initial.c");
    for (name, number) in [
        ("CLOSE", S::HandleClose),
        ("DUPLICATE", S::HandleDuplicate),
        ("CREATE_ENDPOINT", S::IpcCreateHandle),
        ("SEND", S::IpcSendObjectHandles),
        ("RECEIVE", S::IpcRecvObjectHandles),
        ("PAIR", S::StreamPairCreate),
        ("DEBUG", S::DebugWrite),
        ("WRITE", S::StreamWrite),
        ("TABLE", S::HandleTableRead),
        ("READ", S::StreamRead),
        ("YIELD", S::ThreadYield),
    ] {
        assert!(source.contains(&format!("{name} = {}", number as u64)));
    }
    for (name, error) in [
        ("INVALID_ARGUMENT", Error::InvalidArgument),
        ("INVALID_ADDRESS", Error::InvalidAddress),
        ("ACCESS_DENIED", Error::AccessDenied),
        ("RESOURCE_UNAVAILABLE", Error::ResourceUnavailable),
        ("PEER_CLOSED", Error::PeerClosed),
    ] {
        assert!(source.contains(&format!(
            "#define {name} INT64_C({})",
            error.into_raw() as i64
        )));
    }
    assert_eq!(core::mem::size_of::<mnu_abi::IpcObjectHandles>(), 72);
    assert_eq!(mnu_abi::IPC_DELIVERY_ENDPOINT_HANDLE, 2);
    assert_eq!(mnu_abi::HANDLE_RIGHT_READ, 1);
    assert!(!source.contains("#include <stdio.h>"));
    assert!(!source.contains("#include <unistd.h>"));
    let application_probe = include_str!("native_object_delivery.c");
    assert!(application_probe.contains(&format!(
        "#define NATIVE_INVALID_ARGUMENT INT64_C({})",
        Error::InvalidArgument.into_raw() as i64
    )));
    assert!(!application_probe.contains("(uintptr_t)&handles) == -22"));
}
