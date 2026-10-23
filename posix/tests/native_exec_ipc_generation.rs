//! ABI drift checks for the separately linked native integration executable.
//! These checks do not execute image replacement or substitute for its KVM run.
use mnu_abi::{status::Error, SyscallNumber as S};

#[test]
fn native_image_ipc_probe_uses_current_mechanism_abi() {
    let source = include_str!("native_exec_ipc_generation.c");
    for (name, syscall) in [
        ("CLOSE", S::HandleClose),
        ("CONTEXT_GET", S::LaunchHandleGet),
        ("CREATE_ENDPOINT", S::IpcCreateHandle),
        ("SEND", S::IpcSendObjectHandles),
        ("RECEIVE", S::IpcRecvObjectHandles),
        ("CONTEXT_SET", S::ContextHandleSet),
        ("PAIR", S::StreamPairCreate),
        ("CURRENT_THREAD", S::ThreadHandleCreate),
        ("THREAD_STATUS", S::ThreadHandleStatus),
        ("WRITE", S::StreamWrite),
    ] {
        assert!(source.contains(&format!("{name} = {}", syscall as u64)));
    }
    for (name, error) in [
        ("NOT_FOUND", Error::NotFound),
        ("NOT_READY", Error::NotReady),
        ("PEER_CLOSED", Error::PeerClosed),
    ] {
        assert!(source.contains(&format!(
            "#define {name} INT64_C({})",
            error.into_raw() as i64
        )));
    }
    assert_eq!(size_of::<mnu_abi::IpcObjectHandles>(), 72);
    assert_eq!(size_of::<mnu_abi::ThreadStatus>(), 24);
    assert_eq!(mnu_abi::HANDLE_RIGHT_READ, 1);
}
