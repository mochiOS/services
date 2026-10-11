extern crate self as mochi_user_platform;

pub mod handle {
    pub use mnu_abi::{HANDLE_RIGHT_SIGNAL, HANDLE_RIGHT_WAIT};
}

pub struct Error(i32);
impl Error {
    pub fn errno(&self) -> Option<u32> {
        self.0
            .checked_neg()
            .and_then(|value| u32::try_from(value).ok())
    }
}

pub mod process {
    pub fn handle_status(handle: u32) -> Result<mnu_abi::ProcessStatus, crate::Error> {
        match handle {
            52 => Ok(mnu_abi::ProcessStatus {
                process_id: 1030,
                ..Default::default()
            }),
            53 => Ok(mnu_abi::ProcessStatus::default()),
            54 => Err(crate::Error(-22)), // wrong native object type
            _ => Err(crate::Error(-9)),
        }
    }
}

#[path = "../src/process_control.rs"]
mod production;

fn root(handle: u32, rights: u64) -> posix_service::AttachedObject<u32> {
    posix_service::AttachedObject { handle, rights }
}

#[test]
fn tree_root_identity_comes_from_the_explicit_native_process_object() {
    let result = production::authenticated_tree_root(root(
        52,
        handle::HANDLE_RIGHT_WAIT | handle::HANDLE_RIGHT_SIGNAL,
    ))
    .unwrap();
    assert_eq!(result.handle, 52);
    assert_eq!(result.process_id, 1030);
}

#[test]
fn tree_root_rejects_missing_or_excess_rights_and_invalid_objects() {
    let required = handle::HANDLE_RIGHT_WAIT | handle::HANDLE_RIGHT_SIGNAL;
    for rights in [
        0,
        handle::HANDLE_RIGHT_WAIT,
        handle::HANDLE_RIGHT_SIGNAL,
        required | mnu_abi::HANDLE_RIGHT_TRANSFER,
    ] {
        assert_eq!(
            production::authenticated_tree_root(root(52, rights)),
            Err(-22)
        );
    }
    for (object, status) in [(0, -22), (53, -22), (54, -22), (55, -9)] {
        assert_eq!(
            production::authenticated_tree_root(root(object, required)),
            Err(status)
        );
    }
}

#[test]
fn tree_dispatch_requires_one_explicit_object_and_releases_request_reference() {
    let source = include_str!("../src/main.rs");
    let branch = source
        .split("if header.opcode == protocol::OP_PROCESS_TREE_TERMINATE")
        .nth(1)
        .unwrap()
        .split("if header.opcode == protocol::OP_PROCESS_LAUNCH_ABORT")
        .next()
        .unwrap();
    assert!(branch.contains("header.flags == 0"));
    assert!(branch.contains("payload.is_empty()"));
    assert!(branch.contains("attachments.len() == 1"));
    assert!(branch.contains("authenticated_tree_root(attachments[0])"));
    assert!(branch.contains("service.terminate_launched_tree"));
    assert!(!branch.contains("retained_handle ="));
    let library = include_str!("../src/lib.rs");
    assert!(library.contains("| protocol::OP_PROCESS_TREE_TERMINATE"));
}

#[test]
fn native_dispatch_probe_uses_current_wire_and_handle_abi() {
    use mnu_abi::SyscallNumber;
    assert_eq!(SyscallNumber::HandleClose as u64, 626);
    assert_eq!(SyscallNumber::LaunchHandleGet as u64, 628);
    assert_eq!(SyscallNumber::IpcCreateHandle as u64, 629);
    assert_eq!(SyscallNumber::IpcCallObjectHandles as u64, 632);
    assert_eq!(mochios_posix_protocol::VERSION, 1);
    assert_eq!(mochios_posix_protocol::HEADER_LEN, 32);
    assert_eq!(mochios_posix_protocol::OP_PROCESS_TREE_TERMINATE, 61);
    assert_eq!(mnu_abi::HANDLE_RIGHT_SEND, 1 << 2);
}
