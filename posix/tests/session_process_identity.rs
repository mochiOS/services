extern crate alloc;
extern crate self as mochi_user_platform;
extern crate self as mochi_user_syscall;

#[derive(Debug, PartialEq, Eq)]
pub struct SysError;
pub const EINVAL: u64 = 22;
impl SysError {
    pub fn from_raw(_: i64) -> Self {
        Self
    }
}

pub mod service_ready {
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct SessionIdentity {
        pub uid: u32,
        pub gid: u32,
    }
}

#[path = "../../service-manager/src/session.rs"]
mod production;

#[test]
fn native_session_ids_are_not_reinterpreted_as_launch_threads() {
    let identity = service_ready::SessionIdentity { uid: 505, gid: 24 };
    let session =
        production::ActiveSession::from_process_ids(1, identity, Some(1044), 1043, 1042).unwrap();
    assert_eq!(
        (session.linux_pid, session.workspace_pid, session.binder_pid),
        (Some(1044), 1043, 1042)
    );
    for (linux, workspace, binder) in [(Some(0), 1043, 1042), (None, 0, 1042), (None, 1043, 0)] {
        assert!(
            production::ActiveSession::from_process_ids(1, identity, linux, workspace, binder)
                .is_err()
        );
    }
}

#[test]
fn session_launcher_registers_credentials_before_resume_without_legacy_creation() {
    let launcher = include_str!("../../service-manager/src/service_launcher.rs");
    assert!(!launcher.contains("spawn_manifest_with_credentials"));
    let native = launcher
        .split("fn spawn_native_session(")
        .nth(1)
        .unwrap()
        .split("fn append_posix_handle(")
        .next()
        .unwrap();
    assert!(native.contains("NativeProcess::create_with_rollback"));
    let compact: String = native
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect();
    assert!(compact.contains("client.register_spawned_child"));
    assert!(native.contains("identity.uid"));
    assert!(native.contains("identity.gid"));
    assert!(native.contains("client.abort_launched_child"));
    assert!(native.contains("close(image.handle)"));
    let runtime = include_str!("../../service-manager/src/bootstrap.rs");
    assert!(!runtime.contains("ActiveSession::from_launch_threads"));
    assert!(runtime.contains("session_processes.insert(id, process)"));
    assert!(runtime.contains("self.wait_ready(ReadyService::Binder, process.watch_target())"));
}

#[test]
fn session_identity_keeps_native_process_ids_and_session_generation_never_becomes_zero() {
    let identity = service_ready::SessionIdentity {
        uid: 1000,
        gid: 1000,
    };
    let session =
        production::ActiveSession::from_process_ids(1, identity, Some(21), 20, 19).unwrap();
    assert_eq!(session.binder_pid, 19);
    assert_eq!(session.workspace_pid, 20);
    assert_eq!(session.linux_pid, Some(21));
    assert_eq!(session.identity, identity);
    assert_eq!(session.next_id(), 2);
    let final_generation = production::ActiveSession {
        id: u64::MAX,
        ..session
    };
    assert_eq!(final_generation.next_id(), 1);
    let session = production::ActiveSession::from_process_ids(1, identity, None, 20, 19).unwrap();
    assert_eq!(session.linux_pid, None);
}

#[test]
fn session_construction_has_no_legacy_thread_or_credential_fallback() {
    let source = include_str!("../../service-manager/src/session.rs");
    assert!(!source.contains("from_launch_threads"));
    assert!(!source.contains("thread_security_context"));
    assert!(!source.contains("ThreadSecurityContext"));
    assert!(source.contains("fn from_process_ids("));
    assert!(!source.contains("process::list"));
    assert!(!source.contains("parent_pid"));
    assert!(!source.contains("open_handle_for_process_id"));
}
