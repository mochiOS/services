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

static TERMINATED: std::sync::Mutex<Vec<u64>> = std::sync::Mutex::new(Vec::new());

pub mod service_ready {
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct SessionIdentity {
        pub uid: u32,
        pub gid: u32,
    }
}

pub mod handle {
    pub const HANDLE_RIGHT_SIGNAL: u64 = mnu_abi::HANDLE_RIGHT_SIGNAL;
    pub fn close(_: u32) -> Result<(), super::SysError> {
        Ok(())
    }
}

pub mod process {
    pub struct Record {
        pub pid: u64,
        pub state: u64,
        pub parent_pid: u64,
        pub cpu_ticks: u64,
        pub memory_bytes: u64,
        pub thread_count: u64,
    }
    pub fn thread_security_context(
        thread: u64,
    ) -> Result<mnu_abi::ThreadSecurityContext, super::SysError> {
        let process_id = match thread {
            42 => 19,
            43 => 20,
            44 => 21,
            _ => return Err(super::SysError),
        };
        Ok(mnu_abi::ThreadSecurityContext {
            thread_id: thread,
            process_id,
            ..Default::default()
        })
    }
    pub fn list(_: usize) -> Result<Vec<Record>, super::SysError> {
        Ok([(23, 22), (22, 19), (99, 20)]
            .into_iter()
            .map(|(pid, parent_pid)| Record {
                pid,
                parent_pid,
                state: 1,
                cpu_ticks: 0,
                memory_bytes: 0,
                thread_count: 1,
            })
            .collect())
    }
    pub fn open_handle_for_process_id(pid: u64, rights: u64) -> Result<u32, super::SysError> {
        assert_eq!(rights, super::handle::HANDLE_RIGHT_SIGNAL);
        Ok(pid as u32)
    }
    pub fn terminate_handle(handle: u32, exit_code: u64) -> Result<(), super::SysError> {
        assert_eq!(exit_code, 1);
        super::TERMINATED.lock().unwrap().push(handle as u64);
        Ok(())
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
    let native = launcher.split("fn spawn_native_session(").nth(1).unwrap()
        .split("fn append_posix_handle(").next().unwrap();
    assert!(native.contains("NativeProcess::create_with_rollback"));
    let compact: String = native.chars().filter(|character| !character.is_whitespace()).collect();
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
fn session_authentication_and_teardown_keep_process_owners_not_launch_threads() {
    let identity = service_ready::SessionIdentity {
        uid: 1000,
        gid: 1000,
    };
    let session =
        production::ActiveSession::from_launch_threads(1, identity, Some(44), 43, 42).unwrap();
    assert_eq!(session.binder_pid, 19);
    assert_eq!(session.workspace_pid, 20);
    assert_eq!(session.linux_pid, Some(21));
    assert_eq!(session.identity, identity);
    production::terminate_process_tree(session.binder_pid).unwrap();
    assert_eq!(*TERMINATED.lock().unwrap(), [23, 22, 19]);
    let session =
        production::ActiveSession::from_launch_threads(1, identity, None, 43, 42).unwrap();
    assert_eq!(session.linux_pid, None);
}

#[test]
fn session_identity_resolution_does_not_fall_back_to_unverified_launch_ids() {
    let identity = service_ready::SessionIdentity {
        uid: 1000,
        gid: 1000,
    };
    for (linux, workspace, binder) in [(Some(99), 43, 42), (None, 99, 42), (None, 43, 99)] {
        assert_eq!(
            production::ActiveSession::from_launch_threads(1, identity, linux, workspace, binder),
            Err(SysError)
        );
    }
}
