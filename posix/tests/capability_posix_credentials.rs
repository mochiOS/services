extern crate self as mochi_user_platform;

use mochios_posix_protocol::SessionInfo;
use std::sync::Mutex;

pub mod syscall {
    pub const EACCES: u64 = (-13i64) as u64;
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct SysError(i64);
    impl SysError {
        pub fn from_raw(raw: i64) -> Self {
            Self(raw)
        }
    }
    pub use mnu_abi::ThreadSecurityContext;
}

#[derive(Default)]
struct State {
    events: Vec<&'static str>,
    fail_identity: Option<i64>,
    fail_open: bool,
    fail_status: bool,
    different_process: bool,
}
static STATE: Mutex<State> = Mutex::new(State {
    events: Vec::new(),
    fail_identity: None,
    fail_open: false,
    fail_status: false,
    different_process: false,
});

pub mod handle {
    pub type Handle = u32;
    pub const HANDLE_RIGHT_WAIT: u64 = mnu_abi::HANDLE_RIGHT_WAIT;
    pub const HANDLE_RIGHT_TRANSFER: u64 = mnu_abi::HANDLE_RIGHT_TRANSFER;
    pub fn close(handle: u32) -> Result<(), crate::syscall::SysError> {
        assert_eq!(handle, 7);
        crate::STATE.lock().unwrap().events.push("close");
        Ok(())
    }
}
pub mod process {
    pub struct Status {
        pub process_id: u64,
    }
    pub fn thread_security_context(
        endpoint: u64,
    ) -> Result<crate::syscall::ThreadSecurityContext, crate::syscall::SysError> {
        assert_eq!(endpoint, 12);
        crate::STATE.lock().unwrap().events.push("native-identity");
        if let Some(error) = crate::STATE.lock().unwrap().fail_identity {
            return Err(crate::syscall::SysError::from_raw(error));
        }
        Ok(crate::syscall::ThreadSecurityContext {
            process_id: 31,
            package_id: [0x34; mnu_abi::APPLICATION_ID_FIELD_LEN],
            developer_id: [0x12; mnu_abi::APPLICATION_ID_FIELD_LEN],
            package_id_len: 7,
            developer_id_len: 9,
            subject_key_id: [0x56; 32],
            provenance: 2,
            ..Default::default()
        })
    }
    pub fn open_handle_for_endpoint(
        endpoint: u64,
        rights: u64,
    ) -> Result<u32, crate::syscall::SysError> {
        assert_eq!(endpoint, 12);
        assert_eq!(
            rights,
            crate::handle::HANDLE_RIGHT_WAIT | crate::handle::HANDLE_RIGHT_TRANSFER
        );
        let mut state = crate::STATE.lock().unwrap();
        state.events.push("open-authenticated-owner");
        if state.fail_open {
            Err(crate::syscall::SysError::from_raw(-13))
        } else {
            Ok(7)
        }
    }
    pub fn handle_status(handle: u32) -> Result<Status, crate::syscall::SysError> {
        assert_eq!(handle, 7);
        let mut state = crate::STATE.lock().unwrap();
        state.events.push("status");
        if state.fail_status {
            Err(crate::syscall::SysError::from_raw(-9))
        } else {
            Ok(Status {
                process_id: if state.different_process { 32 } else { 31 },
            })
        }
    }
}

#[path = "../../capability/src/requester_context.rs"]
mod production;

#[test]
fn scope_credentials_are_bound_to_the_native_sender_before_grant_policy() {
    let requester = production::RequesterContext {
        process_id: 31,
        ..Default::default()
    };
    let scope = mochios_posix_protocol::read_scope::SourceInfo {
        process_id: 31,
        session: SessionInfo {
            effective_uid: 501,
            effective_gid: 20,
            ..Default::default()
        },
    };
    assert_eq!(
        production::scope_session(&requester, scope).unwrap(),
        scope.session
    );
    assert_eq!(
        requester.effective_uid, 0,
        "the broker must not substitute a current credential observation"
    );
    for process_id in [0, 32] {
        assert_eq!(
            production::scope_session(
                &requester,
                mochios_posix_protocol::read_scope::SourceInfo {
                    process_id,
                    ..scope
                }
            ),
            Err(syscall::SysError::from_raw(
                mochios_posix_protocol::STATUS_EPERM as i64
            ))
        );
    }
}

#[test]
fn credentials_never_fall_back_to_native_root_and_every_acquired_handle_is_closed() {
    let info = production::read(12, |object| {
        assert_eq!(
            (object.handle, object.rights),
            (7, handle::HANDLE_RIGHT_WAIT)
        );
        STATE.lock().unwrap().events.push("posix-credentials");
        Ok(SessionInfo {
            effective_uid: 505,
            effective_gid: 24,
            ..Default::default()
        })
    })
    .unwrap();
    assert_eq!(info.process_id, 31);
    assert_eq!(info.package_id, [0x34; mnu_abi::APPLICATION_ID_FIELD_LEN]);
    assert_eq!(info.developer_id, [0x12; mnu_abi::APPLICATION_ID_FIELD_LEN]);
    assert_eq!((info.package_id_len, info.developer_id_len), (7, 9));
    assert_eq!(info.subject_key_id, [0x56; 32]);
    assert_eq!(info.provenance, 2);
    assert_eq!((info.effective_uid, info.effective_gid), (505, 24));
    assert_eq!(
        STATE.lock().unwrap().events,
        [
            "native-identity",
            "open-authenticated-owner",
            "status",
            "posix-credentials",
            "close"
        ]
    );
    for error in [
        mnu_abi::status::Error::AccessDenied,
        mnu_abi::status::Error::NotFound,
        mnu_abi::status::Error::NotReady,
        mnu_abi::status::Error::InvalidAddress,
        mnu_abi::status::Error::ResourceUnavailable,
        mnu_abi::status::Error::BackingFailure,
    ] {
        let raw = error.into_raw() as i64;
        *STATE.lock().unwrap() = State {
            fail_identity: Some(raw),
            ..Default::default()
        };
        assert_eq!(
            production::read(12, |_| panic!("must not query unauthenticated credentials")),
            Err(syscall::SysError::from_raw(raw))
        );
        assert_eq!(STATE.lock().unwrap().events, ["native-identity"]);
    }
    for error in [-3, -13, -5, -11] {
        *STATE.lock().unwrap() = State::default();
        assert_eq!(
            production::read(12, |_| Err(syscall::SysError::from_raw(error))),
            Err(syscall::SysError::from_raw(error))
        );
        assert_eq!(STATE.lock().unwrap().events.last(), Some(&"close"));
    }
    for (fail_open, fail_status, different_process, expected) in [
        (true, false, false, -13),
        (false, true, false, -9),
        (false, false, true, -13),
    ] {
        *STATE.lock().unwrap() = State {
            fail_open,
            fail_status,
            different_process,
            ..Default::default()
        };
        assert_eq!(
            production::read(12, |_| panic!("must not query an unauthenticated subject")),
            Err(syscall::SysError::from_raw(expected))
        );
        assert_eq!(
            STATE.lock().unwrap().events.last(),
            Some(&if fail_open {
                "open-authenticated-owner"
            } else {
                "close"
            })
        );
    }
}

#[test]
fn all_permission_paths_use_the_posix_credential_adapter() {
    for (source, old) in [
        (
            include_str!("../../capability/src/app_spawn.rs"),
            "thread_security_context(sender)?",
        ),
        (
            include_str!("../../capability/src/server.rs"),
            "thread_security_context(sender)?",
        ),
        (
            include_str!("../../capability/src/dynamic_grant.rs"),
            "thread_security_context(requester_thread)?",
        ),
        (
            include_str!("../../capability/src/persistent_grant.rs"),
            "thread_security_context(requester_thread)?",
        ),
    ] {
        assert!(!source.contains(old));
        assert!(source.contains("requester_context("));
    }
    assert!(include_str!("../../capability/manifest.toml").contains("\"process.inspect\""));
    let adapter = include_str!("../../capability/src/persistent_grant.rs");
    assert!(adapter.contains("client.process_session_info(process)"));
    assert!(!adapter.contains("ThreadSecurityContext"));
    let context = include_str!("../../capability/src/requester_context.rs");
    assert!(!context.contains("native.effective_uid"));
    assert!(!context.contains("native.effective_gid"));
    assert!(!context.contains("context.effective_uid ="));
    assert!(!context.contains("context.effective_gid ="));
}
