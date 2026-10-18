#[path = "../../user/src/status.rs"]
mod account_status;

#[path = "../../service-manager/src/portal_status.rs"]
mod portal_status;

use mochi_user_platform::{session_control, syscall};
use mochios_user_protocol::Status;

#[test]
fn io_errors_are_converted_before_account_reply_or_readiness_notification() {
    for raw in [2, 5, 13, 22, 36, 38, 75, 95] {
        let error = std::io::Error::from_raw_os_error(raw);
        let status = account_status::io_status(&error);
        assert_eq!(status, -raw);
        assert_eq!(
            account_status::wire_status(i64::from(status) as u64),
            status
        );
    }
    for error in [
        std::io::Error::other("no OS errno"),
        std::io::Error::from_raw_os_error(0),
        std::io::Error::from_raw_os_error(-91),
    ] {
        assert_eq!(account_status::io_status(&error), -5);
    }
    let storage = include_str!("../../user/src/storage.rs");
    assert!(storage.contains("crate::status::io_status(&self.source)"));
    let main = include_str!("../../user/src/main.rs");
    assert!(main.contains("let status = error.status();"));
    assert!(main.contains("user_service::status::io_status(&error)"));
    assert!(!main.contains("fn errno(error:"));
}

#[test]
fn authentication_denial_preserves_eacces_through_the_account_protocol() {
    for raw in [13, syscall::EACCES] {
        let status = account_status::wire_status(raw);
        assert_eq!(status, -13);
        let reply = Status {
            request_id: 5,
            status,
            generation: 9,
        };
        let mut bytes = [0; mochios_user_protocol::STATUS_LEN];
        let length = reply.encode(&mut bytes).unwrap();
        let decoded = Status::decode(&bytes[..length]).unwrap();
        assert_eq!(decoded.request_id, 5);
        assert_eq!(decoded.status, syscall::EACCES as i32);
        assert_eq!(decoded.generation, 9);
    }
}

#[test]
fn account_status_accepts_both_errno_forms_and_rejects_unrepresentable_errors() {
    assert_eq!(account_status::wire_status(0), 0);
    for (raw, expected) in [
        (5, -5),
        (syscall::EIO, -5),
        (22, -22),
        (syscall::EINVAL, -22),
    ] {
        assert_eq!(account_status::wire_status(raw), expected);
    }
    for raw in [i64::MIN as u64, i64::MAX as u64, (i32::MAX as u64) + 1] {
        assert_eq!(account_status::wire_status(raw), -5);
    }
}

#[test]
fn account_protocol_translates_native_tags_at_the_userspace_boundary() {
    use syscall::NativeError;
    for (error, expected) in [
        (NativeError::LimitExceeded, -75),
        (NativeError::InvalidAddress, -14),
        (NativeError::ResourceUnavailable, -12),
        (NativeError::BackingFailure, -5),
        (NativeError::InvalidArgument, -22),
        (NativeError::AccessDenied, -13),
        (NativeError::NotReady, -11),
        (NativeError::AlreadyExists, -17),
        (NativeError::NotFound, -2),
        (NativeError::PeerClosed, -32),
        (NativeError::Unsupported, -95),
    ] {
        let raw = error.into_raw();
        for input in [raw, (raw as i64).unsigned_abs()] {
            let reply = Status {
                request_id: 5,
                status: account_status::wire_status(input),
                generation: 9,
            };
            let mut bytes = [0; mochios_user_protocol::STATUS_LEN];
            let length = reply.encode(&mut bytes).unwrap();
            let decoded = Status::decode(&bytes[..length]).unwrap();
            assert_eq!(decoded.status, expected);
            assert_eq!(decoded.request_id, 5);
            assert_eq!(decoded.generation, 9);
        }
    }
    let unknown = (NativeError::Unsupported.into_raw() & !0xffff) | 0xffff;
    assert_eq!(account_status::wire_status(unknown), -5);
    assert_eq!(
        account_status::wire_status((unknown as i64).unsigned_abs()),
        -5
    );
}

#[test]
fn session_rejection_retains_signed_status_and_session_identity() {
    for raw in [
        syscall::EINVAL,
        syscall::EPERM,
        syscall::EACCES,
        syscall::EIO,
    ] {
        let response = session_control::Response {
            action: session_control::Action::Lock,
            session_id: 7,
            status: raw as i32,
        };
        let decoded =
            session_control::decode_response(&session_control::encode_response(response)).unwrap();
        assert_eq!(decoded, response);
        assert!(decoded.status < 0);
    }
}

#[test]
fn portal_rejection_preserves_both_native_and_prompt_errno_encodings() {
    for (raw, expected) in [
        (13, -13),
        (syscall::EACCES, -13),
        (syscall::EINVAL, -22),
        (5, -5),
    ] {
        assert_eq!(portal_status::failure_status(raw), expected);
    }
    for raw in [0, i64::MIN as u64, i64::MAX as u64] {
        assert_eq!(portal_status::failure_status(raw), -5);
    }
    let source = include_str!("../../service-manager/src/portal.rs");
    assert!(!source.contains("-(error as i32)"));
    assert_eq!(
        source
            .matches("crate::portal_status::failure_status")
            .count(),
        3
    );
}

#[test]
fn account_and_security_consumers_do_not_invert_native_error_constants() {
    for source in [
        include_str!("../../secure-ui/src/authentication.rs"),
        include_str!("../../secure-ui/src/permission_server.rs"),
        include_str!("../../secure-ui/src/setup.rs"),
        include_str!("../../service-manager/src/bootstrap.rs"),
        include_str!("../../service-manager/src/portal.rs"),
        include_str!("../../mboot-agent/src/runtime.rs"),
    ] {
        let compact: String = source.chars().filter(|c| !c.is_whitespace()).collect();
        assert!(!compact.contains("-(mochi_user_syscall::E"));
    }
    assert!(
        include_str!("../../user/src/main.rs")
            .contains("user_service::status::wire_status(status)")
    );
    assert!(
        include_str!("../../secure-ui/src/authentication.rs")
            .contains("status.status == mochi_user_syscall::EACCES as i32")
    );
}

#[test]
fn spawn_errors_accept_native_constants_and_positive_remote_errors() {
    for (raw, expected) in [(syscall::EINVAL, 22), (22, 22), (syscall::EIO, 5), (5, 5)] {
        let error = syscall::SysError::from_raw(portal_status::failure_status(raw) as i64);
        assert_eq!(error.errno(), Some(expected));
    }
    let source = include_str!("../../service-manager/src/spawn_support.rs");
    let start = source.find("pub(crate) fn sys_error(").unwrap();
    let end = start
        + source[start..]
            .find("pub(crate) fn call_with_wait(")
            .unwrap();
    assert!(source[start..end].contains("crate::portal_status::failure_status(errno)"));
    assert!(!source[start..end].contains("-(errno as i64)"));
}
