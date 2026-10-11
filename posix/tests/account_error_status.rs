#[path = "../../user/src/status.rs"]
mod account_status;

#[path = "../../service-manager/src/portal_status.rs"]
mod portal_status;

use mochi_user_platform::{session_control, syscall};
use mochios_user_protocol::Status;

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
