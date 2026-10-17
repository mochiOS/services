#[path = "../../linux/src/error.rs"]
mod error;

use error::{HostError, io_status, launch_status, portal_status};
use mboot_protocol::ErrorCode;
use mochi_user_platform::syscall;

#[test]
fn host_launch_failures_keep_the_negative_wire_status() {
    for (failure, expected) in [
        (HostError::Unavailable, -11),
        (HostError::InvalidReply, -5),
        (HostError::Rejected(ErrorCode::PermissionDenied), -13),
        (HostError::Rejected(ErrorCode::Busy), -16),
        (HostError::Rejected(ErrorCode::InvalidArgument), -22),
        (HostError::Rejected(ErrorCode::Internal), -22),
    ] {
        assert_eq!(launch_status(failure), expected);
        assert_eq!(
            syscall::SysError::from_raw(i64::from(launch_status(failure))).errno(),
            Some((-expected) as u64)
        );
    }
}

#[test]
fn portal_failures_keep_their_existing_errno_policy_with_the_correct_sign() {
    assert_eq!(portal_status(HostError::Unavailable), -5);
    assert_eq!(portal_status(HostError::InvalidReply), -22);
    for code in [
        ErrorCode::PermissionDenied,
        ErrorCode::Busy,
        ErrorCode::Internal,
    ] {
        assert_eq!(portal_status(HostError::Rejected(code)), -1);
    }
}

#[test]
fn io_failure_normalization_never_reports_zero_positive_or_overflow() {
    for errno in [1, 2, 5, 11, 13, 22, -13] {
        assert_eq!(
            io_status(std::io::Error::from_raw_os_error(errno)),
            -errno.abs()
        );
    }
    for errno in [0, i32::MIN] {
        assert_eq!(io_status(std::io::Error::from_raw_os_error(errno)), -5);
    }
    assert_eq!(io_status(std::io::Error::other("transport failure")), -5);
}

#[test]
fn native_error_constants_are_already_signed_and_consumers_do_not_negate_them() {
    assert_eq!(syscall::EPERM as i32, -1);
    assert_eq!(mochios_linux_gui_protocol::STATUS_INSTANCE_LIMIT, -28);
    assert_eq!(syscall::EOVERFLOW as i64, -75);
    for source in [
        include_str!("../../linux/src/runtime.rs"),
        include_str!("../../linux/src/portal.rs"),
        include_str!("../../../user/crates/posix-client/src/lib.rs"),
    ] {
        let compact: String = source.chars().filter(|c| !c.is_whitespace()).collect();
        assert!(!compact.contains("-(mochi_user_syscall::E"));
    }
    assert!(
        include_str!("../../linux/src/runtime.rs")
            .contains("crate::error::launch_status as host_status")
    );
    assert!(
        include_str!("../../linux/src/portal.rs")
            .contains("crate::error::{io_status, portal_status as host_status}")
    );
}
