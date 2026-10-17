use mochi_user_platform::syscall;
use mochios_workspace_protocol as protocol;

#[path = "../../../user/crates/platform/src/workspace/response.rs"]
mod response;

#[path = "../../workspace/src/error.rs"]
mod server_error;

#[test]
fn workspace_error_survives_wire_encoding_and_client_decoding() {
    for (native, expected) in [
        (syscall::EINVAL, 22),
        (syscall::EACCES, 13),
        (syscall::EIO, 5),
        (syscall::EPERM, 1),
        (syscall::ENOENT, 2),
        (protocol::STATUS_CAPACITY_EXCEEDED as i64 as u64, 28),
        (syscall::EAGAIN, 11),
        (mochios_posix_protocol::STATUS_EISDIR as u64, 21),
        (mochios_posix_protocol::STATUS_ENOTDIR as u64, 20),
    ] {
        let mut bytes = [0; protocol::HEADER_LEN + 24];
        let length = protocol::encode_status(42, native as i32, 7, 0, &mut bytes).unwrap();
        let message = protocol::decode(&bytes[..length]).unwrap();
        assert_eq!(message.request_id, 42);
        let (status, generation, value) = protocol::decode_status(message).unwrap();
        assert_eq!((generation, value), (7, 0));
        let error = response::status_error(status);
        assert_eq!(error.raw(), -(expected as i64));
        assert_eq!(error.errno(), Some(expected));
    }
}

#[test]
fn file_panel_failure_preserves_errno_without_confusing_cancellation() {
    for status in [0, 1, -13, -5, -22] {
        let mut bytes = [0; protocol::FILE_PANEL_RESULT_PREFIX_LEN + 16];
        let length = protocol::encode_file_panel_result(
            protocol::FilePanelResult {
                status,
                token: [0; protocol::FILE_PANEL_TOKEN_LEN],
                path: if status == 0 { "/tmp/test.txt" } else { "" },
            },
            &mut bytes,
        )
        .unwrap();
        let decoded = protocol::decode_file_panel_result(&bytes[..length]).unwrap();
        assert_eq!(decoded.status, status);
        if status < 0 {
            assert_eq!(
                response::status_error(decoded.status).errno(),
                Some((-status) as u64)
            );
        }
    }
    let client = include_str!("../../../user/crates/platform/src/workspace.rs");
    assert!(client.contains("1 => Ok(None)"));
    assert!(!client.contains("status.unsigned_abs()"));
    assert_eq!(client.matches("response::status_error(status)").count(), 2);
}

#[test]
fn server_normalizes_native_remote_and_io_errors_before_reply_negation() {
    use mochios_posix_client::ClientError;
    for status in [13, -13, 22, -22] {
        assert_eq!(server_error::status_errno(status), status.unsigned_abs());
    }
    for status in [0, i64::MIN, i64::MAX] {
        assert_eq!(server_error::status_errno(status), 5);
    }
    for status in [13, -13, 0, i32::MIN] {
        let expected = if status == 0 || status == i32::MIN {
            5
        } else {
            13
        };
        assert_eq!(
            server_error::io_errno(std::io::Error::from_raw_os_error(status)),
            expected
        );
    }
    assert_eq!(server_error::io_errno(std::io::Error::other("no errno")), 5);
    assert_eq!(
        server_error::posix_errno(ClientError::Transport(syscall::SysError::from_raw(-13))),
        13
    );
    assert_eq!(server_error::posix_errno(ClientError::Remote(-22)), 22);
    assert_eq!(server_error::posix_errno(ClientError::RequestTooLarge), 75);
    assert_eq!(server_error::posix_errno(ClientError::ResponseTooLarge), 5);
    assert_eq!(
        server_error::posix_errno(ClientError::MismatchedResponse),
        5
    );
}

#[test]
fn malformed_positive_failure_is_rejected_with_a_real_errno() {
    for status in [0, 2, 13, i32::MAX] {
        assert_eq!(response::status_error(status).errno(), Some(22));
    }
    assert_eq!(response::status_error(i32::MIN).raw(), i64::from(i32::MIN));
}

#[test]
fn workspace_server_does_not_double_negate_native_errors() {
    let compact: String = include_str!("../../workspace/src/main.rs")
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    assert!(!compact.contains("-(mochi_user_syscall::E"));
    assert!(compact.contains("protocol::encode_status("));
    assert!(!compact.contains("error.errno()"));
}

#[test]
fn tagged_native_failures_are_translated_before_workspace_wire_encoding() {
    use mnu_abi::status::Error;
    use mochios_posix_client::ClientError;
    for (error, expected) in [
        (Error::LimitExceeded, 75),
        (Error::InvalidAddress, 14),
        (Error::ResourceUnavailable, 12),
        (Error::BackingFailure, 5),
        (Error::InvalidArgument, 22),
        (Error::AccessDenied, 13),
        (Error::NotReady, 11),
    ] {
        let raw = error.into_raw() as i64;
        assert_eq!(
            server_error::native_errno(syscall::SysError::from_raw(raw)),
            expected
        );
        for raw in [raw, -raw] {
            assert_eq!(server_error::status_errno(raw), expected);
        }
        assert_eq!(
            server_error::posix_errno(ClientError::Transport(syscall::SysError::from_raw(raw))),
            expected
        );
        assert_eq!(
            server_error::posix_errno(ClientError::Remote(raw as i32)),
            expected
        );
        let mut bytes = [0; protocol::HEADER_LEN + 24];
        let length = protocol::encode_status(
            42,
            -(server_error::status_errno(raw) as i32),
            7,
            0,
            &mut bytes,
        )
        .unwrap();
        let (status, _, _) =
            protocol::decode_status(protocol::decode(&bytes[..length]).unwrap()).unwrap();
        assert_eq!(response::status_error(status).errno(), Some(expected));
    }
    let unknown = (Error::LimitExceeded.into_raw() & !0xffff) | 0xffff;
    assert_eq!(server_error::status_errno(unknown as i64), 5);
}
