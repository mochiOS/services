#[path = "../../network/src/status.rs"]
mod network_status;

use mochi_user_platform::syscall;
use mochios_net_device_protocol::{self as wire, Header, Opcode};

#[test]
fn outgoing_failures_normalize_native_and_positive_errno() {
    for (raw, expected) in [
        (13, -13),
        (syscall::EACCES, -13),
        (11, -11),
        (syscall::EAGAIN, -11),
        (syscall::EINVAL, -22),
        (5, -5),
    ] {
        assert_eq!(network_status::failure_status(raw), expected);
    }
    for raw in [0, i64::MIN as u64, i64::MAX as u64, i32::MIN as i64 as u64] {
        assert_eq!(network_status::failure_status(raw), -5);
    }
}

#[test]
fn empty_receive_is_eagain_and_malformed_driver_status_is_not_success() {
    assert_eq!(network_status::receive_status(-11), Ok(()));
    assert_eq!(network_status::receive_status(-13), Err(syscall::EACCES));
    assert_eq!(network_status::driver_result(0), Ok(()));
    assert_eq!(network_status::driver_result(-13), Err(syscall::EACCES));
    for status in [0, 11, 13, i32::MIN, i32::MAX] {
        if status != 0 {
            assert_eq!(network_status::driver_result(status), Err(syscall::EIO));
        }
        assert_eq!(network_status::receive_status(status), Err(syscall::EIO));
    }
    let mut bytes = [0; wire::STATUS_LEN];
    wire::encode_status(Opcode::FrameReceived, 7, -11, &mut bytes).unwrap();
    let (id, status) = wire::decode_status(Opcode::FrameReceived, &bytes).unwrap();
    assert_eq!(id, 7);
    assert_eq!(network_status::receive_status(status), Ok(()));
}

#[test]
fn actual_permission_replies_deny_tcp_tls_http_and_preserve_request_identity() {
    for (request, response) in [
        (Opcode::Ping, Opcode::PingResult),
        (Opcode::ResolveIpv4, Opcode::ResolveIpv4Result),
        (Opcode::TcpConnect, Opcode::TcpConnectResult),
        (Opcode::TcpSend, Opcode::TcpSendResult),
        (Opcode::TcpReceive, Opcode::TcpReceiveResult),
        (Opcode::TcpClose, Opcode::TcpCloseResult),
        (Opcode::TlsConnect, Opcode::TlsConnectResult),
        (Opcode::TlsSend, Opcode::TlsSendResult),
        (Opcode::TlsReceive, Opcode::TlsReceiveResult),
        (Opcode::TlsClose, Opcode::TlsCloseResult),
        (Opcode::HttpRequest, Opcode::HttpRequestResult),
        (Opcode::HttpRead, Opcode::HttpReadResult),
        (Opcode::HttpClose, Opcode::HttpCloseResult),
    ] {
        let mut request_bytes = [0; wire::HEADER_LEN];
        wire::encode_empty(request, 71, &mut request_bytes).unwrap();
        let header = Header::decode(&request_bytes).unwrap();
        let mut bytes = [0; 8192];
        let length = network_status::permission_denied(header, &mut bytes).unwrap();
        let reply_header = Header::decode(&bytes[..length]).unwrap();
        assert_eq!(reply_header.request_id, 71);
        assert_eq!(reply_header.opcode, response);
        // All these result messages place the signed status immediately after Header.
        assert_eq!(i32::from_le_bytes(bytes[24..28].try_into().unwrap()), -13);
    }
}

#[test]
fn service_error_branches_use_normalization_and_driver_checks_wire_status() {
    let service = include_str!("../../network/src/service.rs");
    assert!(!service.contains("-(errno as i32)"));
    assert!(!service.contains("-(error.errno as i32)"));
    assert!(service.contains("crate::status::permission_denied(header, reply)"));
    let driver = include_str!("../../network/src/driver.rs");
    assert!(driver.contains("crate::status::receive_status(status)?"));
    assert!(driver.contains("crate::status::driver_result(status)"));
}
