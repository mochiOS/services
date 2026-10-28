#[path = "../../network/src/status.rs"]
mod network_status;

use mochi_user_platform::syscall;
use mochios_net_device_protocol::{self as wire, Header, Opcode};

#[test]
fn unsupported_dns_record_is_a_userspace_wire_status() {
    assert_eq!(wire::STATUS_UNSUPPORTED_RECORD, -95);
    let status = network_status::failure_status(wire::STATUS_UNSUPPORTED_RECORD as i64 as u64);
    let mut bytes = [0; 128];
    let length = wire::encode_resolve_ipv4_result(37, status, [0; 4], false, &mut bytes).unwrap();
    let (request_id, status, address, cached) =
        wire::decode_resolve_ipv4_result(&bytes[..length]).unwrap();
    assert_eq!(
        (request_id, status, address, cached),
        (37, -95, [0; 4], false)
    );
    assert!(
        include_str!("../../network/src/resolver_stack.rs")
            .contains("mochios_net_device_protocol::STATUS_UNSUPPORTED_RECORD")
    );
    assert!(
        include_str!("../../../build/mmake/toolchain.mk")
            .contains("mochios-net-device-protocol.path='$(ROOT)/user/crates/net-device-protocol'")
    );
}

#[test]
fn service_connection_limits_keep_their_status_and_typed_wire_failure() {
    assert_eq!(wire::STATUS_CONNECTION_LIMIT, -24);
    let raw = wire::STATUS_CONNECTION_LIMIT as i64 as u64;
    assert_eq!(network_status::failure_status(raw), -24);
    let mut bytes = [0; 256];
    let http = wire::HttpRequestResult {
        request_id: 71,
        status: wire::STATUS_CONNECTION_LIMIT,
        failure: wire::HttpFailure::ConnectionLimit,
        status_code: 0,
        handle: 0,
        body_length: 0,
        headers_length: 0,
        content_type: "",
    };
    let length = wire::encode_http_request_result(
        http.request_id,
        http.status,
        http.failure,
        http.status_code,
        http.handle,
        http.body_length,
        http.headers_length,
        http.content_type,
        &mut bytes,
    )
    .unwrap();
    let decoded = wire::decode_http_request_result(&bytes[..length]).unwrap();
    assert_eq!(decoded.request_id, 71);
    assert_eq!(decoded.status, -24);
    assert_eq!(decoded.failure, wire::HttpFailure::ConnectionLimit);
    assert_eq!(decoded.handle, 0);
    let tls = wire::TlsConnectResult {
        request_id: 72,
        status: wire::STATUS_CONNECTION_LIMIT,
        failure: wire::TlsFailure::ConnectionLimit,
        handle: 0,
        address: [0; 4],
        port: 0,
        protocol_version: 0,
        cipher_suite: 0,
        hostname: "",
        certificate_subject: "",
        certificate_issuer: "",
        certificate_not_before: 0,
        certificate_not_after: 0,
    };
    let length = wire::encode_tls_connect_result(
        tls.request_id,
        tls.status,
        tls.failure,
        tls.handle,
        tls.address,
        tls.port,
        tls.protocol_version,
        tls.cipher_suite,
        tls.hostname,
        tls.certificate_subject,
        tls.certificate_issuer,
        tls.certificate_not_before,
        tls.certificate_not_after,
        &mut bytes,
    )
    .unwrap();
    let decoded = wire::decode_tls_connect_result(&bytes[..length]).unwrap();
    assert_eq!(decoded.request_id, 72);
    assert_eq!(decoded.status, -24);
    assert_eq!(decoded.failure, wire::TlsFailure::ConnectionLimit);
    assert_eq!(decoded.handle, 0);
    for source in [
        include_str!("../../network/src/http.rs"),
        include_str!("../../network/src/tls.rs"),
    ] {
        assert!(!source.contains("mochi_user_syscall::EMFILE"));
        assert!(source.contains("mochios_net_device_protocol::STATUS_CONNECTION_LIMIT"));
    }
}

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

#[test]
fn unavailable_service_returns_typed_transport_failures_without_live_streams() {
    let mut bytes = [0u8; 8192];
    for (op, id) in [
        (wire::Opcode::TcpConnect, 11),
        (wire::Opcode::TcpReceive, 12),
        (wire::Opcode::TlsConnect, 13),
        (wire::Opcode::HttpRequest, 14),
    ] {
        let n = network_status::unavailable(
            wire::Header {
                opcode: op,
                request_id: id,
                length: wire::HEADER_LEN,
            },
            -6,
            &mut bytes,
        )
        .unwrap();
        match op {
            wire::Opcode::TcpConnect => {
                let result = wire::decode_tcp_connect_result(&bytes[..n]).unwrap();
                assert_eq!((result.0, result.1, result.2), (id, -6, 0));
            }
            wire::Opcode::TcpReceive => {
                let result = wire::decode_tcp_receive_result(&bytes[..n]).unwrap();
                assert_eq!((result.0, result.1), (id, -6));
                assert!(result.3.is_empty());
            }
            wire::Opcode::TlsConnect => {
                let result = wire::decode_tls_connect_result(&bytes[..n]).unwrap();
                assert_eq!(
                    (
                        result.request_id,
                        result.status,
                        result.failure,
                        result.handle
                    ),
                    (id, -6, wire::TlsFailure::Transport, 0)
                );
            }
            wire::Opcode::HttpRequest => {
                let result = wire::decode_http_request_result(&bytes[..n]).unwrap();
                assert_eq!(
                    (
                        result.request_id,
                        result.status,
                        result.failure,
                        result.handle
                    ),
                    (id, -6, wire::HttpFailure::InvalidState, 0)
                );
            }
            _ => unreachable!(),
        }
    }
}
