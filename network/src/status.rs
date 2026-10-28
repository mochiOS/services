use mochi_user_platform::syscall;
use mochios_net_device_protocol::{
    Header, HttpFailure, Opcode, TCP_CONNECT_RESULT_LEN, TCP_IO_RESULT_LEN, TLS_IO_RESULT_LEN,
    TlsFailure, encode_http_read_result, encode_http_request_result, encode_ping_result,
    encode_resolve_ipv4_result, encode_security_statistics, encode_stack_statistics,
    encode_tcp_connect_result, encode_tcp_io_result, encode_tcp_receive_result,
    encode_tls_connect_result, encode_tls_io_result, encode_tls_receive_result,
};

pub(crate) fn permission_denied(header: Header, reply: &mut [u8]) -> Option<usize> {
    reply_error(
        header,
        syscall::EACCES as i32,
        TlsFailure::PermissionDenied,
        HttpFailure::PermissionDenied,
        reply,
    )
}

pub(crate) fn unavailable(header: Header, status: i32, reply: &mut [u8]) -> Option<usize> {
    reply_error(
        header,
        status,
        TlsFailure::Transport,
        HttpFailure::InvalidState,
        reply,
    )
}

fn reply_error(
    header: Header,
    status: i32,
    tls_failure: TlsFailure,
    http_failure: HttpFailure,
    reply: &mut [u8],
) -> Option<usize> {
    match header.opcode {
        Opcode::Ping => encode_ping_result(header.request_id, status, 0, reply).ok(),
        Opcode::ResolveIpv4 => {
            encode_resolve_ipv4_result(header.request_id, status, [0; 4], false, reply).ok()
        }
        Opcode::TcpConnect => encode_tcp_connect_result(
            header.request_id,
            status,
            0,
            [0; 4],
            0,
            &mut reply[..TCP_CONNECT_RESULT_LEN],
        )
        .ok(),
        Opcode::TcpSend => encode_tcp_io_result(
            Opcode::TcpSendResult,
            header.request_id,
            status,
            0,
            &mut reply[..TCP_IO_RESULT_LEN],
        )
        .ok(),
        Opcode::TcpReceive => {
            encode_tcp_receive_result(header.request_id, status, false, &[], reply).ok()
        }
        Opcode::TcpClose => encode_tcp_io_result(
            Opcode::TcpCloseResult,
            header.request_id,
            status,
            0,
            &mut reply[..TCP_IO_RESULT_LEN],
        )
        .ok(),
        Opcode::GetStackStatistics => {
            encode_stack_statistics(header.request_id, Default::default(), reply).ok()
        }
        Opcode::GetSecurityStatistics => {
            encode_security_statistics(header.request_id, Default::default(), reply).ok()
        }
        Opcode::TlsConnect => encode_tls_connect_result(
            header.request_id,
            status,
            tls_failure,
            0,
            [0; 4],
            0,
            0,
            0,
            "",
            "",
            "",
            0,
            0,
            reply,
        )
        .ok(),
        Opcode::TlsSend => encode_tls_io_result(
            Opcode::TlsSendResult,
            header.request_id,
            status,
            tls_failure,
            0,
            0,
            &mut reply[..TLS_IO_RESULT_LEN],
        )
        .ok(),
        Opcode::TlsReceive => {
            encode_tls_receive_result(header.request_id, status, tls_failure, 0, false, &[], reply)
                .ok()
        }
        Opcode::TlsClose => encode_tls_io_result(
            Opcode::TlsCloseResult,
            header.request_id,
            status,
            tls_failure,
            0,
            0,
            &mut reply[..TLS_IO_RESULT_LEN],
        )
        .ok(),
        Opcode::HttpRequest => encode_http_request_result(
            header.request_id,
            status,
            http_failure,
            0,
            0,
            0,
            0,
            "",
            reply,
        )
        .ok(),
        Opcode::HttpRead => encode_http_read_result(
            header.request_id,
            Opcode::HttpReadResult,
            status,
            http_failure,
            0,
            false,
            &[],
            reply,
        )
        .ok(),
        Opcode::HttpClose => encode_http_read_result(
            header.request_id,
            Opcode::HttpCloseResult,
            status,
            http_failure,
            0,
            false,
            &[],
            reply,
        )
        .ok(),
        _ => None,
    }
}

/// Service errors may be positive errno values or encoded native failures.
/// A failure reply is always negative and representable in the wire's i32.
pub(crate) fn failure_status(raw: u64) -> i32 {
    match i32::try_from((raw as i64).unsigned_abs()) {
        Ok(errno) if errno != 0 => -errno,
        _ => -(syscall::EIO as i32),
    }
}

/// Driver status replies use signed failures; positive statuses are malformed.
pub(crate) fn driver_result(status: i32) -> Result<(), u64> {
    match status {
        0 => Ok(()),
        value if value < 0 && value != i32::MIN => Err(value as i64 as u64),
        _ => Err(syscall::EIO),
    }
}

/// EAGAIN is the receive protocol's explicit empty-queue response, not an error.
pub(crate) fn receive_status(status: i32) -> Result<(), u64> {
    if status == syscall::EAGAIN as i32 {
        Ok(())
    } else {
        // A status-only success carries no frame and violates the protocol.
        driver_result(status)?;
        Err(syscall::EIO)
    }
}
