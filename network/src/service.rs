use mochi_user_platform as platform;
use mochios_net_device_protocol::{
    HTTP_READ_RESULT_BASE_LEN, Header, HttpFailure, MAX_HTTP_CONTENT_TYPE_LEN,
    MAX_HTTP_IPC_DATA_LEN, MAX_HTTP_URL_LEN, MAX_TCP_IO_LEN, Opcode, PING_RESULT_LEN,
    SECURITY_STATISTICS_LEN, STACK_STATISTICS_LEN, TCP_CONNECT_RESULT_LEN, TCP_IO_RESULT_LEN,
    TLS_IO_RESULT_LEN, TlsFailure, decode_empty, decode_http_close, decode_http_read,
    decode_http_request, decode_ping, decode_resolve_ipv4, decode_tcp_close, decode_tcp_connect,
    decode_tcp_receive, decode_tcp_send, decode_tls_close, decode_tls_connect, decode_tls_receive,
    decode_tls_send, encode_http_read_result, encode_http_request_result, encode_ping_result,
    encode_resolve_ipv4_result, encode_security_statistics, encode_stack_statistics,
    encode_tcp_connect_result, encode_tcp_io_result, encode_tcp_receive_result,
    encode_tls_connect_result, encode_tls_io_result, encode_tls_receive_result,
};
use mochios_network_stack::parse_ipv4_literal;

use crate::driver::DriverClient;
use crate::http::HttpManager;
use crate::stack::NetworkStack;
use crate::tls::TlsManager;

const START_TIMEOUT: u64 = 5_000;
const IPC_BUFFER_LEN: usize =
    48 + MAX_HTTP_URL_LEN + MAX_HTTP_CONTENT_TYPE_LEN + MAX_HTTP_IPC_DATA_LEN;

pub(crate) fn run() -> ! {
    platform::println!("network.service: start");
    let ready = platform::service_ready::take_bootstrap_target();
    let now = platform::time::ticks().unwrap_or(0);
    let driver = match DriverClient::connect(now.saturating_add(START_TIMEOUT)) {
        Ok(driver) => driver,
        Err(errno) => {
            platform::println!(
                "network.service: virtio-net driver unavailable errno={}",
                errno
            );
            if let Some(target) = ready {
                let _ = platform::service_ready::notify(target, -(errno as i32));
            }
            idle()
        }
    };
    let xid = platform::service_ready::generate_token()
        .map(|value| value as u32)
        .unwrap_or(0x4d4f_4348);
    let mut stack = match NetworkStack::new(driver, ready, xid) {
        Ok(stack) => stack,
        Err(errno) => {
            platform::println!("network.service: interface query failed errno={}", errno);
            idle()
        }
    };
    let info = stack.info();
    let driver_name_length = info
        .driver_name
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(info.driver_name.len());
    let driver_name =
        core::str::from_utf8(&info.driver_name[..driver_name_length]).unwrap_or("invalid");
    platform::println!(
        "network.service: interface id={} mac={:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} link={} mtu={} driver={} device={:#x}",
        info.interface_id,
        info.mac[0],
        info.mac[1],
        info.mac[2],
        info.mac[3],
        info.mac[4],
        info.mac[5],
        info.link_up,
        info.mtu,
        driver_name,
        info.device_id
    );
    if stack.start(now).is_err() {
        platform::println!("network.service: DHCP startup failed");
    }
    let mut tls = TlsManager::new();
    let mut http = HttpManager::new();

    let mut request = [0u8; IPC_BUFFER_LEN];
    let mut reply = [0u8; IPC_BUFFER_LEN];
    loop {
        let now = platform::time::ticks().unwrap_or(0);
        stack.tick(now);
        for _ in 0..32 {
            match stack.poll_receive(now) {
                Ok(true) => {}
                Ok(false) | Err(_) => break,
            }
        }
        match platform::ipc::try_wait(&mut request) {
            Ok(message) => {
                let length = (message & 0xffff_ffff) as usize;
                let sender = message >> 32;
                let Some(bytes) = request.get(..length) else {
                    continue;
                };
                if let Some(length) = handle(
                    &mut stack, &mut tls, &mut http, sender, bytes, &mut reply, now,
                ) {
                    let _ = platform::ipc::reply(sender, &reply[..length]);
                }
            }
            Err(error) if error.raw() == mochi_user_syscall::EAGAIN as i64 => {
                platform::thread::yield_now()
            }
            Err(_) => platform::thread::yield_now(),
        }
    }
}

fn handle(
    stack: &mut NetworkStack,
    tls: &mut TlsManager,
    http: &mut HttpManager,
    sender: u64,
    request: &[u8],
    reply: &mut [u8],
    now: u64,
) -> Option<usize> {
    let header = Header::decode(request).ok()?;
    let capability = if matches!(
        header.opcode,
        Opcode::HttpRequest | Opcode::HttpRead | Opcode::HttpClose
    ) {
        "net.http.request"
    } else if matches!(
        header.opcode,
        Opcode::TlsConnect | Opcode::TlsSend | Opcode::TlsReceive | Opcode::TlsClose
    ) {
        "net.tls.connect"
    } else {
        "net.connect"
    };
    if !matches!(
        platform::capability::check_thread(sender, capability),
        Ok(1)
    ) {
        return permission_denied(header, reply);
    }
    match header.opcode {
        Opcode::Ping => {
            let (request_id, target) = decode_ping(request).ok()?;
            let (status, rtt) = match stack.ping(target, now) {
                Ok(rtt) => (0, rtt),
                Err(errno) => (-(errno as i32), 0),
            };
            encode_ping_result(request_id, status, rtt, &mut reply[..PING_RESULT_LEN]).ok()
        }
        Opcode::GetStackStatistics => {
            let request_id = decode_empty(Opcode::GetStackStatistics, request).ok()?;
            let mut stats = stack.statistics();
            if let Ok(device) = stack.driver_statistics() {
                stats.rx_errors = stats.rx_errors.saturating_add(device.rx_errors);
                stats.rx_dropped = stats.rx_dropped.saturating_add(device.rx_dropped);
                stats.tx_errors = stats.tx_errors.saturating_add(device.tx_errors);
                stats.tx_dropped = stats.tx_dropped.saturating_add(device.tx_dropped);
            }
            encode_stack_statistics(request_id, stats, &mut reply[..STACK_STATISTICS_LEN]).ok()
        }
        Opcode::GetSecurityStatistics => {
            let request_id = decode_empty(Opcode::GetSecurityStatistics, request).ok()?;
            let mut statistics = tls.statistics();
            http.add_statistics(&mut statistics);
            encode_security_statistics(
                request_id,
                statistics,
                &mut reply[..SECURITY_STATISTICS_LEN],
            )
            .ok()
        }
        Opcode::ResolveIpv4 => {
            let (request_id, timeout, hostname) = decode_resolve_ipv4(request).ok()?;
            let random = random_value(sender, request_id, now);
            let (status, address, from_cache) =
                match stack.resolve_ipv4(hostname, now, u64::from(timeout), random) {
                    Ok((address, from_cache)) => (0, address, from_cache),
                    Err(errno) => (-(errno as i32), [0; 4], false),
                };
            encode_resolve_ipv4_result(request_id, status, address, from_cache, reply).ok()
        }
        Opcode::TcpConnect => {
            let (request_id, timeout, port, host) = decode_tcp_connect(request).ok()?;
            let random = random_value(sender, request_id, now);
            let address = match parse_ipv4_literal(host) {
                Some(address) => Ok(address),
                None => stack
                    .resolve_ipv4(host, now, u64::from(timeout), random)
                    .map(|result| result.0),
            };
            let (status, handle, address) = match address {
                Ok(address) => match stack.tcp_connect(
                    sender,
                    address,
                    port,
                    now,
                    u64::from(timeout),
                    random.rotate_left(29),
                ) {
                    Ok(handle) => (0, handle, address),
                    Err(errno) => (-(errno as i32), 0, address),
                },
                Err(errno) => (-(errno as i32), 0, [0; 4]),
            };
            encode_tcp_connect_result(request_id, status, handle, address, port, reply).ok()
        }
        Opcode::TcpSend => {
            let (request_id, handle, timeout, data) = decode_tcp_send(request).ok()?;
            let (status, transferred) =
                match stack.tcp_send(sender, handle, data, now, u64::from(timeout)) {
                    Ok(transferred) => (0, transferred as u32),
                    Err(errno) => (-(errno as i32), 0),
                };
            encode_tcp_io_result(
                Opcode::TcpSendResult,
                request_id,
                status,
                transferred,
                reply,
            )
            .ok()
        }
        Opcode::TcpReceive => {
            let (request_id, handle, timeout, maximum) = decode_tcp_receive(request).ok()?;
            let maximum = maximum as usize;
            let mut received = [0u8; MAX_TCP_IO_LEN];
            let (status, length, closed) = match stack.tcp_receive(
                sender,
                handle,
                &mut received[..maximum],
                now,
                u64::from(timeout),
            ) {
                Ok((length, closed)) => (0, length, closed),
                Err(errno) => (-(errno as i32), 0, false),
            };
            encode_tcp_receive_result(request_id, status, closed, &received[..length], reply).ok()
        }
        Opcode::TcpClose => {
            let (request_id, handle, timeout) = decode_tcp_close(request).ok()?;
            let status = match stack.tcp_close(sender, handle, now, u64::from(timeout)) {
                Ok(()) => 0,
                Err(errno) => -(errno as i32),
            };
            encode_tcp_io_result(Opcode::TcpCloseResult, request_id, status, 0, reply).ok()
        }
        Opcode::TlsConnect => {
            let (request_id, timeout, port, hostname) = decode_tls_connect(request).ok()?;
            match tls.connect(stack, sender, hostname, port, now, u64::from(timeout)) {
                Ok(connection) => {
                    platform::println!(
                        "network.service: TLS established host={} version={:#06x} cipher={:#06x}",
                        connection.hostname,
                        connection.protocol_version,
                        connection.cipher_suite
                    );
                    encode_tls_connect_result(
                        request_id,
                        0,
                        TlsFailure::None,
                        connection.handle,
                        connection.address,
                        connection.port,
                        connection.protocol_version,
                        connection.cipher_suite,
                        &connection.hostname,
                        &connection.certificate.subject,
                        &connection.certificate.issuer,
                        connection.certificate.not_before,
                        connection.certificate.not_after,
                        reply,
                    )
                    .ok()
                }
                Err(error) => {
                    platform::println!(
                        "network.service: TLS connect failed host={} failure={:?}",
                        hostname,
                        error.failure
                    );
                    encode_tls_connect_result(
                        request_id,
                        -(error.errno as i32),
                        error.failure,
                        0,
                        [0; 4],
                        port,
                        0,
                        0,
                        hostname,
                        "",
                        "",
                        0,
                        0,
                        reply,
                    )
                    .ok()
                }
            }
        }
        Opcode::TlsSend => {
            let (request_id, connection, timeout, data) = decode_tls_send(request).ok()?;
            let (status, failure, transferred) =
                match tls.send(stack, sender, connection, data, now, u64::from(timeout)) {
                    Ok(transferred) => (0, TlsFailure::None, transferred as u32),
                    Err(error) => (-(error.errno as i32), error.failure, 0),
                };
            encode_tls_io_result(
                Opcode::TlsSendResult,
                request_id,
                status,
                failure,
                connection,
                transferred,
                reply,
            )
            .ok()
        }
        Opcode::TlsReceive => {
            let (request_id, connection, timeout, maximum) = decode_tls_receive(request).ok()?;
            let mut received = [0u8; MAX_TCP_IO_LEN];
            let (status, failure, length, closed) = match tls.receive(
                stack,
                sender,
                connection,
                &mut received[..maximum as usize],
                now,
                u64::from(timeout),
            ) {
                Ok((length, closed)) => (0, TlsFailure::None, length, closed),
                Err(error) => (-(error.errno as i32), error.failure, 0, false),
            };
            encode_tls_receive_result(
                request_id,
                status,
                failure,
                connection,
                closed,
                &received[..length],
                reply,
            )
            .ok()
        }
        Opcode::TlsClose => {
            let (request_id, connection, timeout) = decode_tls_close(request).ok()?;
            let (status, failure) =
                match tls.close(stack, sender, connection, now, u64::from(timeout)) {
                    Ok(()) => (0, TlsFailure::None),
                    Err(error) => (-(error.errno as i32), error.failure),
                };
            encode_tls_io_result(
                Opcode::TlsCloseResult,
                request_id,
                status,
                failure,
                connection,
                0,
                reply,
            )
            .ok()
        }
        Opcode::HttpRequest => {
            let request = decode_http_request(request).ok()?;
            match http.request(
                stack,
                tls,
                sender,
                request.method,
                request.url,
                request.content_type,
                request.body,
                now,
                u64::from(request.timeout_ms),
            ) {
                Ok(response) => encode_http_request_result(
                    request.request_id,
                    0,
                    HttpFailure::None,
                    response.status_code,
                    response.handle,
                    response.body_length,
                    response.headers_length,
                    &response.content_type,
                    reply,
                )
                .ok(),
                Err(error) => encode_http_request_result(
                    request.request_id,
                    -(error.errno as i32),
                    error.failure,
                    0,
                    0,
                    0,
                    0,
                    "",
                    reply,
                )
                .ok(),
            }
        }
        Opcode::HttpRead => {
            let (request_id, handle, maximum, stream) = decode_http_read(request).ok()?;
            let mut data = [0u8; MAX_HTTP_IPC_DATA_LEN];
            let (status, failure, length, complete) =
                match http.read(sender, handle, stream, maximum as usize, &mut data) {
                    Ok((length, complete)) => (0, HttpFailure::None, length, complete),
                    Err(error) => (-(error.errno as i32), error.failure, 0, false),
                };
            encode_http_read_result(
                request_id,
                Opcode::HttpReadResult,
                status,
                failure,
                handle,
                complete,
                &data[..length],
                reply,
            )
            .ok()
        }
        Opcode::HttpClose => {
            let (request_id, handle) = decode_http_close(request).ok()?;
            let (status, failure) = match http.close(sender, handle) {
                Ok(()) => (0, HttpFailure::None),
                Err(error) => (-(error.errno as i32), error.failure),
            };
            encode_http_read_result(
                request_id,
                Opcode::HttpCloseResult,
                status,
                failure,
                handle,
                true,
                &[],
                &mut reply[..HTTP_READ_RESULT_BASE_LEN],
            )
            .ok()
        }
        _ => None,
    }
}

fn permission_denied(header: Header, reply: &mut [u8]) -> Option<usize> {
    let status = -(mochi_user_syscall::EACCES as i32);
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
            -(mochi_user_syscall::EACCES as i32),
            TlsFailure::PermissionDenied,
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
            -(mochi_user_syscall::EACCES as i32),
            TlsFailure::PermissionDenied,
            0,
            0,
            &mut reply[..TLS_IO_RESULT_LEN],
        )
        .ok(),
        Opcode::TlsReceive => encode_tls_receive_result(
            header.request_id,
            -(mochi_user_syscall::EACCES as i32),
            TlsFailure::PermissionDenied,
            0,
            false,
            &[],
            reply,
        )
        .ok(),
        Opcode::TlsClose => encode_tls_io_result(
            Opcode::TlsCloseResult,
            header.request_id,
            -(mochi_user_syscall::EACCES as i32),
            TlsFailure::PermissionDenied,
            0,
            0,
            &mut reply[..TLS_IO_RESULT_LEN],
        )
        .ok(),
        Opcode::HttpRequest => encode_http_request_result(
            header.request_id,
            status,
            HttpFailure::PermissionDenied,
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
            HttpFailure::PermissionDenied,
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
            HttpFailure::PermissionDenied,
            0,
            false,
            &[],
            reply,
        )
        .ok(),
        _ => None,
    }
}

fn random_value(sender: u64, request_id: u64, now: u64) -> u64 {
    platform::service_ready::generate_token().unwrap_or_else(|_| {
        sender.rotate_left(13) ^ request_id.rotate_left(31) ^ now.rotate_left(47)
    })
}

fn idle() -> ! {
    loop {
        platform::thread::yield_now()
    }
}
