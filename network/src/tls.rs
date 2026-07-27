use alloc::collections::VecDeque;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use mochi_user_platform as platform;
use mochios_net_device_protocol::{MAX_TCP_IO_LEN, SecurityStatistics, TlsFailure};
use mochios_network_stack::parse_ipv4_literal;
#[cfg(not(feature = "test-web-pki"))]
use mochios_tls_client::production_root_store;
#[cfg(feature = "test-web-pki")]
use mochios_tls_client::smoke_test_root_store;
use mochios_tls_client::{
    MAX_TLS_CONNECTIONS, PeerCertificateInfo, PlatformTimeProvider, TlsConnection, TlsError,
    TlsEvent, build_client_config, rustls,
};

use crate::stack::NetworkStack;

const TCP_CHUNK_LEN: usize = MAX_TCP_IO_LEN;

pub(crate) struct TlsConnectSuccess {
    pub(crate) handle: u64,
    pub(crate) address: [u8; 4],
    pub(crate) port: u16,
    pub(crate) protocol_version: u16,
    pub(crate) cipher_suite: u16,
    pub(crate) hostname: String,
    pub(crate) certificate: PeerCertificateInfo,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct TlsOperationError {
    pub(crate) errno: u64,
    pub(crate) failure: TlsFailure,
}

struct TlsSession {
    handle: u64,
    owner: u64,
    tcp_handle: u64,
    connection: TlsConnection,
    pending_plaintext: VecDeque<u8>,
    sent_records: u64,
    received_records: TlsRecordCounter,
}

pub(crate) struct TlsManager {
    config: Option<Arc<rustls::ClientConfig>>,
    sessions: Vec<TlsSession>,
    statistics: SecurityStatistics,
}

impl TlsManager {
    pub(crate) fn new() -> Self {
        #[cfg(not(feature = "test-web-pki"))]
        let roots = Ok(production_root_store());
        #[cfg(feature = "test-web-pki")]
        let roots = smoke_test_root_store();
        let config = roots
            .and_then(|roots| build_client_config(roots, Arc::new(PlatformTimeProvider)))
            .ok()
            .map(Arc::new);
        Self {
            config,
            sessions: Vec::with_capacity(MAX_TLS_CONNECTIONS),
            statistics: SecurityStatistics::default(),
        }
    }

    pub(crate) fn connect(
        &mut self,
        stack: &mut NetworkStack,
        owner: u64,
        hostname: &str,
        port: u16,
        started: u64,
        timeout: u64,
    ) -> Result<TlsConnectSuccess, TlsOperationError> {
        self.statistics.tls_connections_attempted =
            self.statistics.tls_connections_attempted.saturating_add(1);
        let result = self.connect_inner(stack, owner, hostname, port, started, timeout);
        match &result {
            Ok(_) => {
                self.statistics.tls_connections_established = self
                    .statistics
                    .tls_connections_established
                    .saturating_add(1);
            }
            Err(error) => self.record_connection_failure(error.failure),
        }
        result
    }

    fn connect_inner(
        &mut self,
        stack: &mut NetworkStack,
        owner: u64,
        hostname: &str,
        port: u16,
        started: u64,
        timeout: u64,
    ) -> Result<TlsConnectSuccess, TlsOperationError> {
        if self.sessions.len() >= MAX_TLS_CONNECTIONS {
            return Err(operation_error(
                mochi_user_syscall::EMFILE,
                TlsFailure::ConnectionLimit,
            ));
        }
        let config = self.config.clone().ok_or_else(|| {
            operation_error(mochi_user_syscall::EIO, TlsFailure::InvalidConfiguration)
        })?;
        let random = secure_u64()?;
        let address = match parse_ipv4_literal(hostname) {
            Some(_) => {
                return Err(operation_error(
                    mochi_user_syscall::EINVAL,
                    TlsFailure::InvalidServerName,
                ));
            }
            None => resolve_tls_hostname(stack, hostname, started, timeout, random)?,
        };
        let tcp_handle = stack
            .tcp_connect(
                owner,
                address,
                port,
                started,
                timeout,
                random.rotate_left(29),
            )
            .map_err(transport_error)?;
        let result = self.finish_connect(
            stack, owner, hostname, port, address, tcp_handle, config, started, timeout,
        );
        if result.is_err() {
            stack.tcp_discard(owner, tcp_handle);
        }
        result
    }

    #[allow(clippy::too_many_arguments)]
    fn finish_connect(
        &mut self,
        stack: &mut NetworkStack,
        owner: u64,
        hostname: &str,
        port: u16,
        address: [u8; 4],
        tcp_handle: u64,
        config: Arc<rustls::ClientConfig>,
        started: u64,
        timeout: u64,
    ) -> Result<TlsConnectSuccess, TlsOperationError> {
        let mut connection = TlsConnection::new(config, hostname).map_err(tls_error)?;
        let mut sent_records = 0u64;
        let mut received_records = TlsRecordCounter::new();
        for _ in 0..256 {
            match connection.next_event().map_err(tls_error)? {
                TlsEvent::Transmit(bytes) => {
                    send_all_tls(stack, owner, tcp_handle, &bytes, started, timeout)?;
                    sent_records = sent_records.saturating_add(count_complete_records(&bytes));
                }
                TlsEvent::NeedReceive => {
                    receive_one_tls(
                        stack,
                        owner,
                        tcp_handle,
                        &mut connection,
                        &mut received_records,
                        started,
                        timeout,
                    )?;
                }
                TlsEvent::Established => {
                    let certificate = connection.peer_certificate_info().map_err(tls_error)?;
                    let protocol_version = connection
                        .protocol_version()
                        .map(u16::from)
                        .ok_or_else(|| {
                            operation_error(mochi_user_syscall::EIO, TlsFailure::Protocol)
                        })?;
                    let cipher_suite =
                        connection.cipher_suite().map(u16::from).ok_or_else(|| {
                            operation_error(mochi_user_syscall::EIO, TlsFailure::Protocol)
                        })?;
                    let handle = self.allocate_handle()?;
                    self.sessions.push(TlsSession {
                        handle,
                        owner,
                        tcp_handle,
                        connection,
                        pending_plaintext: VecDeque::new(),
                        sent_records,
                        received_records,
                    });
                    self.statistics.tls_records_sent = self
                        .statistics
                        .tls_records_sent
                        .saturating_add(sent_records);
                    self.statistics.tls_records_received = self
                        .statistics
                        .tls_records_received
                        .saturating_add(received_records.completed);
                    return Ok(TlsConnectSuccess {
                        handle,
                        address,
                        port,
                        protocol_version,
                        cipher_suite,
                        hostname: hostname.into(),
                        certificate,
                    });
                }
                _ => {
                    return Err(operation_error(
                        mochi_user_syscall::EIO,
                        TlsFailure::Protocol,
                    ));
                }
            }
        }
        Err(operation_error(
            mochi_user_syscall::EAGAIN,
            TlsFailure::Timeout,
        ))
    }

    pub(crate) fn send(
        &mut self,
        stack: &mut NetworkStack,
        owner: u64,
        handle: u64,
        data: &[u8],
        started: u64,
        timeout: u64,
    ) -> Result<usize, TlsOperationError> {
        let index = self.session_index(owner, handle)?;
        let mut session = self.sessions.remove(index);
        let sent_before = session.sent_records;
        let result = session
            .connection
            .encrypt(data)
            .map_err(tls_error)
            .and_then(|record| {
                send_all_tls(stack, owner, session.tcp_handle, &record, started, timeout)?;
                session.sent_records = session
                    .sent_records
                    .saturating_add(count_complete_records(&record));
                Ok(())
            })
            .map(|()| data.len());
        self.statistics.tls_records_sent = self
            .statistics
            .tls_records_sent
            .saturating_add(session.sent_records.saturating_sub(sent_before));
        if result.is_ok() {
            self.sessions.insert(index, session);
        } else {
            stack.tcp_discard(owner, session.tcp_handle);
        }
        result
    }

    pub(crate) fn receive(
        &mut self,
        stack: &mut NetworkStack,
        owner: u64,
        handle: u64,
        out: &mut [u8],
        started: u64,
        timeout: u64,
    ) -> Result<(usize, bool), TlsOperationError> {
        let index = self.session_index(owner, handle)?;
        let mut session = self.sessions.remove(index);
        let received_before = session.received_records.completed;
        let result = receive_plaintext(stack, &mut session, out, started, timeout);
        self.statistics.tls_records_received = self.statistics.tls_records_received.saturating_add(
            session
                .received_records
                .completed
                .saturating_sub(received_before),
        );
        if matches!(
            result,
            Err(TlsOperationError {
                failure: TlsFailure::AuthenticationFailed,
                ..
            })
        ) {
            self.statistics.tls_decrypt_failures =
                self.statistics.tls_decrypt_failures.saturating_add(1);
        }
        if result.is_ok() {
            self.sessions.insert(index, session);
        } else {
            stack.tcp_discard(owner, session.tcp_handle);
        }
        result
    }

    pub(crate) fn close(
        &mut self,
        stack: &mut NetworkStack,
        owner: u64,
        handle: u64,
        started: u64,
        timeout: u64,
    ) -> Result<(), TlsOperationError> {
        let index = self.session_index(owner, handle)?;
        let mut session = self.sessions.remove(index);
        let sent_before = session.sent_records;
        let received_before = session.received_records.completed;
        let result = close_session(stack, &mut session, started, timeout);
        self.statistics.tls_records_sent = self
            .statistics
            .tls_records_sent
            .saturating_add(session.sent_records.saturating_sub(sent_before));
        self.statistics.tls_records_received = self.statistics.tls_records_received.saturating_add(
            session
                .received_records
                .completed
                .saturating_sub(received_before),
        );
        if result.is_err() {
            stack.tcp_discard(owner, session.tcp_handle);
        }
        result
    }

    pub(crate) const fn statistics(&self) -> SecurityStatistics {
        self.statistics
    }

    fn record_connection_failure(&mut self, failure: TlsFailure) {
        self.statistics.tls_connections_failed =
            self.statistics.tls_connections_failed.saturating_add(1);
        if !matches!(
            failure,
            TlsFailure::Transport
                | TlsFailure::ConnectionLimit
                | TlsFailure::InvalidServerName
                | TlsFailure::PermissionDenied
        ) {
            self.statistics.tls_handshake_failures =
                self.statistics.tls_handshake_failures.saturating_add(1);
        }
        if matches!(
            failure,
            TlsFailure::CertificateInvalid
                | TlsFailure::CertificateChainTooDeep
                | TlsFailure::CertificateTooLarge
                | TlsFailure::CertificateChainTooLarge
        ) {
            self.statistics.tls_certificate_failures =
                self.statistics.tls_certificate_failures.saturating_add(1);
        }
        if failure == TlsFailure::HostnameMismatch {
            self.statistics.tls_hostname_failures =
                self.statistics.tls_hostname_failures.saturating_add(1);
        }
    }

    fn session_index(&self, owner: u64, handle: u64) -> Result<usize, TlsOperationError> {
        if let Some(index) = self
            .sessions
            .iter()
            .position(|session| session.handle == handle && session.owner == owner)
        {
            return Ok(index);
        }
        let errno = if self.sessions.iter().any(|session| session.handle == handle) {
            mochi_user_syscall::EACCES
        } else {
            mochi_user_syscall::EBADF
        };
        Err(operation_error(errno, TlsFailure::InvalidState))
    }

    fn allocate_handle(&self) -> Result<u64, TlsOperationError> {
        for _ in 0..8 {
            let handle = secure_u64()?;
            if handle != 0 && !self.sessions.iter().any(|session| session.handle == handle) {
                return Ok(handle);
            }
        }
        Err(operation_error(
            mochi_user_syscall::EAGAIN,
            TlsFailure::RandomUnavailable,
        ))
    }
}

fn receive_plaintext(
    stack: &mut NetworkStack,
    session: &mut TlsSession,
    out: &mut [u8],
    started: u64,
    timeout: u64,
) -> Result<(usize, bool), TlsOperationError> {
    let pending = drain_pending(&mut session.pending_plaintext, out);
    if pending != 0 {
        return Ok((pending, false));
    }
    for _ in 0..256 {
        match session.connection.next_event().map_err(tls_error)? {
            TlsEvent::Transmit(bytes) => {
                send_all_tls(
                    stack,
                    session.owner,
                    session.tcp_handle,
                    &bytes,
                    started,
                    timeout,
                )?;
                session.sent_records = session
                    .sent_records
                    .saturating_add(count_complete_records(&bytes));
            }
            TlsEvent::NeedReceive => receive_one_tls(
                stack,
                session.owner,
                session.tcp_handle,
                &mut session.connection,
                &mut session.received_records,
                started,
                timeout,
            )?,
            TlsEvent::Plaintext(bytes) => {
                session.pending_plaintext.extend(bytes);
                let length = drain_pending(&mut session.pending_plaintext, out);
                return Ok((length, false));
            }
            TlsEvent::PeerClosed | TlsEvent::Closed => return Ok((0, true)),
            TlsEvent::Established => {}
        }
    }
    Err(operation_error(
        mochi_user_syscall::EAGAIN,
        TlsFailure::Timeout,
    ))
}

fn close_session(
    stack: &mut NetworkStack,
    session: &mut TlsSession,
    started: u64,
    timeout: u64,
) -> Result<(), TlsOperationError> {
    let close = session.connection.close_notify().map_err(tls_error)?;
    send_all_tls(
        stack,
        session.owner,
        session.tcp_handle,
        &close,
        started,
        timeout,
    )?;
    session.sent_records = session
        .sent_records
        .saturating_add(count_complete_records(&close));
    stack
        .tcp_close(session.owner, session.tcp_handle, started, timeout)
        .map_err(transport_error)
}

fn send_all_tls(
    stack: &mut NetworkStack,
    owner: u64,
    tcp_handle: u64,
    bytes: &[u8],
    started: u64,
    timeout: u64,
) -> Result<(), TlsOperationError> {
    for chunk in bytes.chunks(TCP_CHUNK_LEN) {
        let transferred = stack
            .tcp_send(owner, tcp_handle, chunk, started, timeout)
            .map_err(transport_error)?;
        if transferred != chunk.len() {
            return Err(operation_error(
                mochi_user_syscall::EIO,
                TlsFailure::Transport,
            ));
        }
    }
    Ok(())
}

fn receive_one_tls(
    stack: &mut NetworkStack,
    owner: u64,
    tcp_handle: u64,
    connection: &mut TlsConnection,
    records: &mut TlsRecordCounter,
    started: u64,
    timeout: u64,
) -> Result<(), TlsOperationError> {
    let mut incoming = [0u8; TCP_CHUNK_LEN];
    let (length, _closed) = stack
        .tcp_receive(owner, tcp_handle, &mut incoming, started, timeout)
        .map_err(transport_error)?;
    if length == 0 {
        return Err(operation_error(
            mochi_user_syscall::EPIPE,
            TlsFailure::Protocol,
        ));
    }
    records.feed(&incoming[..length]);
    connection
        .receive_tls(&incoming[..length])
        .map_err(tls_error)
}

#[derive(Clone, Copy)]
struct TlsRecordCounter {
    header: [u8; 5],
    header_length: usize,
    body_remaining: usize,
    completed: u64,
}

impl TlsRecordCounter {
    const fn new() -> Self {
        Self {
            header: [0; 5],
            header_length: 0,
            body_remaining: 0,
            completed: 0,
        }
    }

    fn feed(&mut self, mut bytes: &[u8]) {
        while !bytes.is_empty() {
            if self.body_remaining != 0 {
                let consumed = self.body_remaining.min(bytes.len());
                self.body_remaining -= consumed;
                bytes = &bytes[consumed..];
                if self.body_remaining == 0 {
                    self.completed = self.completed.saturating_add(1);
                }
                continue;
            }
            let required = 5 - self.header_length;
            let consumed = required.min(bytes.len());
            self.header[self.header_length..self.header_length + consumed]
                .copy_from_slice(&bytes[..consumed]);
            self.header_length += consumed;
            bytes = &bytes[consumed..];
            if self.header_length == 5 {
                self.body_remaining =
                    usize::from(u16::from_be_bytes([self.header[3], self.header[4]]));
                self.header_length = 0;
                if self.body_remaining == 0 {
                    self.completed = self.completed.saturating_add(1);
                }
            }
        }
    }
}

fn count_complete_records(bytes: &[u8]) -> u64 {
    let mut counter = TlsRecordCounter::new();
    counter.feed(bytes);
    counter.completed
}

fn drain_pending(pending: &mut VecDeque<u8>, out: &mut [u8]) -> usize {
    let length = out.len().min(pending.len());
    for destination in out.iter_mut().take(length) {
        if let Some(byte) = pending.pop_front() {
            *destination = byte;
        }
    }
    length
}

fn resolve_tls_hostname(
    stack: &mut NetworkStack,
    hostname: &str,
    started: u64,
    timeout: u64,
    query_id: u64,
) -> Result<[u8; 4], TlsOperationError> {
    #[cfg(feature = "test-web-pki")]
    if hostname.ends_with(".test.mochios") {
        return Ok([10, 0, 2, 2]);
    }
    stack
        .resolve_ipv4(hostname, started, timeout, query_id)
        .map(|result| result.0)
        .map_err(transport_error)
}

fn secure_u64() -> Result<u64, TlsOperationError> {
    let mut bytes = [0u8; 8];
    platform::random::fill(&mut bytes)
        .map_err(|_| operation_error(mochi_user_syscall::EAGAIN, TlsFailure::RandomUnavailable))?;
    Ok(u64::from_le_bytes(bytes))
}

fn tls_error(error: TlsError) -> TlsOperationError {
    let (errno, failure) = match error {
        TlsError::InvalidServerName => (mochi_user_syscall::EINVAL, TlsFailure::InvalidServerName),
        TlsError::InvalidConfiguration => {
            (mochi_user_syscall::EIO, TlsFailure::InvalidConfiguration)
        }
        TlsError::RandomUnavailable => (mochi_user_syscall::EAGAIN, TlsFailure::RandomUnavailable),
        TlsError::TimeUnavailable => (mochi_user_syscall::EAGAIN, TlsFailure::TimeUnavailable),
        TlsError::CertificateInvalid => {
            (mochi_user_syscall::EACCES, TlsFailure::CertificateInvalid)
        }
        TlsError::HostnameMismatch => (mochi_user_syscall::EACCES, TlsFailure::HostnameMismatch),
        TlsError::CertificateChainTooDeep => (
            mochi_user_syscall::EACCES,
            TlsFailure::CertificateChainTooDeep,
        ),
        TlsError::CertificateTooLarge => {
            (mochi_user_syscall::EACCES, TlsFailure::CertificateTooLarge)
        }
        TlsError::CertificateChainTooLarge => (
            mochi_user_syscall::EACCES,
            TlsFailure::CertificateChainTooLarge,
        ),
        TlsError::AuthenticationFailed => {
            (mochi_user_syscall::EIO, TlsFailure::AuthenticationFailed)
        }
        TlsError::BufferLimit => (mochi_user_syscall::ENOMEM, TlsFailure::BufferLimit),
        TlsError::Protocol => (mochi_user_syscall::EIO, TlsFailure::Protocol),
        TlsError::PeerAlert => (mochi_user_syscall::EIO, TlsFailure::PeerAlert),
        TlsError::InvalidState => (mochi_user_syscall::EINVAL, TlsFailure::InvalidState),
    };
    operation_error(errno, failure)
}

fn transport_error(errno: u64) -> TlsOperationError {
    let failure = if errno == mochi_user_syscall::EAGAIN {
        TlsFailure::Timeout
    } else {
        TlsFailure::Transport
    };
    operation_error(errno, failure)
}

const fn operation_error(errno: u64, failure: TlsFailure) -> TlsOperationError {
    TlsOperationError { errno, failure }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_counter_handles_fragmented_headers_and_bodies() {
        let first = [23, 3, 3, 0, 3, 1, 2, 3];
        let second = [21, 3, 3, 0, 2, 4, 5];
        let mut counter = TlsRecordCounter::new();
        counter.feed(&first[..2]);
        counter.feed(&first[2..6]);
        assert_eq!(counter.completed, 0);
        counter.feed(&first[6..]);
        counter.feed(&second);
        assert_eq!(counter.completed, 2);
        assert_eq!(
            count_complete_records(&[first.as_slice(), second.as_slice()].concat()),
            2
        );
    }
}
