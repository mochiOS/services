use alloc::string::String;
use alloc::vec::Vec;

use mochi_user_platform as platform;
use mochios_http_client::{
    Header, HttpError, HttpResponse, HttpsUrl, Method, ResponseDecoder, encode_request,
};
use mochios_net_device_protocol::{HttpFailure, HttpMethod, HttpStream, SecurityStatistics};

use crate::stack::NetworkStack;
use crate::tls::TlsManager;

const MAX_HTTP_RESPONSES: usize = 8;
const RECEIVE_CHUNK: usize = 4_096;
const MAX_RECEIVE_STEPS: usize = 1_032;

pub(crate) struct HttpRequestSuccess {
    pub(crate) handle: u64,
    pub(crate) status_code: u16,
    pub(crate) body_length: u32,
    pub(crate) headers_length: u32,
    pub(crate) content_type: String,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct HttpOperationError {
    pub(crate) errno: u64,
    pub(crate) failure: HttpFailure,
}

struct StoredResponse {
    handle: u64,
    owner: u64,
    headers: Vec<u8>,
    body: Vec<u8>,
    headers_offset: usize,
    body_offset: usize,
}

pub(crate) struct HttpManager {
    responses: Vec<StoredResponse>,
    statistics: SecurityStatistics,
}

impl HttpManager {
    pub(crate) fn new() -> Self {
        Self {
            responses: Vec::new(),
            statistics: SecurityStatistics::default(),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn request(
        &mut self,
        stack: &mut NetworkStack,
        tls: &mut TlsManager,
        owner: u64,
        method: HttpMethod,
        raw_url: &str,
        content_type: &str,
        if_none_match: &str,
        body: &[u8],
        started: u64,
        timeout: u64,
    ) -> Result<HttpRequestSuccess, HttpOperationError> {
        self.statistics.http_requests = self.statistics.http_requests.saturating_add(1);
        let result = self.request_inner(
            stack,
            tls,
            owner,
            method,
            raw_url,
            content_type,
            if_none_match,
            body,
            started,
            timeout,
        );
        match &result {
            Ok(_) => {
                self.statistics.http_responses = self.statistics.http_responses.saturating_add(1)
            }
            Err(error) => {
                self.statistics.http_failures = self.statistics.http_failures.saturating_add(1);
                match error.failure {
                    HttpFailure::HeaderLimit | HttpFailure::InvalidResponse => {
                        self.statistics.http_header_errors =
                            self.statistics.http_header_errors.saturating_add(1);
                    }
                    HttpFailure::BodyLimit => {
                        self.statistics.http_body_limit_errors =
                            self.statistics.http_body_limit_errors.saturating_add(1);
                    }
                    HttpFailure::ChunkError => {
                        self.statistics.http_chunk_errors =
                            self.statistics.http_chunk_errors.saturating_add(1);
                    }
                    HttpFailure::RedirectRejected => {
                        self.statistics.http_redirects =
                            self.statistics.http_redirects.saturating_add(1);
                    }
                    _ => {}
                }
            }
        }
        result
    }

    #[allow(clippy::too_many_arguments)]
    fn request_inner(
        &mut self,
        stack: &mut NetworkStack,
        tls: &mut TlsManager,
        owner: u64,
        method: HttpMethod,
        raw_url: &str,
        content_type: &str,
        if_none_match: &str,
        body: &[u8],
        started: u64,
        timeout: u64,
    ) -> Result<HttpRequestSuccess, HttpOperationError> {
        if self.responses.len() >= MAX_HTTP_RESPONSES {
            return Err(error(
                mochi_user_syscall::EMFILE,
                HttpFailure::ConnectionLimit,
            ));
        }
        let url = HttpsUrl::parse(raw_url).map_err(http_error)?;
        let method = match method {
            HttpMethod::Get => Method::Get,
            HttpMethod::Post => Method::Post,
        };
        let mut headers = Vec::with_capacity(2);
        if method == Method::Post && !content_type.is_empty() {
            headers.push(Header {
                name: "Content-Type",
                value: content_type,
            });
        }
        if !if_none_match.is_empty() {
            headers.push(Header {
                name: "If-None-Match",
                value: if_none_match,
            });
        }
        let request = encode_request(method, &url, &headers, body).map_err(http_error)?;
        let connection = tls
            .connect(stack, owner, url.hostname(), url.port(), started, timeout)
            .map_err(|operation| {
                log_tls_failure("connect", operation);
                http_tls_error(operation)
            })?;
        let tls_handle = connection.handle;
        let result = exchange(stack, tls, owner, tls_handle, &request, started, timeout);
        if result.is_err() {
            let _ = tls.close(stack, owner, tls_handle, started, timeout);
        }
        let response = result?;
        if matches!(response.status_code, 301 | 302 | 303 | 307 | 308) {
            let _ = tls.close(stack, owner, tls_handle, started, timeout);
            return Err(error(
                mochi_user_syscall::EACCES,
                HttpFailure::RedirectRejected,
            ));
        }
        tls.close(stack, owner, tls_handle, started, timeout)
            .map_err(|operation| {
                log_tls_failure("close", operation);
                http_tls_error(operation)
            })?;
        let headers = serialize_headers(&response)?;
        let content_type = response.header("content-type").unwrap_or("").into();
        let handle = self.allocate_handle()?;
        let body_length = response.body.len() as u32;
        let headers_length = headers.len() as u32;
        self.responses.push(StoredResponse {
            handle,
            owner,
            headers,
            body: response.body,
            headers_offset: 0,
            body_offset: 0,
        });
        Ok(HttpRequestSuccess {
            handle,
            status_code: response.status_code,
            body_length,
            headers_length,
            content_type,
        })
    }

    pub(crate) fn read<'a>(
        &'a mut self,
        owner: u64,
        handle: u64,
        stream: HttpStream,
        maximum: usize,
        out: &'a mut [u8],
    ) -> Result<(usize, bool), HttpOperationError> {
        let response = self.response_mut(owner, handle)?;
        let (source, offset) = match stream {
            HttpStream::Headers => (&response.headers, &mut response.headers_offset),
            HttpStream::Body => (&response.body, &mut response.body_offset),
        };
        let length = maximum
            .min(out.len())
            .min(source.len().saturating_sub(*offset));
        out[..length].copy_from_slice(&source[*offset..*offset + length]);
        *offset += length;
        Ok((length, *offset == source.len()))
    }

    pub(crate) fn close(&mut self, owner: u64, handle: u64) -> Result<(), HttpOperationError> {
        let index = self.response_index(owner, handle)?;
        self.responses.remove(index);
        Ok(())
    }

    pub(crate) fn add_statistics(&self, target: &mut SecurityStatistics) {
        target.http_requests = self.statistics.http_requests;
        target.http_responses = self.statistics.http_responses;
        target.http_failures = self.statistics.http_failures;
        target.http_redirects = self.statistics.http_redirects;
        target.http_header_errors = self.statistics.http_header_errors;
        target.http_body_limit_errors = self.statistics.http_body_limit_errors;
        target.http_chunk_errors = self.statistics.http_chunk_errors;
    }

    fn response_mut(
        &mut self,
        owner: u64,
        handle: u64,
    ) -> Result<&mut StoredResponse, HttpOperationError> {
        let index = self.response_index(owner, handle)?;
        Ok(&mut self.responses[index])
    }

    fn response_index(&self, owner: u64, handle: u64) -> Result<usize, HttpOperationError> {
        if let Some(index) = self
            .responses
            .iter()
            .position(|response| response.handle == handle && response.owner == owner)
        {
            return Ok(index);
        }
        let errno = if self
            .responses
            .iter()
            .any(|response| response.handle == handle)
        {
            mochi_user_syscall::EACCES
        } else {
            mochi_user_syscall::EBADF
        };
        Err(error(errno, HttpFailure::InvalidState))
    }

    fn allocate_handle(&self) -> Result<u64, HttpOperationError> {
        for _ in 0..8 {
            let mut bytes = [0u8; 8];
            platform::random::fill(&mut bytes)
                .map_err(|_| error(mochi_user_syscall::EAGAIN, HttpFailure::InvalidState))?;
            let handle = u64::from_le_bytes(bytes);
            if handle != 0
                && !self
                    .responses
                    .iter()
                    .any(|response| response.handle == handle)
            {
                return Ok(handle);
            }
        }
        Err(error(mochi_user_syscall::EAGAIN, HttpFailure::InvalidState))
    }
}

fn exchange(
    stack: &mut NetworkStack,
    tls: &mut TlsManager,
    owner: u64,
    handle: u64,
    request: &[u8],
    started: u64,
    timeout: u64,
) -> Result<HttpResponse, HttpOperationError> {
    let sent = tls
        .send(stack, owner, handle, request, started, timeout)
        .map_err(|operation| {
            log_tls_failure("send", operation);
            http_tls_error(operation)
        })?;
    if sent != request.len() {
        return Err(error(mochi_user_syscall::EIO, HttpFailure::Tls));
    }
    let mut decoder = ResponseDecoder::new();
    let mut incoming = [0u8; RECEIVE_CHUNK];
    for _ in 0..MAX_RECEIVE_STEPS {
        let (length, closed) = tls
            .receive(stack, owner, handle, &mut incoming, started, timeout)
            .map_err(|operation| {
                log_tls_failure("receive", operation);
                http_tls_error(operation)
            })?;
        decoder.feed(&incoming[..length]).map_err(http_error)?;
        match decoder.decode(closed) {
            Ok(response) => return Ok(response),
            Err(HttpError::Incomplete) => {}
            Err(problem) => return Err(http_error(problem)),
        }
        if closed {
            return Err(error(
                mochi_user_syscall::EPIPE,
                HttpFailure::InvalidResponse,
            ));
        }
    }
    Err(error(mochi_user_syscall::EAGAIN, HttpFailure::Timeout))
}

fn log_tls_failure(stage: &str, operation: crate::tls::TlsOperationError) {
    platform::logln!(
        "network.service: HTTP TLS {stage} failed failure={:?} errno={}",
        operation.failure,
        operation.errno
    );
}

fn http_tls_error(operation: crate::tls::TlsOperationError) -> HttpOperationError {
    let failure = if operation.failure == mochios_net_device_protocol::TlsFailure::Timeout {
        HttpFailure::Timeout
    } else {
        HttpFailure::Tls
    };
    error(operation.errno, failure)
}

fn serialize_headers(response: &HttpResponse) -> Result<Vec<u8>, HttpOperationError> {
    let mut result = Vec::new();
    for (name, value) in &response.headers {
        let required = name
            .len()
            .checked_add(value.len())
            .and_then(|length| length.checked_add(4))
            .ok_or_else(|| error(mochi_user_syscall::ENOMEM, HttpFailure::HeaderLimit))?;
        if result.len().saturating_add(required) > mochios_http_client::MAX_HEADER_BYTES {
            return Err(error(mochi_user_syscall::ENOMEM, HttpFailure::HeaderLimit));
        }
        result.extend_from_slice(name.as_bytes());
        result.extend_from_slice(b": ");
        result.extend_from_slice(value.as_bytes());
        result.extend_from_slice(b"\r\n");
    }
    Ok(result)
}

fn http_error(problem: HttpError) -> HttpOperationError {
    let failure = match problem {
        HttpError::HeadersTooLarge | HttpError::TooManyHeaders => HttpFailure::HeaderLimit,
        HttpError::BodyTooLarge | HttpError::ChunkTooLarge => HttpFailure::BodyLimit,
        HttpError::InvalidChunkSize | HttpError::InvalidChunkTerminator => HttpFailure::ChunkError,
        HttpError::RedirectDowngrade
        | HttpError::RedirectLimit
        | HttpError::RedirectLoop
        | HttpError::RedirectUnsupported => HttpFailure::RedirectRejected,
        HttpError::InvalidUrl
        | HttpError::UnsupportedScheme
        | HttpError::UserInfoForbidden
        | HttpError::FragmentForbidden
        | HttpError::InvalidHostname
        | HttpError::InvalidPort
        | HttpError::InvalidPath
        | HttpError::UrlTooLong => HttpFailure::InvalidUrl,
        HttpError::InvalidMethod
        | HttpError::InvalidHeaderName
        | HttpError::InvalidHeaderValue
        | HttpError::HostnameMismatch
        | HttpError::ContentLengthMismatch => HttpFailure::InvalidRequest,
        _ => HttpFailure::InvalidResponse,
    };
    let errno = if matches!(failure, HttpFailure::BodyLimit | HttpFailure::HeaderLimit) {
        mochi_user_syscall::ENOMEM
    } else {
        mochi_user_syscall::EINVAL
    };
    error(errno, failure)
}

const fn error(errno: u64, failure: HttpFailure) -> HttpOperationError {
    HttpOperationError { errno, failure }
}
