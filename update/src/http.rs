use mochios_http_client::{MAX_BODY_BYTES, MAX_HEADER_BYTES, MAX_HEADER_COUNT};
use mochios_net_device_protocol::{
    HTTP_CLOSE_REQUEST_LEN, HTTP_READ_REQUEST_LEN, HTTP_READ_RESULT_BASE_LEN,
    HTTP_REQUEST_RESULT_BASE_LEN, HttpFailure, HttpMethod, HttpStream, MAX_HTTP_CONTENT_TYPE_LEN,
    MAX_HTTP_IPC_DATA_LEN, Opcode, decode_http_read_result, decode_http_request_result,
    encode_http_close, encode_http_read, encode_http_request,
};
use std::string::{String, ToString};
use std::vec;
use std::vec::Vec;

use crate::coordinator::SnapshotFetcher;
use crate::scheduler::SnapshotKind;

pub const REQUEST_TIMEOUT_MS: u32 = 30_000;
pub const DEVELOPER_CA_BASE_URL: &str = "https://ca.mochios.org";
pub const TRUST_URL: &str = "https://ca.mochios.org/v1/trust-store";
pub const REVOCATIONS_URL: &str = "https://ca.mochios.org/v1/revocations";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Response {
    pub status_code: u16,
    pub etag: Option<String>,
    pub retry_after_seconds: Option<u64>,
    pub body: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FetchError {
    Transport(u64),
    Wire,
    RequestIdMismatch,
    HandleMismatch,
    ServiceFailure { status: i32, failure: HttpFailure },
    DeclaredLengthTooLarge,
    Truncated,
    InvalidHeaders,
    MissingEtag,
    EtagMismatch,
    InvalidContentType,
    InvalidNotModified,
}

pub trait Transport {
    fn call(&mut self, request: &[u8], reply: &mut [u8]) -> Result<usize, FetchError>;
}

pub struct DeveloperCaFetcher<T> {
    transport: T,
}

impl<T> DeveloperCaFetcher<T> {
    pub const fn new(transport: T) -> Self {
        Self { transport }
    }

    pub fn into_transport(self) -> T {
        self.transport
    }
}

impl<T: Transport> SnapshotFetcher for DeveloperCaFetcher<T> {
    fn fetch(
        &mut self,
        kind: SnapshotKind,
        request_id: u64,
        if_none_match: &str,
    ) -> Result<Response, FetchError> {
        get(
            &mut self.transport,
            request_id,
            snapshot_url(kind),
            if_none_match,
        )
    }
}

pub const fn snapshot_url(kind: SnapshotKind) -> &'static str {
    match kind {
        SnapshotKind::Trust => TRUST_URL,
        SnapshotKind::Revocations => REVOCATIONS_URL,
    }
}

pub fn version_url(kind: SnapshotKind, snapshot_version: u64) -> String {
    format!("{}/{snapshot_version}", snapshot_url(kind))
}

pub fn get<T: Transport>(
    transport: &mut T,
    request_id: u64,
    url: &str,
    if_none_match: &str,
) -> Result<Response, FetchError> {
    let mut request = vec![0; 48 + url.len() + if_none_match.len()];
    let request_length = encode_http_request(
        request_id,
        HttpMethod::Get,
        REQUEST_TIMEOUT_MS,
        url,
        "",
        if_none_match,
        &[],
        &mut request,
    )
    .map_err(|_| FetchError::Wire)?;
    let mut reply = [0; HTTP_REQUEST_RESULT_BASE_LEN + MAX_HTTP_CONTENT_TYPE_LEN];
    let reply_length = transport.call(&request[..request_length], &mut reply)?;
    let result = decode_http_request_result(reply.get(..reply_length).ok_or(FetchError::Wire)?)
        .map_err(|_| FetchError::Wire)?;
    if result.request_id != request_id {
        return Err(FetchError::RequestIdMismatch);
    }
    if result.status != 0 || result.failure != HttpFailure::None {
        return Err(FetchError::ServiceFailure {
            status: result.status,
            failure: result.failure,
        });
    }
    if result.body_length as usize > MAX_BODY_BYTES
        || result.headers_length as usize > MAX_HEADER_BYTES
    {
        let _ = close(transport, request_id, result.handle);
        return Err(FetchError::DeclaredLengthTooLarge);
    }

    let fetched = read_response(
        transport,
        request_id,
        result.handle,
        result.status_code,
        result.content_type,
        result.headers_length as usize,
        result.body_length as usize,
        if_none_match,
    );
    let close_result = close(transport, request_id, result.handle);
    match (fetched, close_result) {
        (Ok(response), Ok(())) => Ok(response),
        (Err(error), _) | (Ok(_), Err(error)) => Err(error),
    }
}

#[allow(clippy::too_many_arguments)]
fn read_response<T: Transport>(
    transport: &mut T,
    request_id: u64,
    handle: u64,
    status_code: u16,
    content_type: &str,
    headers_length: usize,
    body_length: usize,
    if_none_match: &str,
) -> Result<Response, FetchError> {
    let headers = read_stream(
        transport,
        request_id,
        handle,
        HttpStream::Headers,
        headers_length,
    )?;
    let parsed = ParsedHeaders::parse(&headers)?;
    match status_code {
        200 => {
            if !is_json_content_type(content_type) {
                return Err(FetchError::InvalidContentType);
            }
            let etag = parsed.etag.ok_or(FetchError::MissingEtag)?;
            let body = read_stream(transport, request_id, handle, HttpStream::Body, body_length)?;
            Ok(Response {
                status_code,
                etag: Some(etag),
                retry_after_seconds: parsed.retry_after_seconds,
                body,
            })
        }
        304 => {
            if body_length != 0 || if_none_match.is_empty() {
                return Err(FetchError::InvalidNotModified);
            }
            let etag = parsed.etag.ok_or(FetchError::MissingEtag)?;
            if etag != if_none_match {
                return Err(FetchError::EtagMismatch);
            }
            Ok(Response {
                status_code,
                etag: Some(etag),
                retry_after_seconds: parsed.retry_after_seconds,
                body: Vec::new(),
            })
        }
        _ => {
            let body = read_stream(transport, request_id, handle, HttpStream::Body, body_length)?;
            Ok(Response {
                status_code,
                etag: parsed.etag,
                retry_after_seconds: parsed.retry_after_seconds,
                body,
            })
        }
    }
}

fn read_stream<T: Transport>(
    transport: &mut T,
    request_id: u64,
    handle: u64,
    stream: HttpStream,
    expected_length: usize,
) -> Result<Vec<u8>, FetchError> {
    if expected_length == 0 {
        return Ok(Vec::new());
    }
    let mut output = Vec::with_capacity(expected_length);
    let mut complete = false;
    while output.len() < expected_length && !complete {
        let maximum = (expected_length - output.len()).min(MAX_HTTP_IPC_DATA_LEN);
        let mut request = [0; HTTP_READ_REQUEST_LEN];
        encode_http_read(request_id, handle, maximum as u32, stream, &mut request)
            .map_err(|_| FetchError::Wire)?;
        let mut reply = vec![0; HTTP_READ_RESULT_BASE_LEN + maximum];
        let reply_length = transport.call(&request, &mut reply)?;
        let (reply_id, status, failure, reply_handle, reply_complete, data) =
            decode_http_read_result(
                Opcode::HttpReadResult,
                reply.get(..reply_length).ok_or(FetchError::Wire)?,
            )
            .map_err(|_| FetchError::Wire)?;
        if reply_id != request_id {
            return Err(FetchError::RequestIdMismatch);
        }
        if reply_handle != handle {
            return Err(FetchError::HandleMismatch);
        }
        if status != 0 || failure != HttpFailure::None {
            return Err(FetchError::ServiceFailure { status, failure });
        }
        if data.is_empty() && !reply_complete {
            return Err(FetchError::Truncated);
        }
        output.extend_from_slice(data);
        complete = reply_complete;
    }
    if output.len() != expected_length || !complete {
        return Err(FetchError::Truncated);
    }
    Ok(output)
}

fn close<T: Transport>(transport: &mut T, request_id: u64, handle: u64) -> Result<(), FetchError> {
    let mut request = [0; HTTP_CLOSE_REQUEST_LEN];
    encode_http_close(request_id, handle, &mut request).map_err(|_| FetchError::Wire)?;
    let mut reply = [0; HTTP_READ_RESULT_BASE_LEN];
    let reply_length = transport.call(&request, &mut reply)?;
    let (reply_id, status, failure, reply_handle, complete, data) = decode_http_read_result(
        Opcode::HttpCloseResult,
        reply.get(..reply_length).ok_or(FetchError::Wire)?,
    )
    .map_err(|_| FetchError::Wire)?;
    if reply_id != request_id {
        return Err(FetchError::RequestIdMismatch);
    }
    if reply_handle != handle || !complete || !data.is_empty() {
        return Err(FetchError::HandleMismatch);
    }
    if status != 0 || failure != HttpFailure::None {
        return Err(FetchError::ServiceFailure { status, failure });
    }
    Ok(())
}

struct ParsedHeaders {
    etag: Option<String>,
    retry_after_seconds: Option<u64>,
}

impl ParsedHeaders {
    fn parse(bytes: &[u8]) -> Result<Self, FetchError> {
        let text = core::str::from_utf8(bytes).map_err(|_| FetchError::InvalidHeaders)?;
        let mut etag = None;
        let mut retry_after_seconds = None;
        let mut header_count = 0usize;
        for line in text.split("\r\n") {
            if line.is_empty() {
                continue;
            }
            header_count = header_count.saturating_add(1);
            if header_count > MAX_HEADER_COUNT {
                return Err(FetchError::InvalidHeaders);
            }
            let (name, value) = line.split_once(':').ok_or(FetchError::InvalidHeaders)?;
            let value = value.trim_matches([' ', '\t']);
            if name.eq_ignore_ascii_case("etag") {
                if etag.is_some() {
                    return Err(FetchError::InvalidHeaders);
                }
                etag = Some(value.to_string());
            } else if name.eq_ignore_ascii_case("retry-after") {
                if retry_after_seconds.is_some() {
                    return Err(FetchError::InvalidHeaders);
                }
                retry_after_seconds = Some(parse_decimal(value)?);
            }
        }
        Ok(Self {
            etag,
            retry_after_seconds,
        })
    }
}

fn parse_decimal(value: &str) -> Result<u64, FetchError> {
    if value.is_empty() {
        return Err(FetchError::InvalidHeaders);
    }
    let mut result = 0u64;
    for byte in value.bytes() {
        if !byte.is_ascii_digit() {
            return Err(FetchError::InvalidHeaders);
        }
        result = result
            .checked_mul(10)
            .and_then(|current| current.checked_add(u64::from(byte - b'0')))
            .ok_or(FetchError::InvalidHeaders)?;
    }
    Ok(result)
}

fn is_json_content_type(value: &str) -> bool {
    let media_type = value.split(';').next().unwrap_or("");
    media_type.trim().eq_ignore_ascii_case("application/json")
}

#[cfg(target_os = "mochios")]
pub struct NetworkTransport;

#[cfg(target_os = "mochios")]
impl Transport for NetworkTransport {
    fn call(&mut self, request: &[u8], reply: &mut [u8]) -> Result<usize, FetchError> {
        let service = mochi_user_platform::process::find_by_name("network.service")
            .map_err(|error| FetchError::Transport(error.errno().unwrap_or(0)))?;
        if service == 0 {
            return Err(FetchError::Transport(mochi_user_platform::syscall::ENOENT));
        }
        let result = mochi_user_platform::ipc::call(service, request, reply)
            .map_err(|error| FetchError::Transport(error.errno().unwrap_or(0)))?;
        let length = (result & 0xffff_ffff) as usize;
        if length > reply.len() {
            Err(FetchError::Wire)
        } else {
            Ok(length)
        }
    }
}
