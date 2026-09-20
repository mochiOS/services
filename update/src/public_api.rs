//! Small, bounded client for the public OS API. No credentials are sent.

use mochios_net_device_protocol::{
    HTTP_REQUEST_RESULT_BASE_LEN, HttpMethod, HttpStream, MAX_HTTP_CONTENT_TYPE_LEN,
    decode_http_request_result, encode_http_request,
};

use crate::http::{FetchError, Transport, close, read_stream};

pub const BASE_URL: &str = "https://api.mochios.org";
const TIMEOUT_MS: u32 = 30_000;
const MAX_RESPONSE_BYTES: usize = 64 * 1024;
const MAX_HEADERS_BYTES: usize = 16 * 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Response {
    pub status: u16,
    pub request_id: Option<String>,
    pub retry_after_seconds: Option<u64>,
    pub body: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApiError {
    Transport(FetchError),
    InvalidHeaders,
    InvalidContentType,
    ResponseTooLarge,
}

pub fn request<T: Transport>(
    transport: &mut T,
    request_id: u64,
    method: HttpMethod,
    path: &str,
    body: &[u8],
) -> Result<Response, ApiError> {
    if !path.starts_with('/') || path.starts_with("//") || body.len() > MAX_RESPONSE_BYTES {
        return Err(ApiError::ResponseTooLarge);
    }
    let url = format!("{BASE_URL}{path}");
    let content_type = if matches!(method, HttpMethod::Post) {
        "application/json"
    } else {
        ""
    };
    let mut encoded = vec![0; 48 + url.len() + content_type.len() + body.len()];
    let length = encode_http_request(
        request_id,
        method,
        TIMEOUT_MS,
        &url,
        content_type,
        "",
        body,
        &mut encoded,
    )
    .map_err(|_| ApiError::Transport(FetchError::Wire))?;
    let mut reply = [0; HTTP_REQUEST_RESULT_BASE_LEN + MAX_HTTP_CONTENT_TYPE_LEN];
    let reply_length = transport
        .call(&encoded[..length], &mut reply)
        .map_err(ApiError::Transport)?;
    let result = decode_http_request_result(
        reply.get(..reply_length)
            .ok_or(ApiError::Transport(FetchError::Wire))?,
    )
    .map_err(|_| ApiError::Transport(FetchError::Wire))?;
    if result.request_id != request_id {
        return Err(ApiError::Transport(FetchError::RequestIdMismatch));
    }
    if result.status != 0 || result.failure != mochios_net_device_protocol::HttpFailure::None {
        return Err(ApiError::Transport(FetchError::ServiceFailure {
            status: result.status,
            failure: result.failure,
        }));
    }
    let handle = result.handle;
    let fetched = (|| {
        if result.body_length as usize > MAX_RESPONSE_BYTES
            || result.headers_length as usize > MAX_HEADERS_BYTES
        {
            return Err(ApiError::ResponseTooLarge);
        }
        let headers = read_stream(
            transport,
            request_id,
            handle,
            HttpStream::Headers,
            result.headers_length as usize,
        )
        .map_err(ApiError::Transport)?;
        let (request_id_header, retry_after_seconds) = parse_headers(&headers)?;
        let body = read_stream(
            transport,
            request_id,
            handle,
            HttpStream::Body,
            result.body_length as usize,
        )
        .map_err(ApiError::Transport)?;
        if (200..300).contains(&result.status_code)
            && !body.is_empty()
            && !result
                .content_type
                .split(';')
                .next()
                .unwrap_or("")
                .trim()
                .eq_ignore_ascii_case("application/json")
        {
            return Err(ApiError::InvalidContentType);
        }
        Ok(Response {
            status: result.status_code,
            request_id: request_id_header,
            retry_after_seconds,
            body,
        })
    })();
    let closed = close(transport, request_id, handle).map_err(ApiError::Transport);
    match (fetched, closed) {
        (Ok(response), Ok(())) => Ok(response),
        (Err(error), _) | (Ok(_), Err(error)) => Err(error),
    }
}

fn parse_headers(bytes: &[u8]) -> Result<(Option<String>, Option<u64>), ApiError> {
    let text = std::str::from_utf8(bytes).map_err(|_| ApiError::InvalidHeaders)?;
    let mut request_id = None;
    let mut retry_after = None;
    for line in text.split("\r\n").filter(|line| !line.is_empty()) {
        let (name, value) = line.split_once(':').ok_or(ApiError::InvalidHeaders)?;
        let value = value.trim_matches([' ', '\t']);
        if name.eq_ignore_ascii_case("x-request-id") {
            if request_id.is_some()
                || value.is_empty()
                || value.len() > 128
                || !value.bytes().all(|byte| byte.is_ascii_graphic())
            {
                return Err(ApiError::InvalidHeaders);
            }
            request_id = Some(value.to_owned());
        } else if name.eq_ignore_ascii_case("retry-after") {
            if retry_after.is_some() {
                return Err(ApiError::InvalidHeaders);
            }
            retry_after = Some(value.parse().map_err(|_| ApiError::InvalidHeaders)?);
        }
    }
    Ok((request_id, retry_after))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_request_id_and_retry_after() {
        assert_eq!(
            parse_headers(b"x-request-id: abc-123\r\nRetry-After: 60\r\n"),
            Ok((Some("abc-123".to_owned()), Some(60)))
        );
    }

    #[test]
    fn rejects_duplicate_request_id() {
        assert_eq!(
            parse_headers(b"x-request-id: first\r\nx-request-id: second\r\n"),
            Err(ApiError::InvalidHeaders)
        );
    }
}
