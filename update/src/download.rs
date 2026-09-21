//! Sequential HTTPS range downloader for large update artifacts.

use mochios_net_device_protocol::{
    HTTP_REQUEST_RESULT_BASE_LEN, HttpFailure, HttpMethod, HttpStream,
    MAX_HTTP_CONTENT_TYPE_LEN, decode_http_request_result, encode_http_request_with_range,
};

use crate::http::{FetchError, Transport, close, read_stream};
use crate::installer::RangeSource;

const TIMEOUT_MS: u32 = 60_000;
const MAX_HEADERS_BYTES: usize = 16 * 1024;
const MAX_RANGE_BYTES: usize = 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DownloadError {
    Transport(FetchError),
    Wire,
    WrongStatus(u16),
    InvalidHeaders,
    WrongRange,
    ChangedEntity,
    InvalidLength,
}

pub struct RangeDownloader<'a, T> {
    transport: T,
    url: &'a str,
    total: u64,
    next_offset: u64,
    next_request_id: u64,
    entity_tag: Option<String>,
}

impl<'a, T> RangeDownloader<'a, T> {
    pub fn new(transport: T, url: &'a str, total: u64, first_request_id: u64) -> Self {
        Self { transport, url, total, next_offset: 0, next_request_id: first_request_id, entity_tag: None }
    }
}

impl<T: Transport> RangeSource for RangeDownloader<'_, T> {
    type Error = DownloadError;

    fn fetch(&mut self, offset: u64, length: usize) -> Result<Vec<u8>, Self::Error> {
        if offset != self.next_offset || length == 0 || length > MAX_RANGE_BYTES
            || offset.checked_add(length as u64).is_none_or(|end| end > self.total)
        {
            return Err(DownloadError::InvalidLength);
        }
        let end = offset + length as u64 - 1;
        let range = format!("bytes={offset}-{end}");
        let request_id = self.next_request_id;
        self.next_request_id = self.next_request_id.checked_add(1).ok_or(DownloadError::Wire)?;
        let mut request = vec![0; 48 + self.url.len() + range.len()];
        let request_length = encode_http_request_with_range(
            request_id, HttpMethod::Get, TIMEOUT_MS, self.url, "", "", &range, &[], &mut request,
        ).map_err(|_| DownloadError::Wire)?;
        let mut reply = [0; HTTP_REQUEST_RESULT_BASE_LEN + MAX_HTTP_CONTENT_TYPE_LEN];
        let reply_length = self.transport.call(&request[..request_length], &mut reply)
            .map_err(DownloadError::Transport)?;
        let result = decode_http_request_result(reply.get(..reply_length).ok_or(DownloadError::Wire)?)
            .map_err(|_| DownloadError::Wire)?;
        if result.request_id != request_id { return Err(DownloadError::Wire); }
        if result.status != 0 || result.failure != HttpFailure::None {
            return Err(DownloadError::Transport(FetchError::ServiceFailure {
                status: result.status, failure: result.failure,
            }));
        }
        let handle = result.handle;
        let fetched = (|| {
            if result.status_code != 206 { return Err(DownloadError::WrongStatus(result.status_code)); }
            if result.headers_length as usize > MAX_HEADERS_BYTES
                || result.body_length as usize != length
            {
                return Err(DownloadError::InvalidLength);
            }
            let headers = read_stream(
                &mut self.transport, request_id, handle, HttpStream::Headers,
                result.headers_length as usize,
            ).map_err(DownloadError::Transport)?;
            let parsed = parse_headers(&headers)?;
            if parsed.content_range != (offset, end, self.total) {
                return Err(DownloadError::WrongRange);
            }
            if let Some(expected) = &self.entity_tag {
                if parsed.entity_tag.as_deref() != Some(expected.as_str()) {
                    return Err(DownloadError::ChangedEntity);
                }
            } else {
                self.entity_tag = parsed.entity_tag;
            }
            read_stream(&mut self.transport, request_id, handle, HttpStream::Body, length)
                .map_err(DownloadError::Transport)
        })();
        let closed = close(&mut self.transport, request_id, handle).map_err(DownloadError::Transport);
        let body = match (fetched, closed) {
            (Ok(body), Ok(())) => body,
            (Err(error), _) | (Ok(_), Err(error)) => return Err(error),
        };
        self.next_offset += length as u64;
        Ok(body)
    }
}

struct ParsedHeaders {
    content_range: (u64, u64, u64),
    entity_tag: Option<String>,
}

fn parse_headers(bytes: &[u8]) -> Result<ParsedHeaders, DownloadError> {
    let text = std::str::from_utf8(bytes).map_err(|_| DownloadError::InvalidHeaders)?;
    let mut content_range = None;
    let mut entity_tag = None;
    for line in text.split("\r\n").filter(|line| !line.is_empty()) {
        let (name, value) = line.split_once(':').ok_or(DownloadError::InvalidHeaders)?;
        let value = value.trim_matches([' ', '\t']);
        if name.eq_ignore_ascii_case("content-range") {
            if content_range.is_some() { return Err(DownloadError::InvalidHeaders); }
            content_range = Some(parse_content_range(value)?);
        } else if name.eq_ignore_ascii_case("etag") {
            if entity_tag.is_some() || value.len() > 128 || value.starts_with("W/")
                || value.len() < 2 || !value.starts_with('"') || !value.ends_with('"')
                || value.bytes().any(|byte| byte.is_ascii_control())
            {
                return Err(DownloadError::InvalidHeaders);
            }
            entity_tag = Some(value.to_owned());
        }
    }
    Ok(ParsedHeaders { content_range: content_range.ok_or(DownloadError::InvalidHeaders)?, entity_tag })
}

fn parse_content_range(value: &str) -> Result<(u64, u64, u64), DownloadError> {
    let value = value.strip_prefix("bytes ").ok_or(DownloadError::InvalidHeaders)?;
    let (range, total) = value.split_once('/').ok_or(DownloadError::InvalidHeaders)?;
    let (start, end) = range.split_once('-').ok_or(DownloadError::InvalidHeaders)?;
    if start.is_empty() || end.is_empty() || total.is_empty()
        || start.starts_with('+') || end.starts_with('+') || total.starts_with('+')
    {
        return Err(DownloadError::InvalidHeaders);
    }
    let parsed = (
        start.parse().map_err(|_| DownloadError::InvalidHeaders)?,
        end.parse().map_err(|_| DownloadError::InvalidHeaders)?,
        total.parse().map_err(|_| DownloadError::InvalidHeaders)?,
    );
    if parsed.0 > parsed.1 || parsed.2 == 0 || parsed.1 >= parsed.2 {
        return Err(DownloadError::InvalidHeaders);
    }
    Ok(parsed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_only_canonical_bounded_content_ranges() {
        let parsed = parse_headers(b"Content-Range: bytes 4096-8191/16384\r\nETag: \"abc\"\r\n").unwrap();
        assert_eq!(parsed.content_range, (4096, 8191, 16384));
        assert_eq!(parsed.entity_tag.as_deref(), Some("\"abc\""));
        for invalid in [
            "bytes */10", "bytes 2-1/10", "bytes 0-10/10", "bytes +0-1/10", "items 0-1/10",
        ] {
            assert_eq!(parse_content_range(invalid), Err(DownloadError::InvalidHeaders));
        }
    }
}
