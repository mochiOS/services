use std::collections::VecDeque;

use mochios_http_client::MAX_BODY_BYTES;
use mochios_net_device_protocol::{
    HttpFailure, Opcode, decode_http_request, encode_http_read_result, encode_http_request_result,
};
use update::coordinator::SnapshotFetcher;
use update::http::{DeveloperCaFetcher, REVOCATIONS_URL, TRUST_URL, snapshot_url, version_url};
use update::http::{FetchError, Response, Transport, get};
use update::scheduler::SnapshotKind;

const REQUEST_ID: u64 = 71;
const HANDLE: u64 = 99;

#[derive(Default)]
struct ScriptedTransport {
    replies: VecDeque<Vec<u8>>,
    requests: Vec<Vec<u8>>,
}

impl ScriptedTransport {
    fn with_replies(replies: Vec<Vec<u8>>) -> Self {
        Self {
            replies: replies.into(),
            requests: Vec::new(),
        }
    }
}

impl Transport for ScriptedTransport {
    fn call(&mut self, request: &[u8], reply: &mut [u8]) -> Result<usize, FetchError> {
        self.requests.push(request.to_vec());
        let scripted = self.replies.pop_front().ok_or(FetchError::Transport(5))?;
        if scripted.len() > reply.len() {
            return Err(FetchError::Wire);
        }
        reply[..scripted.len()].copy_from_slice(&scripted);
        Ok(scripted.len())
    }
}

fn request_result(status: u16, content_type: &str, headers: &[u8], body: &[u8]) -> Vec<u8> {
    let mut output = vec![0; 512];
    let length = encode_http_request_result(
        REQUEST_ID,
        0,
        HttpFailure::None,
        status,
        HANDLE,
        body.len() as u32,
        headers.len() as u32,
        content_type,
        &mut output,
    )
    .unwrap();
    output.truncate(length);
    output
}

fn stream(data: &[u8]) -> Vec<u8> {
    let mut output = vec![0; 48 + data.len()];
    let length = encode_http_read_result(
        REQUEST_ID,
        Opcode::HttpReadResult,
        0,
        HttpFailure::None,
        HANDLE,
        true,
        data,
        &mut output,
    )
    .unwrap();
    output.truncate(length);
    output
}

fn close_result() -> Vec<u8> {
    let mut output = vec![0; 48];
    let length = encode_http_read_result(
        REQUEST_ID,
        Opcode::HttpCloseResult,
        0,
        HttpFailure::None,
        HANDLE,
        true,
        &[],
        &mut output,
    )
    .unwrap();
    output.truncate(length);
    output
}

#[test]
fn fetches_json_body_and_forwards_conditional_etag() {
    let headers = b"ETag: W/\"snapshot-7\"\r\nCache-Control: public, max-age=300\r\n";
    let body = br#"{"format_version":1}"#;
    let mut transport = ScriptedTransport::with_replies(vec![
        request_result(200, "application/json; charset=utf-8", headers, body),
        stream(headers),
        stream(body),
        close_result(),
    ]);
    assert_eq!(
        get(
            &mut transport,
            REQUEST_ID,
            "https://ca.mochios.org/v1/trust-store",
            "\"old\"",
        ),
        Ok(Response {
            status_code: 200,
            etag: Some("W/\"snapshot-7\"".to_string()),
            retry_after_seconds: None,
            body: body.to_vec(),
        })
    );
    let request = decode_http_request(&transport.requests[0]).unwrap();
    assert_eq!(request.if_none_match, "\"old\"");
    assert!(transport.replies.is_empty());
}

#[test]
fn accepts_only_consistent_bodyless_not_modified_response() {
    let headers = b"etag: \"same\"\r\n";
    let mut transport = ScriptedTransport::with_replies(vec![
        request_result(304, "application/json", headers, &[]),
        stream(headers),
        close_result(),
    ]);
    assert_eq!(
        get(
            &mut transport,
            REQUEST_ID,
            "https://ca.mochios.org/v1/revocations",
            "\"same\"",
        )
        .unwrap()
        .status_code,
        304
    );

    let mismatched = b"ETag: \"new\"\r\n";
    let mut transport = ScriptedTransport::with_replies(vec![
        request_result(304, "application/json", mismatched, &[]),
        stream(mismatched),
        close_result(),
    ]);
    assert_eq!(
        get(
            &mut transport,
            REQUEST_ID,
            "https://ca.mochios.org/v1/revocations",
            "\"old\"",
        ),
        Err(FetchError::EtagMismatch)
    );
    assert!(transport.replies.is_empty());
}

#[test]
fn duplicate_etag_and_invalid_content_type_are_rejected_and_closed() {
    let duplicate = b"ETag: \"a\"\r\netag: \"b\"\r\n";
    let mut transport = ScriptedTransport::with_replies(vec![
        request_result(200, "application/json", duplicate, b"x"),
        stream(duplicate),
        close_result(),
    ]);
    assert_eq!(
        get(
            &mut transport,
            REQUEST_ID,
            "https://ca.mochios.org/v1/trust-store",
            "",
        ),
        Err(FetchError::InvalidHeaders)
    );
    assert!(transport.replies.is_empty());

    let headers = b"ETag: \"a\"\r\n";
    let mut transport = ScriptedTransport::with_replies(vec![
        request_result(200, "text/plain", headers, b"x"),
        stream(headers),
        close_result(),
    ]);
    assert_eq!(
        get(
            &mut transport,
            REQUEST_ID,
            "https://ca.mochios.org/v1/trust-store",
            "",
        ),
        Err(FetchError::InvalidContentType)
    );
    assert!(transport.replies.is_empty());
}

#[test]
fn retry_after_is_parsed_for_transient_http_status() {
    let headers = b"Retry-After: 120\r\n";
    let body = b"busy";
    let mut transport = ScriptedTransport::with_replies(vec![
        request_result(503, "application/json", headers, body),
        stream(headers),
        stream(body),
        close_result(),
    ]);
    let response = get(
        &mut transport,
        REQUEST_ID,
        "https://ca.mochios.org/v1/revocations",
        "",
    )
    .unwrap();
    assert_eq!(response.status_code, 503);
    assert_eq!(response.retry_after_seconds, Some(120));
}

#[test]
fn oversized_declared_body_is_rejected_and_handle_is_closed() {
    let mut output = vec![0; 512];
    let length = encode_http_request_result(
        REQUEST_ID,
        0,
        HttpFailure::None,
        200,
        HANDLE,
        (MAX_BODY_BYTES + 1) as u32,
        0,
        "application/json",
        &mut output,
    )
    .unwrap();
    output.truncate(length);
    let mut transport = ScriptedTransport::with_replies(vec![output, close_result()]);
    assert_eq!(
        get(
            &mut transport,
            REQUEST_ID,
            "https://ca.mochios.org/v1/trust-store",
            "",
        ),
        Err(FetchError::DeclaredLengthTooLarge)
    );
    assert!(transport.replies.is_empty());
}

#[test]
fn empty_success_body_does_not_require_a_read_call() {
    let headers = b"ETag: \"empty\"\r\n";
    let mut transport = ScriptedTransport::with_replies(vec![
        request_result(200, "application/json", headers, &[]),
        stream(headers),
        close_result(),
    ]);
    let response = get(
        &mut transport,
        REQUEST_ID,
        "https://ca.mochios.org/v1/trust-store",
        "",
    )
    .unwrap();
    assert!(response.body.is_empty());
    assert_eq!(transport.requests.len(), 3);
}

#[test]
fn fetcher_routes_each_snapshot_kind_to_the_fixed_https_endpoint() {
    for (kind, expected_url) in [
        (SnapshotKind::Trust, TRUST_URL),
        (SnapshotKind::Revocations, REVOCATIONS_URL),
    ] {
        let headers = b"ETag: \"snapshot\"\r\n";
        let transport = ScriptedTransport::with_replies(vec![
            request_result(200, "application/json", headers, b"{}"),
            stream(headers),
            stream(b"{}"),
            close_result(),
        ]);
        let mut fetcher = DeveloperCaFetcher::new(transport);
        fetcher.fetch(kind, REQUEST_ID, "").unwrap();
        let transport = fetcher.into_transport();
        let request = decode_http_request(&transport.requests[0]).unwrap();
        assert_eq!(request.url, expected_url);
        assert_eq!(snapshot_url(kind), expected_url);
        assert_eq!(version_url(kind, 42), format!("{expected_url}/42"));
    }
}
