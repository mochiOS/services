use std::fs;
use std::path::Path;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use mochios_certificate_database::std_file::FileBackend;
use update::coordinator::SnapshotRepository;
use update::repository::CertificateRepository;
use update::scheduler::SnapshotKind;

struct HttpResponse {
    status: u16,
    content_type: Option<String>,
    etag: Option<String>,
    body: Vec<u8>,
}

fn fetch(directory: &Path, name: &str, url: &str, etag: &str) -> HttpResponse {
    let headers_path = directory.join(format!("{name}.headers"));
    let body_path = directory.join(format!("{name}.body"));
    let mut command = Command::new("curl");
    command
        .args([
            "--silent",
            "--show-error",
            "--http1.1",
            "--tlsv1.3",
            "--tls-max",
            "1.3",
            "--dump-header",
        ])
        .arg(&headers_path)
        .arg("--output")
        .arg(&body_path)
        .args(["--write-out", "%{http_code}"]);
    if !etag.is_empty() {
        command
            .arg("--header")
            .arg(format!("If-None-Match: {etag}"));
    }
    let output = command.arg(url).output().unwrap();
    assert!(
        output.status.success(),
        "curl failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let status = std::str::from_utf8(&output.stdout)
        .unwrap()
        .parse::<u16>()
        .unwrap();
    let headers = fs::read_to_string(headers_path).unwrap();
    let mut content_type = None;
    let mut response_etag = None;
    for line in headers.split("\r\n") {
        let Some((header_name, value)) = line.split_once(':') else {
            continue;
        };
        if header_name.eq_ignore_ascii_case("content-type") {
            content_type = Some(value.trim().to_string());
        } else if header_name.eq_ignore_ascii_case("etag") {
            response_etag = Some(value.trim().to_string());
        }
    }
    let body = match fs::read(&body_path) {
        Ok(body) => body,
        Err(error) if status == 304 && error.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(error) => panic!("failed to read curl response body: {error}"),
    };
    HttpResponse {
        status,
        content_type,
        etag: response_etag,
        body,
    }
}

fn decode_roots(value: &str) -> Vec<[u8; 32]> {
    value
        .split(',')
        .map(|encoded| {
            let encoded = encoded.trim();
            assert_eq!(encoded.len(), 64, "Root public key must be 32-byte hex");
            let mut key = [0; 32];
            for (index, byte) in key.iter_mut().enumerate() {
                *byte = u8::from_str_radix(&encoded[index * 2..index * 2 + 2], 16).unwrap();
            }
            key
        })
        .collect()
}

#[test]
#[ignore = "requires the production DeveloperCA and configured Offline Root public key"]
fn production_snapshots_verify_persist_and_reload() {
    let roots = decode_roots(
        &std::env::var("MOCHIOS_DEVELOPER_ROOT_PUBLIC_KEYS_HEX")
            .expect("production Root public key is required"),
    );
    assert!(!roots.is_empty());
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let temporary = std::env::temp_dir().join(format!(
        "developer-pki-production-{}-{now}",
        std::process::id()
    ));
    let database_root = temporary.join("database-root");
    fs::create_dir_all(&database_root).unwrap();
    let backend = FileBackend::for_root(&database_root).unwrap();
    let mut repository = CertificateRepository::load(backend, &roots, now).unwrap();

    let trust = fetch(
        &temporary,
        "trust-initial",
        "https://ca.mochios.org/v1/trust-store",
        "",
    );
    assert_eq!(trust.status, 200);
    assert!(
        trust
            .content_type
            .as_deref()
            .is_some_and(|value| value.starts_with("application/json"))
    );
    let trust_etag = trust.etag.as_deref().expect("Trust ETag is required");
    repository
        .apply(SnapshotKind::Trust, &trust.body, trust_etag, now)
        .unwrap();

    let revocations = fetch(
        &temporary,
        "revocations-initial",
        "https://ca.mochios.org/v1/revocations",
        "",
    );
    assert_eq!(
        revocations.status,
        200,
        "production revocation snapshot is unavailable: {}",
        String::from_utf8_lossy(&revocations.body)
    );
    assert!(
        revocations
            .content_type
            .as_deref()
            .is_some_and(|value| value.starts_with("application/json"))
    );
    let revocation_etag = revocations
        .etag
        .as_deref()
        .expect("Revocation ETag is required");
    repository
        .apply(
            SnapshotKind::Revocations,
            &revocations.body,
            revocation_etag,
            now,
        )
        .unwrap();

    let trust_unchanged = fetch(
        &temporary,
        "trust-unchanged",
        "https://ca.mochios.org/v1/trust-store",
        trust_etag,
    );
    assert_eq!(trust_unchanged.status, 304);
    assert_eq!(trust_unchanged.etag.as_deref(), Some(trust_etag));
    let revocations_unchanged = fetch(
        &temporary,
        "revocations-unchanged",
        "https://ca.mochios.org/v1/revocations",
        revocation_etag,
    );
    assert_eq!(revocations_unchanged.status, 304);
    assert_eq!(revocations_unchanged.etag.as_deref(), Some(revocation_etag));

    let expected_state = repository.state().clone();
    let backend = FileBackend::for_root(&database_root).unwrap();
    let reloaded = CertificateRepository::load(backend, &roots, now).unwrap();
    assert_eq!(reloaded.state(), &expected_state);
    assert!(reloaded.trust().is_some());
    assert!(reloaded.revocations().is_some());
    println!(
        "production DeveloperCA verified: trust={} revocations={} generation={}",
        expected_state.trust.snapshot_version,
        expected_state.revocations.snapshot_version,
        expected_state.generation
    );

    fs::remove_dir_all(temporary).unwrap();
}
