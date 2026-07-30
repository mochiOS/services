use std::fs::{self, File};
use std::io::Write;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::{Engine, engine::general_purpose::STANDARD};
use ed25519_dalek::SigningKey;
use mochios_certificate_database::Slot;
use mochios_certificate_database::std_file::FileBackend;
use mochios_developer_ca_trust::{
    IssuerRecord, IssuerStatus, RevocationReasonCode, RevocationSnapshot, SnapshotRevocation,
    TrustSnapshot, UnsignedRevocationSnapshot, UnsignedTrustSnapshot, key_id,
};
use update::coordinator::{Coordinator, SnapshotFetcher};
use update::http::{FetchError, Response};
use update::repository::CertificateRepository;
use update::scheduler::SnapshotKind;

const TEST_ROOT_SEED: [u8; 32] = [91; 32];
const TEST_ISSUER_SEED: [u8; 32] = [92; 32];

struct Server {
    child: Child,
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

struct CurlFetcher {
    port: u16,
    directory: PathBuf,
    ca_certificate: PathBuf,
}

impl SnapshotFetcher for CurlFetcher {
    fn fetch(
        &mut self,
        kind: SnapshotKind,
        request_id: u64,
        if_none_match: &str,
    ) -> Result<Response, FetchError> {
        let stem = match kind {
            SnapshotKind::Trust => "trust",
            SnapshotKind::Revocations => "revocations",
        };
        let headers_path = self.directory.join(format!("{stem}-{request_id}.headers"));
        let body_path = self.directory.join(format!("{stem}-{request_id}.body"));
        let url = format!(
            "https://tls.test.mochios:{}/v1/{}",
            self.port,
            if kind == SnapshotKind::Trust {
                "trust-store"
            } else {
                "revocations"
            }
        );
        let mut command = Command::new("curl");
        command
            .args([
                "--silent",
                "--show-error",
                "--http1.1",
                "--tlsv1.3",
                "--tls-max",
                "1.3",
                "--noproxy",
                "*",
                "--cacert",
            ])
            .arg(&self.ca_certificate)
            .arg("--resolve")
            .arg(format!("tls.test.mochios:{}:127.0.0.1", self.port))
            .arg("--dump-header")
            .arg(&headers_path)
            .arg("--output")
            .arg(&body_path)
            .args(["--write-out", "%{http_code}"]);
        if !if_none_match.is_empty() {
            command
                .arg("--header")
                .arg(format!("If-None-Match: {if_none_match}"));
        }
        let output = command
            .arg(url)
            .output()
            .map_err(|_| FetchError::Transport(1))?;
        if !output.status.success() {
            return Err(FetchError::Transport(
                output.status.code().unwrap_or(1) as u64
            ));
        }
        let status_code = std::str::from_utf8(&output.stdout)
            .ok()
            .and_then(|value| value.parse::<u16>().ok())
            .ok_or(FetchError::Wire)?;
        let headers = fs::read_to_string(headers_path).map_err(|_| FetchError::Wire)?;
        let mut etag = None;
        let mut retry_after_seconds = None;
        for line in headers.split("\r\n") {
            let Some((name, value)) = line.split_once(':') else {
                continue;
            };
            if name.eq_ignore_ascii_case("etag") {
                etag = Some(value.trim().to_string());
            } else if name.eq_ignore_ascii_case("retry-after") {
                retry_after_seconds = value.trim().parse().ok();
            }
        }
        Ok(Response {
            status_code,
            etag,
            retry_after_seconds,
            body: fs::read(body_path).map_err(|_| FetchError::Wire)?,
        })
    }
}

fn write_json(path: &Path, value: &impl serde::Serialize) {
    fs::write(path, serde_json::to_vec(value).unwrap()).unwrap();
}

fn tamper_signature(value: &mut String) {
    let replacement = if value.starts_with('A') { "B" } else { "A" };
    value.replace_range(0..1, replacement);
}

fn write_snapshots(directory: &Path, now: u64) -> [u8; 32] {
    let root = SigningKey::from_bytes(&TEST_ROOT_SEED);
    let issuer = SigningKey::from_bytes(&TEST_ISSUER_SEED);
    let root_public = root.verifying_key().to_bytes();
    let issuer_public = issuer.verifying_key().to_bytes();
    let issuer_record = IssuerRecord {
        issuer_key_id: key_id(&issuer_public),
        public_key: STANDARD.encode(issuer_public),
        status: IssuerStatus::Active,
        not_before: now - 3_600,
        not_after: now + 86_400,
        allowed_key_usages: vec![
            "developer-certificate-signing".to_string(),
            "revocation-signing".to_string(),
        ],
    };
    let trust = |version| {
        TrustSnapshot::issue(
            UnsignedTrustSnapshot {
                format_version: 1,
                snapshot_version: version,
                generated_at: now - 120 + version,
                expires_at: now + 3_600 + version,
                root_key_id: key_id(&root_public),
                issuers: vec![issuer_record.clone()],
                signature_algorithm: "ed25519".to_string(),
            },
            &root,
        )
        .unwrap()
    };
    let revocations = |version, entries| {
        RevocationSnapshot::issue(
            UnsignedRevocationSnapshot {
                format_version: 1,
                snapshot_version: version,
                generated_at: now - 120 + version,
                expires_at: now + 3_600 + version,
                issuer_key_id: key_id(&issuer_public),
                revocations: entries,
                signature_algorithm: "ed25519".to_string(),
            },
            &issuer,
        )
        .unwrap()
    };
    let trust_v1 = trust(1);
    let trust_v2 = trust(2);
    let revocations_v1 = revocations(1, vec![]);
    let revocations_v2 = revocations(
        2,
        vec![SnapshotRevocation {
            certificate_serial: "4242".to_string(),
            revoked_at: now - 60,
            reason_code: RevocationReasonCode::KeyCompromise,
        }],
    );
    let mut trust_invalid = trust(3);
    tamper_signature(&mut trust_invalid.root_signature);
    let mut revocations_invalid = revocations(3, revocations_v2.content.revocations.clone());
    tamper_signature(&mut revocations_invalid.signature);

    write_json(&directory.join("trust-v1.json"), &trust_v1);
    write_json(&directory.join("trust-v2.json"), &trust_v2);
    write_json(&directory.join("trust-rollback.json"), &trust_v1);
    write_json(
        &directory.join("trust-invalid-signature.json"),
        &trust_invalid,
    );
    write_json(&directory.join("revocations-v1.json"), &revocations_v1);
    write_json(&directory.join("revocations-v2.json"), &revocations_v2);
    write_json(
        &directory.join("revocations-rollback.json"),
        &revocations_v1,
    );
    write_json(
        &directory.join("revocations-invalid-signature.json"),
        &revocations_invalid,
    );
    root_public
}

fn synchronize(
    fetcher: &mut CurlFetcher,
    repository: &mut CertificateRepository<'_, FileBackend>,
    now: u64,
) -> Coordinator {
    let mut coordinator = Coordinator::network_ready(0);
    coordinator.synchronize_due(fetcher, repository, 0, now);
    coordinator
}

#[test]
#[ignore = "host-only deterministic TLS smoke test"]
fn synchronizes_and_recovers_the_developer_pki_database_over_tls() {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let root = manifest.parent().unwrap().parent().unwrap();
    let unique = format!(
        "developer-pki-sync-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let temporary = std::env::temp_dir().join(unique);
    let fixtures = temporary.join("fixtures");
    let database_root = temporary.join("database-root");
    fs::create_dir_all(&fixtures).unwrap();
    fs::create_dir_all(&database_root).unwrap();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let root_public = write_snapshots(&fixtures, now);
    assert_ne!(root_public, update::DEVELOPER_ROOT_PUBLIC_KEYS[0]);

    let port = TcpListener::bind(("127.0.0.1", 0))
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let ready = temporary.join("server.ready");
    let server_log = temporary.join("server.log");
    let output_log = File::create(temporary.join("server.output")).unwrap();
    let child = Command::new("python3")
        .arg(root.join("scripts/developer-pki-smoke-server.py"))
        .arg(port.to_string())
        .arg(&ready)
        .arg(&fixtures)
        .arg(&server_log)
        .stdout(Stdio::from(output_log.try_clone().unwrap()))
        .stderr(Stdio::from(output_log))
        .spawn()
        .unwrap();
    let _server = Server { child };
    for _ in 0..100 {
        if ready.is_file() {
            break;
        }
        thread::sleep(Duration::from_millis(20));
    }
    assert!(ready.is_file(), "fixture server did not become ready");

    let mut fetcher = CurlFetcher {
        port,
        directory: temporary.clone(),
        ca_certificate: root.join("user/crates/tls-client/test-fixtures/test-root.cert.pem"),
    };
    let backend = FileBackend::for_root(&database_root).unwrap();
    let roots = [root_public];
    let mut repository = CertificateRepository::load(backend, &roots, now).unwrap();

    let first = synchronize(&mut fetcher, &mut repository, now);
    assert_eq!(first.statistics().trust_sync_updated, 1);
    assert_eq!(first.statistics().revocation_sync_updated, 1);
    assert_eq!(repository.state().trust.snapshot_version, 1);
    assert_eq!(repository.state().revocations.snapshot_version, 1);
    let slots_after_v1 = (
        repository.state().active_trust_slot,
        repository.state().active_revocation_slot,
    );

    let not_modified = synchronize(&mut fetcher, &mut repository, now + 1);
    assert_eq!(not_modified.statistics().trust_sync_not_modified, 1);
    assert_eq!(not_modified.statistics().revocation_sync_not_modified, 1);
    assert_eq!(
        (
            repository.state().active_trust_slot,
            repository.state().active_revocation_slot,
        ),
        slots_after_v1
    );

    let second = synchronize(&mut fetcher, &mut repository, now + 2);
    assert_eq!(second.statistics().trust_sync_updated, 1);
    assert_eq!(second.statistics().revocation_sync_updated, 1);
    assert_eq!(repository.state().trust.snapshot_version, 2);
    assert_eq!(repository.state().revocations.snapshot_version, 2);
    assert_ne!(repository.state().active_trust_slot, slots_after_v1.0);
    assert_ne!(repository.state().active_revocation_slot, slots_after_v1.1);
    assert!(matches!(
        repository.state().active_trust_slot,
        Slot::A | Slot::B
    ));
    assert!(
        repository
            .revocations()
            .unwrap()
            .snapshot()
            .content
            .revocations
            .iter()
            .any(|entry| entry.certificate_serial == "4242")
    );

    let backend = FileBackend::for_root(&database_root).unwrap();
    let mut repository = CertificateRepository::load(backend, &roots, now + 3).unwrap();
    assert_eq!(repository.state().trust.snapshot_version, 2);
    assert_eq!(repository.state().revocations.snapshot_version, 2);
    assert!(!repository.recovered());

    let rollback = synchronize(&mut fetcher, &mut repository, now + 3);
    assert_eq!(rollback.statistics().snapshot_rollback_rejections, 2);
    assert_eq!(repository.state().trust.snapshot_version, 2);
    assert_eq!(repository.state().revocations.snapshot_version, 2);

    let invalid = synchronize(&mut fetcher, &mut repository, now + 4);
    assert_eq!(invalid.statistics().snapshot_signature_failures, 2);
    assert_eq!(repository.state().trust.snapshot_version, 2);
    assert_eq!(repository.state().revocations.snapshot_version, 2);

    let log = fs::read_to_string(&server_log).unwrap();
    assert_eq!(log.matches("tls=TLSv1.3").count(), 10);
    assert!(log.contains("path=/v1/trust-store request=2 if-none-match=\"trust-v1\""));
    assert!(log.contains("path=/v1/revocations request=2 if-none-match=\"revocations-v1\""));
    assert!(log.contains("path=/v1/trust-store request=4 if-none-match=\"trust-v2\""));
    assert!(log.contains("path=/v1/revocations request=5 if-none-match=\"revocations-v2\""));

    let mut marker = File::create(temporary.join("success")).unwrap();
    writeln!(marker, "trust=2 revocations=2 revoked=4242").unwrap();
    fs::remove_dir_all(temporary).unwrap();
}
