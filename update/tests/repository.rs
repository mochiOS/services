use std::collections::BTreeMap;

use base64::{Engine, engine::general_purpose::STANDARD};
use ed25519_dalek::SigningKey;
use mochios_certificate_database::storage::{
    REVOCATIONS_B_PATH, STATE_PATH, StorageBackend, StorageError, TRUST_A_PATH, TRUST_B_PATH,
};
use mochios_certificate_database::{DatabaseState, Slot};
use mochios_developer_ca_trust::{
    IssuerRecord, IssuerStatus, RevocationSnapshot, TrustSnapshot, UnsignedRevocationSnapshot,
    UnsignedTrustSnapshot, key_id,
};
use update::coordinator::{ApplyError, SnapshotRepository};
use update::repository::CertificateRepository;
use update::scheduler::SnapshotKind;

const NOW: u64 = 1_000;

#[derive(Default)]
struct MemoryBackend {
    files: BTreeMap<String, Vec<u8>>,
    writes: Vec<String>,
    fail_path: Option<String>,
    corrupt_after_write: Option<String>,
}

impl StorageBackend for MemoryBackend {
    fn read(&mut self, path: &str) -> Result<Option<Vec<u8>>, StorageError> {
        let mut bytes = self.files.get(path).cloned();
        if self.corrupt_after_write.as_deref() == Some(path)
            && self.writes.iter().any(|written| written == path)
            && let Some(first) = bytes.as_mut().and_then(|bytes| bytes.first_mut())
        {
            *first ^= 0xff;
        }
        Ok(bytes)
    }

    fn write_sync(&mut self, path: &str, bytes: &[u8]) -> Result<(), StorageError> {
        if self.fail_path.as_deref() == Some(path) {
            return Err(StorageError::Backend);
        }
        self.writes.push(path.to_string());
        self.files.insert(path.to_string(), bytes.to_vec());
        Ok(())
    }
}

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn trust(root: &SigningKey, issuer: &SigningKey, version: u64) -> TrustSnapshot {
    let issuer_public_key = issuer.verifying_key().to_bytes();
    TrustSnapshot::issue(
        UnsignedTrustSnapshot {
            format_version: 1,
            snapshot_version: version,
            generated_at: 900 + version,
            expires_at: 1_900 + version,
            root_key_id: key_id(&root.verifying_key().to_bytes()),
            issuers: vec![IssuerRecord {
                issuer_key_id: key_id(&issuer_public_key),
                public_key: STANDARD.encode(issuer_public_key),
                status: IssuerStatus::Active,
                not_before: 100,
                not_after: 2_000,
                allowed_key_usages: vec!["revocation-signing".to_string()],
            }],
            signature_algorithm: "ed25519".to_string(),
        },
        root,
    )
    .unwrap()
}

fn revocations(issuer: &SigningKey, version: u64) -> RevocationSnapshot {
    RevocationSnapshot::issue(
        UnsignedRevocationSnapshot {
            format_version: 1,
            snapshot_version: version,
            generated_at: 900 + version,
            expires_at: 1_100 + version,
            issuer_key_id: key_id(&issuer.verifying_key().to_bytes()),
            revocations: vec![],
            signature_algorithm: "ed25519".to_string(),
        },
        issuer,
    )
    .unwrap()
}

fn json<T: serde::Serialize>(value: &T) -> Vec<u8> {
    serde_json::to_vec(value).unwrap()
}

#[test]
fn loads_empty_database_as_recovered_without_trust() {
    let root = key(1);
    let roots = [root.verifying_key().to_bytes()];
    let repository = CertificateRepository::load(MemoryBackend::default(), &roots, NOW).unwrap();

    assert!(repository.recovered());
    assert!(repository.trust().is_none());
    assert!(repository.revocations().is_none());
    assert_eq!(repository.state().generation, 1);
    assert!(repository.into_backend().files.contains_key(STATE_PATH));
}

#[test]
fn applies_trust_before_revocations_and_commits_each_inactive_slot() {
    let root = key(1);
    let issuer = key(2);
    let roots = [root.verifying_key().to_bytes()];
    let trust = trust(&root, &issuer, 1);
    let revocations = revocations(&issuer, 1);
    let mut repository =
        CertificateRepository::load(MemoryBackend::default(), &roots, NOW).unwrap();

    repository
        .apply(SnapshotKind::Trust, &json(&trust), "\"trust-1\"", NOW)
        .unwrap();
    repository
        .apply(
            SnapshotKind::Revocations,
            &json(&revocations),
            "W/\"revocations-1\"",
            NOW,
        )
        .unwrap();

    assert_eq!(repository.state().active_trust_slot, Slot::B);
    assert_eq!(repository.state().active_revocation_slot, Slot::B);
    assert_eq!(repository.state().trust.snapshot_version, 1);
    assert_eq!(repository.state().revocations.snapshot_version, 1);
    assert_eq!(repository.etag(SnapshotKind::Trust), "\"trust-1\"");
    assert_eq!(
        repository.etag(SnapshotKind::Revocations),
        "W/\"revocations-1\""
    );
    let backend = repository.into_backend();
    assert_eq!(backend.files.get(TRUST_B_PATH), Some(&json(&trust)));
    assert_eq!(
        backend.files.get(REVOCATIONS_B_PATH),
        Some(&json(&revocations))
    );
}

#[test]
fn revocations_require_active_trust() {
    let root = key(1);
    let issuer = key(2);
    let roots = [root.verifying_key().to_bytes()];
    let mut repository =
        CertificateRepository::load(MemoryBackend::default(), &roots, NOW).unwrap();

    assert_eq!(
        repository.apply(
            SnapshotKind::Revocations,
            &json(&revocations(&issuer, 1)),
            "\"revocations-1\"",
            NOW,
        ),
        Err(ApplyError::UnknownIssuer)
    );
}

#[test]
fn not_modified_updates_only_state_and_preserves_active_slot_and_etag() {
    let root = key(1);
    let issuer = key(2);
    let roots = [root.verifying_key().to_bytes()];
    let mut repository =
        CertificateRepository::load(MemoryBackend::default(), &roots, NOW).unwrap();
    repository
        .apply(
            SnapshotKind::Trust,
            &json(&trust(&root, &issuer, 1)),
            "\"trust-1\"",
            NOW,
        )
        .unwrap();
    let slot = repository.state().active_trust_slot;
    let version = repository.state().trust.snapshot_version;
    let generation = repository.state().generation;

    repository
        .mark_checked(SnapshotKind::Trust, NOW + 10)
        .unwrap();

    assert_eq!(repository.state().active_trust_slot, slot);
    assert_eq!(repository.state().trust.snapshot_version, version);
    assert_eq!(repository.state().trust.last_checked_at, NOW + 10);
    assert_eq!(repository.etag(SnapshotKind::Trust), "\"trust-1\"");
    assert_eq!(repository.state().generation, generation + 1);
    let backend = repository.into_backend();
    assert_eq!(backend.writes.last().map(String::as_str), Some(STATE_PATH));
}

#[test]
fn writeback_corruption_does_not_change_active_memory_or_state() {
    let root = key(1);
    let issuer = key(2);
    let roots = [root.verifying_key().to_bytes()];
    let backend = MemoryBackend {
        corrupt_after_write: Some(TRUST_B_PATH.to_string()),
        ..MemoryBackend::default()
    };
    let mut repository = CertificateRepository::load(backend, &roots, NOW).unwrap();
    let state = repository.state().clone();

    assert_eq!(
        repository.apply(
            SnapshotKind::Trust,
            &json(&trust(&root, &issuer, 1)),
            "\"trust-1\"",
            NOW,
        ),
        Err(ApplyError::Storage)
    );
    assert_eq!(repository.state(), &state);
    assert!(repository.trust().is_none());
}

#[test]
fn corrupt_active_trust_falls_back_to_previous_valid_slot() {
    let root = key(1);
    let issuer = key(2);
    let roots = [root.verifying_key().to_bytes()];
    let mut repository =
        CertificateRepository::load(MemoryBackend::default(), &roots, NOW).unwrap();
    repository
        .apply(
            SnapshotKind::Trust,
            &json(&trust(&root, &issuer, 1)),
            "\"trust-1\"",
            NOW,
        )
        .unwrap();
    repository
        .apply(
            SnapshotKind::Trust,
            &json(&trust(&root, &issuer, 2)),
            "\"trust-2\"",
            NOW,
        )
        .unwrap();
    let mut backend = repository.into_backend();
    backend.files.insert(TRUST_A_PATH.to_string(), vec![0xff]);

    let recovered = CertificateRepository::load(backend, &roots, NOW).unwrap();

    assert!(recovered.recovered());
    assert_eq!(recovered.state().active_trust_slot, Slot::B);
    assert_eq!(recovered.state().trust.snapshot_version, 1);
    assert_eq!(
        recovered
            .trust()
            .unwrap()
            .snapshot()
            .content
            .snapshot_version,
        1
    );
}

#[test]
fn invalid_etag_is_rejected_before_storage() {
    let root = key(1);
    let issuer = key(2);
    let roots = [root.verifying_key().to_bytes()];
    let mut repository =
        CertificateRepository::load(MemoryBackend::default(), &roots, NOW).unwrap();
    assert_eq!(
        repository.apply(
            SnapshotKind::Trust,
            &json(&trust(&root, &issuer, 1)),
            "not-an-etag",
            NOW,
        ),
        Err(ApplyError::InvalidSnapshot)
    );
}

#[test]
fn state_write_failure_keeps_previous_active_snapshot() {
    let root = key(1);
    let issuer = key(2);
    let roots = [root.verifying_key().to_bytes()];
    let mut repository =
        CertificateRepository::load(MemoryBackend::default(), &roots, NOW).unwrap();
    repository
        .apply(
            SnapshotKind::Trust,
            &json(&trust(&root, &issuer, 1)),
            "\"trust-1\"",
            NOW,
        )
        .unwrap();
    let state = repository.state().clone();
    let mut backend = repository.into_backend();
    backend.fail_path = Some(STATE_PATH.to_string());
    let mut repository = CertificateRepository::load(backend, &roots, NOW).unwrap();

    assert_eq!(
        repository.apply(
            SnapshotKind::Trust,
            &json(&trust(&root, &issuer, 2)),
            "\"trust-2\"",
            NOW,
        ),
        Err(ApplyError::Storage)
    );
    assert_eq!(repository.state(), &state);
    assert_eq!(
        repository
            .trust()
            .unwrap()
            .snapshot()
            .content
            .snapshot_version,
        1
    );
    assert_eq!(
        DatabaseState::decode(repository.into_backend().files.get(STATE_PATH).unwrap()).unwrap(),
        state
    );
}
