use std::collections::BTreeMap;

use base64::{Engine, engine::general_purpose::STANDARD};
use ed25519_dalek::SigningKey;
use mochios_certificate::{DeveloperCertificate, KEY_USAGE_PACKAGE_SIGNING, key_id as cert_key_id};
use mochios_certificate_database::storage::{
    REVOCATIONS_A_PATH, StorageBackend, StorageError, TRUST_A_PATH,
};
use mochios_developer_ca_trust::{
    IssuerRecord, IssuerStatus, RevocationReasonCode, RevocationSnapshot, SnapshotRevocation,
    TrustSnapshot, UnsignedRevocationSnapshot, UnsignedTrustSnapshot, key_id,
};
use signature::database::{ActiveDatabase, DatabaseError};

const NOW: u64 = 1_000;

#[derive(Default)]
struct MemoryBackend {
    files: BTreeMap<String, Vec<u8>>,
}

impl StorageBackend for MemoryBackend {
    fn read(&mut self, path: &str) -> Result<Option<Vec<u8>>, StorageError> {
        Ok(self.files.get(path).cloned())
    }

    fn write_sync(&mut self, _path: &str, _bytes: &[u8]) -> Result<(), StorageError> {
        Err(StorageError::Backend)
    }
}

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn database(status: IssuerStatus, revoked: bool) -> (ActiveDatabase, DeveloperCertificate) {
    let root = key(1);
    let issuer = key(2);
    let subject = key(3);
    let revocation_issuer = key(4);
    let issuer_public_key = issuer.verifying_key().to_bytes();
    let revocation_public_key = revocation_issuer.verifying_key().to_bytes();
    let mut issuers = vec![
        IssuerRecord {
            issuer_key_id: key_id(&issuer_public_key),
            public_key: STANDARD.encode(issuer_public_key),
            status,
            not_before: 800,
            not_after: 1_400,
            allowed_key_usages: vec!["developer-certificate-signing".to_string()],
        },
        IssuerRecord {
            issuer_key_id: key_id(&revocation_public_key),
            public_key: STANDARD.encode(revocation_public_key),
            status: IssuerStatus::Retired,
            not_before: 800,
            not_after: 1_400,
            allowed_key_usages: vec!["revocation-signing".to_string()],
        },
    ];
    issuers.sort_by(|left, right| left.issuer_key_id.cmp(&right.issuer_key_id));
    let trust = TrustSnapshot::issue(
        UnsignedTrustSnapshot {
            format_version: 1,
            snapshot_version: 4,
            generated_at: 900,
            expires_at: 1_500,
            root_key_id: key_id(&root.verifying_key().to_bytes()),
            issuers,
            signature_algorithm: "ed25519".to_string(),
        },
        &root,
    )
    .unwrap();
    let serial_number = 42;
    let revocations = RevocationSnapshot::issue(
        UnsignedRevocationSnapshot {
            format_version: 1,
            snapshot_version: 7,
            generated_at: 950,
            expires_at: 1_200,
            issuer_key_id: key_id(&revocation_public_key),
            revocations: if revoked {
                vec![SnapshotRevocation {
                    certificate_serial: serial_number.to_string(),
                    revoked_at: 960,
                    reason_code: RevocationReasonCode::KeyCompromise,
                }]
            } else {
                vec![]
            },
            signature_algorithm: "ed25519".to_string(),
        },
        &revocation_issuer,
    )
    .unwrap();
    let mut backend = MemoryBackend::default();
    backend.files.insert(
        TRUST_A_PATH.to_string(),
        serde_json::to_vec(&trust).unwrap(),
    );
    backend.files.insert(
        REVOCATIONS_A_PATH.to_string(),
        serde_json::to_vec(&revocations).unwrap(),
    );
    let roots = [root.verifying_key().to_bytes()];
    let database = ActiveDatabase::load_from(backend, &roots).unwrap();
    let subject_public_key = subject.verifying_key().to_bytes();
    let certificate = DeveloperCertificate {
        serial_number,
        issuer_key_id: cert_key_id(&issuer_public_key),
        developer_id: "019f9e5ac6687902b0e72fe53abfbef1".to_string(),
        subject_key_id: cert_key_id(&subject_public_key),
        subject_public_key,
        not_before: 900,
        not_after: 1_100,
        key_usage: KEY_USAGE_PACKAGE_SIGNING,
        package_id_scopes: vec![],
        allowed_capabilities: vec![],
        signature: [0; 64],
    };
    (database, certificate)
}

#[test]
fn active_and_retired_issuers_are_accepted() {
    for status in [IssuerStatus::Active, IssuerStatus::Retired] {
        let (database, certificate) = database(status, false);
        assert!(database.issuer_public_key(&certificate, NOW).is_ok());
    }
}

#[test]
fn future_revoked_and_unknown_issuers_are_rejected() {
    for status in [IssuerStatus::Future, IssuerStatus::Revoked] {
        let (database, certificate) = database(status, false);
        assert_eq!(
            database.issuer_public_key(&certificate, NOW),
            Err(DatabaseError::UnknownIssuer)
        );
    }
    let (database, mut certificate) = database(IssuerStatus::Active, false);
    certificate.issuer_key_id = [0xff; 32];
    assert_eq!(
        database.issuer_public_key(&certificate, NOW),
        Err(DatabaseError::UnknownIssuer)
    );
}

#[test]
fn revoked_certificate_and_expired_snapshots_are_rejected() {
    let (database, certificate) = database(IssuerStatus::Active, true);
    assert_eq!(
        database.issuer_public_key(&certificate, NOW),
        Err(DatabaseError::Revoked)
    );
    assert_eq!(
        database.issuer_public_key(&certificate, 1_200),
        Err(DatabaseError::Expired)
    );
}
