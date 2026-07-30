use base64::{Engine, engine::general_purpose::STANDARD};
use ed25519_dalek::SigningKey;
use mochios_developer_ca_trust::{
    IssuerRecord, IssuerStatus, RevocationReasonCode, RevocationSnapshot, SnapshotRevocation,
    TrustSnapshot, UnsignedRevocationSnapshot, UnsignedTrustSnapshot, key_id,
};
use update::coordinator::ApplyError;
use update::snapshot::{SnapshotVerifier, VerifiedTrust};

const NOW: u64 = 1_000;

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn issuer_record(signing_key: &SigningKey, status: IssuerStatus) -> IssuerRecord {
    let public_key = signing_key.verifying_key().to_bytes();
    IssuerRecord {
        issuer_key_id: key_id(&public_key),
        public_key: STANDARD.encode(public_key),
        status,
        not_before: 100,
        not_after: 2_000,
        allowed_key_usages: vec![
            "developer-certificate-signing".to_string(),
            "revocation-signing".to_string(),
        ],
    }
}

fn issue_trust(
    root: &SigningKey,
    issuer: &SigningKey,
    version: u64,
    status: IssuerStatus,
) -> TrustSnapshot {
    TrustSnapshot::issue(
        UnsignedTrustSnapshot {
            format_version: 1,
            snapshot_version: version,
            generated_at: 900 + version,
            expires_at: 1_900 + version,
            root_key_id: key_id(&root.verifying_key().to_bytes()),
            issuers: vec![issuer_record(issuer, status)],
            signature_algorithm: "ed25519".to_string(),
        },
        root,
    )
    .unwrap()
}

fn revocations(
    issuer: &SigningKey,
    version: u64,
    entries: Vec<SnapshotRevocation>,
) -> RevocationSnapshot {
    RevocationSnapshot::issue(
        UnsignedRevocationSnapshot {
            format_version: 1,
            snapshot_version: version,
            generated_at: 900 + version,
            expires_at: 1_100 + version,
            issuer_key_id: key_id(&issuer.verifying_key().to_bytes()),
            revocations: entries,
            signature_algorithm: "ed25519".to_string(),
        },
        issuer,
    )
    .unwrap()
}

fn revoked(serial: &str) -> SnapshotRevocation {
    SnapshotRevocation {
        certificate_serial: serial.to_string(),
        revoked_at: 950,
        reason_code: RevocationReasonCode::KeyCompromise,
    }
}

fn verified_trust(verifier: &SnapshotVerifier<'_>, snapshot: &TrustSnapshot) -> VerifiedTrust {
    verifier.verify_trust(&json(snapshot), None, NOW).unwrap()
}

fn tamper_signature(signature: &mut String) {
    let replacement = if signature.starts_with('A') { "B" } else { "A" };
    signature.replace_range(0..1, replacement);
}

fn json<T: serde::Serialize>(value: &T) -> Vec<u8> {
    serde_json::to_vec(value).unwrap()
}

#[test]
fn verifies_root_signed_trust_and_reports_metadata() {
    let root = key(1);
    let issuer = key(2);
    let snapshot = issue_trust(&root, &issuer, 1, IssuerStatus::Active);
    let roots = [root.verifying_key().to_bytes()];
    let verified = SnapshotVerifier::new(&roots)
        .verify_trust(&json(&snapshot), None, NOW)
        .unwrap();

    assert_eq!(verified.snapshot(), &snapshot);
    assert_eq!(verified.metadata().snapshot_version, 1);
    assert_eq!(verified.metadata().generated_at, 901);
    assert_eq!(verified.metadata().expires_at, 1_901);
}

#[test]
fn rejects_unknown_root_and_tampered_root_signature() {
    let root = key(1);
    let other_root = key(3);
    let issuer = key(2);
    let snapshot = issue_trust(&root, &issuer, 1, IssuerStatus::Active);
    let roots = [other_root.verifying_key().to_bytes()];
    assert_eq!(
        SnapshotVerifier::new(&roots).verify_trust(&json(&snapshot), None, NOW),
        Err(ApplyError::InvalidSignature)
    );

    let mut tampered = snapshot;
    tamper_signature(&mut tampered.root_signature);
    let roots = [root.verifying_key().to_bytes()];
    assert_eq!(
        SnapshotVerifier::new(&roots).verify_trust(&json(&tampered), None, NOW),
        Err(ApplyError::InvalidSignature)
    );
}

#[test]
fn rejects_expired_and_future_trust_snapshots() {
    let root = key(1);
    let issuer = key(2);
    let snapshot = issue_trust(&root, &issuer, 1, IssuerStatus::Active);
    let roots = [root.verifying_key().to_bytes()];
    let verifier = SnapshotVerifier::new(&roots);

    assert_eq!(
        verifier.verify_trust(&json(&snapshot), None, 1_901),
        Err(ApplyError::Expired)
    );
    assert_eq!(
        verifier.verify_trust(&json(&snapshot), None, 500),
        Err(ApplyError::Expired)
    );
}

#[test]
fn stored_expired_snapshots_remain_cryptographically_loadable() {
    let root = key(1);
    let issuer = key(2);
    let trust = issue_trust(&root, &issuer, 1, IssuerStatus::Active);
    let revocations = revocations(&issuer, 1, vec![]);
    let roots = [root.verifying_key().to_bytes()];
    let verifier = SnapshotVerifier::new(&roots);

    let stored_trust = verifier.verify_stored_trust(&json(&trust)).unwrap();
    assert!(
        verifier
            .verify_stored_revocations(&json(&revocations), &stored_trust)
            .is_ok()
    );
    assert_eq!(
        verifier.verify_trust(&json(&trust), None, trust.content.expires_at),
        Err(ApplyError::Expired)
    );
    assert_eq!(
        verifier.verify_revocations(
            &json(&revocations),
            &stored_trust,
            None,
            revocations.content.expires_at,
        ),
        Err(ApplyError::Expired)
    );

    let mut tampered = trust;
    tamper_signature(&mut tampered.root_signature);
    assert_eq!(
        verifier.verify_stored_trust(&json(&tampered)),
        Err(ApplyError::InvalidSignature)
    );
}

#[test]
fn rejects_unknown_json_fields_and_oversized_bodies() {
    let root = key(1);
    let issuer = key(2);
    let snapshot = issue_trust(&root, &issuer, 1, IssuerStatus::Active);
    let mut value = serde_json::to_value(snapshot).unwrap();
    value
        .as_object_mut()
        .unwrap()
        .insert("unexpected".to_string(), serde_json::Value::Bool(true));
    let roots = [root.verifying_key().to_bytes()];
    let verifier = SnapshotVerifier::new(&roots);
    assert_eq!(
        verifier.verify_trust(&json(&value), None, NOW),
        Err(ApplyError::InvalidSnapshot)
    );
    assert_eq!(
        verifier.verify_trust(&vec![0; 4 * 1024 * 1024 + 1], None, NOW),
        Err(ApplyError::InvalidSnapshot)
    );
}

#[test]
fn rejects_invalid_trust_format_lifetime_and_issuer_sets() {
    let root = key(1);
    let issuer = key(2);
    let roots = [root.verifying_key().to_bytes()];
    let verifier = SnapshotVerifier::new(&roots);
    let snapshot = issue_trust(&root, &issuer, 1, IssuerStatus::Active);

    let mut invalid_format = snapshot.clone();
    invalid_format.content.format_version = 2;
    let mut zero_version = snapshot.clone();
    zero_version.content.snapshot_version = 0;
    let mut invalid_algorithm = snapshot.clone();
    invalid_algorithm.content.signature_algorithm = "rsa".to_string();
    let mut excessive_lifetime = snapshot.clone();
    excessive_lifetime.content.expires_at =
        excessive_lifetime.content.generated_at + 180 * 24 * 60 * 60 + 1;
    let mut duplicate_issuer = snapshot.clone();
    duplicate_issuer
        .content
        .issuers
        .push(duplicate_issuer.content.issuers[0].clone());
    let mut multiple_active = snapshot.clone();
    multiple_active
        .content
        .issuers
        .push(issuer_record(&key(3), IssuerStatus::Active));
    multiple_active
        .content
        .issuers
        .sort_by(|left, right| left.issuer_key_id.cmp(&right.issuer_key_id));
    let mut replaced_public_key = snapshot.clone();
    replaced_public_key.content.issuers[0].public_key =
        STANDARD.encode(key(3).verifying_key().to_bytes());

    for invalid in [
        invalid_format,
        zero_version,
        invalid_algorithm,
        excessive_lifetime,
        duplicate_issuer,
        multiple_active,
        replaced_public_key,
    ] {
        assert_eq!(
            verifier.verify_trust(&json(&invalid), None, NOW),
            Err(ApplyError::InvalidSnapshot)
        );
    }
}

#[test]
fn rejects_trust_version_generated_time_issuer_and_status_rollback() {
    let root = key(1);
    let issuer = key(2);
    let current = issue_trust(&root, &issuer, 2, IssuerStatus::Active);
    let roots = [root.verifying_key().to_bytes()];
    let verifier = SnapshotVerifier::new(&roots);

    let generated_at_rollback = TrustSnapshot::issue(
        UnsignedTrustSnapshot {
            generated_at: current.content.generated_at - 1,
            snapshot_version: 3,
            expires_at: current.content.expires_at + 1,
            ..current.content.clone()
        },
        &root,
    )
    .unwrap();
    for next in [
        issue_trust(&root, &issuer, 2, IssuerStatus::Active),
        generated_at_rollback,
        issue_trust(&root, &issuer, 3, IssuerStatus::Future),
    ] {
        assert_eq!(
            verifier.verify_trust(&json(&next), Some(&current), NOW),
            Err(ApplyError::Rollback)
        );
    }

    let omitted = TrustSnapshot::issue(
        UnsignedTrustSnapshot {
            format_version: 1,
            snapshot_version: 3,
            generated_at: 903,
            expires_at: 1_903,
            root_key_id: key_id(&root.verifying_key().to_bytes()),
            issuers: vec![],
            signature_algorithm: "ed25519".to_string(),
        },
        &root,
    )
    .unwrap();
    assert_eq!(
        verifier.verify_trust(&json(&omitted), Some(&current), NOW),
        Err(ApplyError::Rollback)
    );
}

#[test]
fn verifies_revocations_with_current_authorized_issuer() {
    let root = key(1);
    let issuer = key(2);
    let trust = issue_trust(&root, &issuer, 1, IssuerStatus::Active);
    let snapshot = revocations(&issuer, 1, vec![revoked("10")]);
    let roots = [root.verifying_key().to_bytes()];
    let verifier = SnapshotVerifier::new(&roots);
    let trust = verified_trust(&verifier, &trust);
    let verified = verifier
        .verify_revocations(&json(&snapshot), &trust, None, NOW)
        .unwrap();

    assert_eq!(verified.snapshot(), &snapshot);
    assert_eq!(verified.metadata().snapshot_version, 1);
}

#[test]
fn retired_issuer_may_verify_but_future_revoked_and_unauthorized_issuers_may_not() {
    let root = key(1);
    let issuer = key(2);
    let snapshot = revocations(&issuer, 1, vec![]);
    let roots = [root.verifying_key().to_bytes()];
    let verifier = SnapshotVerifier::new(&roots);

    let retired = verified_trust(
        &verifier,
        &issue_trust(&root, &issuer, 1, IssuerStatus::Retired),
    );
    assert!(
        verifier
            .verify_revocations(&json(&snapshot), &retired, None, NOW)
            .is_ok()
    );
    for status in [IssuerStatus::Future, IssuerStatus::Revoked] {
        let denied = verified_trust(&verifier, &issue_trust(&root, &issuer, 1, status));
        assert_eq!(
            verifier.verify_revocations(&json(&snapshot), &denied, None, NOW),
            Err(ApplyError::UnknownIssuer)
        );
    }

    let unauthorized = TrustSnapshot::issue(
        UnsignedTrustSnapshot {
            format_version: 1,
            snapshot_version: 1,
            generated_at: 901,
            expires_at: 1_901,
            root_key_id: key_id(&root.verifying_key().to_bytes()),
            issuers: vec![IssuerRecord {
                allowed_key_usages: vec!["developer-certificate-signing".to_string()],
                ..issuer_record(&issuer, IssuerStatus::Active)
            }],
            signature_algorithm: "ed25519".to_string(),
        },
        &root,
    )
    .unwrap();
    let unauthorized = verified_trust(&verifier, &unauthorized);
    assert_eq!(
        verifier.verify_revocations(&json(&snapshot), &unauthorized, None, NOW),
        Err(ApplyError::UnknownIssuer)
    );
}

#[test]
fn rejects_unknown_revocation_issuer_and_bad_signature() {
    let root = key(1);
    let issuer = key(2);
    let other = key(3);
    let trust = issue_trust(&root, &issuer, 1, IssuerStatus::Active);
    let unknown = revocations(&other, 1, vec![]);
    let roots = [root.verifying_key().to_bytes()];
    let verifier = SnapshotVerifier::new(&roots);
    let trust = verified_trust(&verifier, &trust);
    assert_eq!(
        verifier.verify_revocations(&json(&unknown), &trust, None, NOW),
        Err(ApplyError::UnknownIssuer)
    );

    let mut tampered = revocations(&issuer, 1, vec![]);
    tamper_signature(&mut tampered.signature);
    assert_eq!(
        verifier.verify_revocations(&json(&tampered), &trust, None, NOW),
        Err(ApplyError::InvalidSignature)
    );
}

#[test]
fn rejects_expired_issuer_and_revocation_snapshot() {
    let root = key(1);
    let issuer = key(2);
    let mut trust = issue_trust(&root, &issuer, 1, IssuerStatus::Active);
    let snapshot = revocations(&issuer, 1, vec![]);
    let roots = [root.verifying_key().to_bytes()];
    let verifier = SnapshotVerifier::new(&roots);

    trust.content.issuers[0].not_after = NOW;
    let trust = TrustSnapshot::issue(trust.content, &root).unwrap();
    let trust = verified_trust(&verifier, &trust);
    assert_eq!(
        verifier.verify_revocations(&json(&snapshot), &trust, None, NOW),
        Err(ApplyError::UnknownIssuer)
    );
    let trust = verified_trust(
        &verifier,
        &issue_trust(&root, &issuer, 1, IssuerStatus::Active),
    );
    assert_eq!(
        verifier.verify_revocations(&json(&snapshot), &trust, None, 1_101),
        Err(ApplyError::Expired)
    );
}

#[test]
fn rejects_invalid_revocation_format_lifetime_and_duplicate_serials() {
    let root = key(1);
    let issuer = key(2);
    let trust = issue_trust(&root, &issuer, 1, IssuerStatus::Active);
    let roots = [root.verifying_key().to_bytes()];
    let verifier = SnapshotVerifier::new(&roots);
    let trust = verified_trust(&verifier, &trust);
    let snapshot = revocations(&issuer, 1, vec![revoked("10")]);

    let mut invalid_format = snapshot.clone();
    invalid_format.content.format_version = 2;
    let mut zero_version = snapshot.clone();
    zero_version.content.snapshot_version = 0;
    let mut invalid_algorithm = snapshot.clone();
    invalid_algorithm.content.signature_algorithm = "rsa".to_string();
    let mut excessive_lifetime = snapshot.clone();
    excessive_lifetime.content.expires_at =
        excessive_lifetime.content.generated_at + 7 * 24 * 60 * 60 + 1;
    let mut duplicate_serial = snapshot.clone();
    duplicate_serial
        .content
        .revocations
        .push(duplicate_serial.content.revocations[0].clone());

    for invalid in [
        invalid_format,
        zero_version,
        invalid_algorithm,
        excessive_lifetime,
        duplicate_serial,
    ] {
        assert_eq!(
            verifier.verify_revocations(&json(&invalid), &trust, None, NOW),
            Err(ApplyError::InvalidSnapshot)
        );
    }
}

#[test]
fn rejects_revocation_rollback_missing_and_conflicting_records() {
    let root = key(1);
    let issuer = key(2);
    let trust = issue_trust(&root, &issuer, 1, IssuerStatus::Active);
    let current = revocations(&issuer, 2, vec![revoked("10")]);
    let roots = [root.verifying_key().to_bytes()];
    let verifier = SnapshotVerifier::new(&roots);
    let trust = verified_trust(&verifier, &trust);

    let same_version = revocations(&issuer, 2, vec![revoked("10")]);
    let missing = revocations(&issuer, 3, vec![]);
    let mut changed = revoked("10");
    changed.reason_code = RevocationReasonCode::Administrative;
    let conflicting = revocations(&issuer, 3, vec![changed]);
    let mut changed_time = revoked("10");
    changed_time.revoked_at += 1;
    let conflicting_time = revocations(&issuer, 3, vec![changed_time]);
    for next in [same_version, missing, conflicting, conflicting_time] {
        assert_eq!(
            verifier.verify_revocations(&json(&next), &trust, Some(&current), NOW),
            Err(ApplyError::Rollback)
        );
    }
}
