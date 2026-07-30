use mochios_developer_ca_trust::{
    IssuerRecord, IssuerStatus, MAX_SNAPSHOT_BYTES, RevocationSnapshot, TrustError, TrustSnapshot,
    decode_public_key, key_id, validate_revocation_successor, validate_trust_successor,
};

use crate::coordinator::ApplyError;

const REVOCATION_SIGNING_USAGE: &str = "revocation-signing";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SnapshotProperties {
    pub snapshot_version: u64,
    pub generated_at: u64,
    pub expires_at: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedTrust {
    snapshot: TrustSnapshot,
}

impl VerifiedTrust {
    pub const fn snapshot(&self) -> &TrustSnapshot {
        &self.snapshot
    }

    pub fn metadata(&self) -> SnapshotProperties {
        SnapshotProperties {
            snapshot_version: self.snapshot.content.snapshot_version,
            generated_at: self.snapshot.content.generated_at,
            expires_at: self.snapshot.content.expires_at,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedRevocations {
    snapshot: RevocationSnapshot,
}

impl VerifiedRevocations {
    pub const fn snapshot(&self) -> &RevocationSnapshot {
        &self.snapshot
    }

    pub fn metadata(&self) -> SnapshotProperties {
        SnapshotProperties {
            snapshot_version: self.snapshot.content.snapshot_version,
            generated_at: self.snapshot.content.generated_at,
            expires_at: self.snapshot.content.expires_at,
        }
    }
}

#[derive(Clone, Copy)]
pub struct SnapshotVerifier<'a> {
    root_public_keys: &'a [[u8; 32]],
}

impl<'a> SnapshotVerifier<'a> {
    pub const fn new(root_public_keys: &'a [[u8; 32]]) -> Self {
        Self { root_public_keys }
    }

    pub fn verify_trust(
        &self,
        bytes: &[u8],
        current: Option<&TrustSnapshot>,
        now_utc: u64,
    ) -> Result<VerifiedTrust, ApplyError> {
        check_size(bytes)?;
        let snapshot: TrustSnapshot =
            serde_json::from_slice(bytes).map_err(|_| ApplyError::InvalidSnapshot)?;
        let root = self
            .root_public_keys
            .iter()
            .find(|public_key| key_id(public_key) == snapshot.content.root_key_id)
            .ok_or(ApplyError::InvalidSignature)?;
        snapshot.verify(root, now_utc).map_err(map_trust_error)?;
        if let Some(current) = current {
            validate_trust_successor(current, &snapshot).map_err(map_trust_error)?;
        }
        Ok(VerifiedTrust { snapshot })
    }

    pub fn verify_revocations(
        &self,
        bytes: &[u8],
        trust: &VerifiedTrust,
        current: Option<&RevocationSnapshot>,
        now_utc: u64,
    ) -> Result<VerifiedRevocations, ApplyError> {
        check_size(bytes)?;
        let snapshot: RevocationSnapshot =
            serde_json::from_slice(bytes).map_err(|_| ApplyError::InvalidSnapshot)?;
        let issuer = trust
            .snapshot
            .content
            .issuers
            .iter()
            .find(|issuer| issuer.issuer_key_id == snapshot.content.issuer_key_id)
            .ok_or(ApplyError::UnknownIssuer)?;
        validate_revocation_issuer(issuer, now_utc)?;
        let public_key = decode_public_key(&issuer.public_key).map_err(map_trust_error)?;
        snapshot
            .verify(&public_key, now_utc)
            .map_err(map_trust_error)?;
        if let Some(current) = current {
            validate_revocation_successor(current, &snapshot).map_err(map_trust_error)?;
        }
        Ok(VerifiedRevocations { snapshot })
    }
}

fn check_size(bytes: &[u8]) -> Result<(), ApplyError> {
    if bytes.len() > MAX_SNAPSHOT_BYTES {
        Err(ApplyError::InvalidSnapshot)
    } else {
        Ok(())
    }
}

fn validate_revocation_issuer(issuer: &IssuerRecord, now_utc: u64) -> Result<(), ApplyError> {
    if !matches!(issuer.status, IssuerStatus::Active | IssuerStatus::Retired)
        || now_utc < issuer.not_before
        || now_utc >= issuer.not_after
        || !issuer
            .allowed_key_usages
            .iter()
            .any(|usage| usage == REVOCATION_SIGNING_USAGE)
    {
        return Err(ApplyError::UnknownIssuer);
    }
    Ok(())
}

fn map_trust_error(error: TrustError) -> ApplyError {
    match error {
        TrustError::InvalidSignature => ApplyError::InvalidSignature,
        TrustError::SnapshotRollback
        | TrustError::MissingIssuer
        | TrustError::PublicKeyReplacement
        | TrustError::InvalidStatusTransition
        | TrustError::MissingRevocation
        | TrustError::ConflictingRevocation => ApplyError::Rollback,
        TrustError::InvalidValidity => ApplyError::Expired,
        TrustError::UnsupportedFormat
        | TrustError::UnsupportedSignatureAlgorithm
        | TrustError::InvalidVersion
        | TrustError::LifetimeTooLong
        | TrustError::TooManyIssuers
        | TrustError::TooManyRevocations
        | TrustError::InvalidKeyId
        | TrustError::InvalidPublicKey
        | TrustError::KeyIdMismatch
        | TrustError::InvalidKeyUsage
        | TrustError::DuplicateIssuer
        | TrustError::UnsortedIssuers
        | TrustError::MultipleActiveIssuers
        | TrustError::InvalidSerial
        | TrustError::InvalidReasonCode
        | TrustError::DuplicateRevocation
        | TrustError::UnsortedRevocations
        | TrustError::SnapshotTooLarge
        | TrustError::EncodingOverflow => ApplyError::InvalidSnapshot,
    }
}
