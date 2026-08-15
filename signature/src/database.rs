use mochios_certificate::DeveloperCertificate;
use mochios_certificate_database::DatabaseState;
use mochios_certificate_database::std_file::FileBackend;
use mochios_certificate_database::storage::{
    SnapshotKind, SnapshotValidator, StorageBackend, StorageError, ValidatedSnapshot,
    load_database_read_only,
};
use mochios_developer_ca_trust::{
    IssuerRecord, IssuerStatus, RevocationSnapshot, TrustSnapshot, decode_public_key, key_id,
};

const CERTIFICATE_SIGNING_USAGE: &str = "developer-certificate-signing";
const REVOCATION_SIGNING_USAGE: &str = "revocation-signing";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DatabaseError {
    Storage,
    MissingTrust,
    MissingRevocations,
    InvalidTrust,
    InvalidRevocations,
    Expired,
    UnknownIssuer,
    Revoked,
}

pub struct ActiveDatabase {
    state: DatabaseState,
    trust: TrustSnapshot,
    revocations: RevocationSnapshot,
    recovered: bool,
}

impl ActiveDatabase {
    pub fn load(root_public_keys: &[[u8; 32]]) -> Result<Self, DatabaseError> {
        let backend = FileBackend::system_read_only();
        Self::load_from(backend, root_public_keys)
    }

    pub fn load_from<B: StorageBackend>(
        mut backend: B,
        root_public_keys: &[[u8; 32]],
    ) -> Result<Self, DatabaseError> {
        let mut validator = DatabaseValidator::new(root_public_keys);
        let loaded = load_database_read_only(&mut backend, &mut validator)
            .map_err(|_| DatabaseError::Storage)?;
        Ok(Self {
            state: loaded.state,
            trust: validator.trust.ok_or(DatabaseError::MissingTrust)?,
            revocations: validator
                .revocations
                .ok_or(DatabaseError::MissingRevocations)?,
            recovered: loaded.recovered,
        })
    }

    pub const fn state(&self) -> &DatabaseState {
        &self.state
    }

    pub const fn recovered(&self) -> bool {
        self.recovered
    }

    pub fn is_current(&self, now_utc: u64) -> bool {
        now_utc >= self.trust.content.generated_at
            && now_utc < self.trust.content.expires_at
            && now_utc >= self.revocations.content.generated_at
            && now_utc < self.revocations.content.expires_at
    }

    pub fn issuer_public_key(
        &self,
        certificate: &DeveloperCertificate,
        now_utc: u64,
    ) -> Result<[u8; 32], DatabaseError> {
        if !self.is_current(now_utc) {
            return Err(DatabaseError::Expired);
        }
        if self
            .revocations
            .content
            .revocations
            .iter()
            .any(|entry| entry.certificate_serial == certificate.serial_number.to_string())
        {
            return Err(DatabaseError::Revoked);
        }
        let issuer = self
            .trust
            .content
            .issuers
            .iter()
            .find(|issuer| issuer_matches_certificate(issuer, certificate))
            .ok_or(DatabaseError::UnknownIssuer)?;
        if !matches!(issuer.status, IssuerStatus::Active | IssuerStatus::Retired)
            || now_utc < issuer.not_before
            || now_utc >= issuer.not_after
            || !issuer
                .allowed_key_usages
                .iter()
                .any(|usage| usage == CERTIFICATE_SIGNING_USAGE)
        {
            return Err(DatabaseError::UnknownIssuer);
        }
        decode_public_key(&issuer.public_key).map_err(|_| DatabaseError::UnknownIssuer)
    }
}

struct DatabaseValidator<'a> {
    roots: &'a [[u8; 32]],
    trust: Option<TrustSnapshot>,
    revocations: Option<RevocationSnapshot>,
}

impl<'a> DatabaseValidator<'a> {
    const fn new(roots: &'a [[u8; 32]]) -> Self {
        Self {
            roots,
            trust: None,
            revocations: None,
        }
    }

    fn decode_trust(&self, bytes: &[u8]) -> Result<TrustSnapshot, DatabaseError> {
        let snapshot: TrustSnapshot =
            serde_json::from_slice(bytes).map_err(|_| DatabaseError::InvalidTrust)?;
        let root = self
            .roots
            .iter()
            .find(|root| key_id(root) == snapshot.content.root_key_id)
            .ok_or(DatabaseError::InvalidTrust)?;
        snapshot
            .verify(root, snapshot.content.generated_at)
            .map_err(|_| DatabaseError::InvalidTrust)?;
        Ok(snapshot)
    }

    fn decode_revocations(&self, bytes: &[u8]) -> Result<RevocationSnapshot, DatabaseError> {
        let trust = self
            .trust
            .as_ref()
            .ok_or(DatabaseError::InvalidRevocations)?;
        let snapshot: RevocationSnapshot =
            serde_json::from_slice(bytes).map_err(|_| DatabaseError::InvalidRevocations)?;
        let issuer = trust
            .content
            .issuers
            .iter()
            .find(|issuer| issuer.issuer_key_id == snapshot.content.issuer_key_id)
            .ok_or(DatabaseError::InvalidRevocations)?;
        if !matches!(issuer.status, IssuerStatus::Active | IssuerStatus::Retired)
            || snapshot.content.generated_at < issuer.not_before
            || snapshot.content.generated_at >= issuer.not_after
            || !issuer
                .allowed_key_usages
                .iter()
                .any(|usage| usage == REVOCATION_SIGNING_USAGE)
        {
            return Err(DatabaseError::InvalidRevocations);
        }
        let public_key =
            decode_public_key(&issuer.public_key).map_err(|_| DatabaseError::InvalidRevocations)?;
        snapshot
            .verify(&public_key, snapshot.content.generated_at)
            .map_err(|_| DatabaseError::InvalidRevocations)?;
        Ok(snapshot)
    }
}

impl SnapshotValidator for DatabaseValidator<'_> {
    fn validate(
        &mut self,
        kind: SnapshotKind,
        bytes: &[u8],
    ) -> Result<ValidatedSnapshot, StorageError> {
        match kind {
            SnapshotKind::Trust => self.decode_trust(bytes).map(|snapshot| {
                metadata(
                    snapshot.content.snapshot_version,
                    snapshot.content.generated_at,
                    snapshot.content.expires_at,
                )
            }),
            SnapshotKind::Revocations => self.decode_revocations(bytes).map(|snapshot| {
                metadata(
                    snapshot.content.snapshot_version,
                    snapshot.content.generated_at,
                    snapshot.content.expires_at,
                )
            }),
        }
        .map_err(|_| StorageError::InvalidSnapshot)
    }

    fn activate(&mut self, kind: SnapshotKind, bytes: &[u8]) -> Result<(), StorageError> {
        match kind {
            SnapshotKind::Trust => {
                self.trust = Some(
                    self.decode_trust(bytes)
                        .map_err(|_| StorageError::InvalidSnapshot)?,
                )
            }
            SnapshotKind::Revocations => {
                self.revocations = Some(
                    self.decode_revocations(bytes)
                        .map_err(|_| StorageError::InvalidSnapshot)?,
                )
            }
        }
        Ok(())
    }
}

const fn metadata(snapshot_version: u64, generated_at: u64, expires_at: u64) -> ValidatedSnapshot {
    ValidatedSnapshot {
        snapshot_version,
        generated_at,
        expires_at,
    }
}

fn issuer_matches_certificate(issuer: &IssuerRecord, certificate: &DeveloperCertificate) -> bool {
    decode_public_key(&issuer.public_key).is_ok_and(|public_key| {
        mochios_certificate::key_id(&public_key) == certificate.issuer_key_id
    })
}
