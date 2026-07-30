use mochios_certificate_database::storage::{
    LoadedDatabase, SnapshotKind as StorageKind, SnapshotValidator, StorageBackend, StorageError,
    ValidatedSnapshot, load_database, mark_checked, persist_snapshot,
};
use mochios_certificate_database::{DatabaseState, Etag, SnapshotMetadata};

use crate::coordinator::{ApplyError, SnapshotRepository, SnapshotTimes};
use crate::scheduler::SnapshotKind;
use crate::snapshot::{SnapshotProperties, SnapshotVerifier, VerifiedRevocations, VerifiedTrust};

pub struct CertificateRepository<'a, B> {
    backend: B,
    verifier: SnapshotVerifier<'a>,
    state: DatabaseState,
    trust: Option<VerifiedTrust>,
    revocations: Option<VerifiedRevocations>,
    recovered: bool,
}

impl<'a, B: StorageBackend> CertificateRepository<'a, B> {
    pub fn load(
        mut backend: B,
        root_public_keys: &'a [[u8; 32]],
        now_utc: u64,
    ) -> Result<Self, StorageError> {
        let verifier = SnapshotVerifier::new(root_public_keys);
        let mut recovery = RecoveryValidator::new(verifier, now_utc);
        let LoadedDatabase {
            state, recovered, ..
        } = load_database(&mut backend, &mut recovery)?;
        Ok(Self {
            backend,
            verifier,
            state,
            trust: recovery.trust,
            revocations: recovery.revocations,
            recovered,
        })
    }

    pub const fn state(&self) -> &DatabaseState {
        &self.state
    }

    pub const fn trust(&self) -> Option<&VerifiedTrust> {
        self.trust.as_ref()
    }

    pub const fn revocations(&self) -> Option<&VerifiedRevocations> {
        self.revocations.as_ref()
    }

    pub const fn recovered(&self) -> bool {
        self.recovered
    }

    pub fn into_backend(self) -> B {
        self.backend
    }

    fn apply_trust(
        &mut self,
        body: &[u8],
        etag: Etag,
        now_utc: u64,
    ) -> Result<SnapshotTimes, ApplyError> {
        let verified = self.verifier.verify_trust(
            body,
            self.trust.as_ref().map(VerifiedTrust::snapshot),
            now_utc,
        )?;
        let mut validator = ApplyValidator {
            verifier: self.verifier,
            now_utc,
            trust: self.trust.as_ref(),
            revocations: self.revocations.as_ref(),
        };
        persist_snapshot(
            &mut self.backend,
            &mut validator,
            &mut self.state,
            StorageKind::Trust,
            body,
            etag,
            now_utc,
        )
        .map_err(|_| ApplyError::Storage)?;
        let times = times(verified.metadata());
        self.trust = Some(verified);
        Ok(times)
    }

    fn apply_revocations(
        &mut self,
        body: &[u8],
        etag: Etag,
        now_utc: u64,
    ) -> Result<SnapshotTimes, ApplyError> {
        let trust = self.trust.as_ref().ok_or(ApplyError::UnknownIssuer)?;
        let verified = self.verifier.verify_revocations(
            body,
            trust,
            self.revocations.as_ref().map(VerifiedRevocations::snapshot),
            now_utc,
        )?;
        let mut validator = ApplyValidator {
            verifier: self.verifier,
            now_utc,
            trust: self.trust.as_ref(),
            revocations: self.revocations.as_ref(),
        };
        persist_snapshot(
            &mut self.backend,
            &mut validator,
            &mut self.state,
            StorageKind::Revocations,
            body,
            etag,
            now_utc,
        )
        .map_err(|_| ApplyError::Storage)?;
        let times = times(verified.metadata());
        self.revocations = Some(verified);
        Ok(times)
    }
}

impl<B: StorageBackend> SnapshotRepository for CertificateRepository<'_, B> {
    fn etag(&self, kind: SnapshotKind) -> &str {
        metadata(&self.state, kind).etag.as_str()
    }

    fn apply(
        &mut self,
        kind: SnapshotKind,
        body: &[u8],
        etag: &str,
        now_utc: u64,
    ) -> Result<SnapshotTimes, ApplyError> {
        let etag = Etag::parse(etag).map_err(|_| ApplyError::InvalidSnapshot)?;
        match kind {
            SnapshotKind::Trust => self.apply_trust(body, etag, now_utc),
            SnapshotKind::Revocations => self.apply_revocations(body, etag, now_utc),
        }
    }

    fn mark_checked(
        &mut self,
        kind: SnapshotKind,
        now_utc: u64,
    ) -> Result<SnapshotTimes, ApplyError> {
        let storage_kind = storage_kind(kind);
        mark_checked(&mut self.backend, &mut self.state, storage_kind, now_utc)
            .map_err(|_| ApplyError::Storage)?;
        let current = metadata(&self.state, kind);
        Ok(SnapshotTimes {
            generated_at: current.generated_at,
            expires_at: current.expires_at,
        })
    }
}

struct RecoveryValidator<'a> {
    verifier: SnapshotVerifier<'a>,
    now_utc: u64,
    trust: Option<VerifiedTrust>,
    revocations: Option<VerifiedRevocations>,
}

impl<'a> RecoveryValidator<'a> {
    const fn new(verifier: SnapshotVerifier<'a>, now_utc: u64) -> Self {
        Self {
            verifier,
            now_utc,
            trust: None,
            revocations: None,
        }
    }
}

impl SnapshotValidator for RecoveryValidator<'_> {
    fn validate(
        &mut self,
        kind: StorageKind,
        bytes: &[u8],
    ) -> Result<ValidatedSnapshot, StorageError> {
        match kind {
            StorageKind::Trust => self
                .verifier
                .verify_trust(bytes, None, self.now_utc)
                .map(|verified| storage_metadata(verified.metadata()))
                .map_err(|_| StorageError::InvalidSnapshot),
            StorageKind::Revocations => self
                .trust
                .as_ref()
                .ok_or(StorageError::InvalidSnapshot)
                .and_then(|trust| {
                    self.verifier
                        .verify_revocations(bytes, trust, None, self.now_utc)
                        .map(|verified| storage_metadata(verified.metadata()))
                        .map_err(|_| StorageError::InvalidSnapshot)
                }),
        }
    }

    fn activate(&mut self, kind: StorageKind, bytes: &[u8]) -> Result<(), StorageError> {
        match kind {
            StorageKind::Trust => {
                self.trust = Some(
                    self.verifier
                        .verify_trust(bytes, None, self.now_utc)
                        .map_err(|_| StorageError::InvalidSnapshot)?,
                );
            }
            StorageKind::Revocations => {
                let trust = self.trust.as_ref().ok_or(StorageError::InvalidSnapshot)?;
                self.revocations = Some(
                    self.verifier
                        .verify_revocations(bytes, trust, None, self.now_utc)
                        .map_err(|_| StorageError::InvalidSnapshot)?,
                );
            }
        }
        Ok(())
    }
}

struct ApplyValidator<'roots, 'state> {
    verifier: SnapshotVerifier<'roots>,
    now_utc: u64,
    trust: Option<&'state VerifiedTrust>,
    revocations: Option<&'state VerifiedRevocations>,
}

impl SnapshotValidator for ApplyValidator<'_, '_> {
    fn validate(
        &mut self,
        kind: StorageKind,
        bytes: &[u8],
    ) -> Result<ValidatedSnapshot, StorageError> {
        match kind {
            StorageKind::Trust => self
                .verifier
                .verify_trust(bytes, self.trust.map(VerifiedTrust::snapshot), self.now_utc)
                .map(|verified| storage_metadata(verified.metadata()))
                .map_err(|_| StorageError::InvalidSnapshot),
            StorageKind::Revocations => {
                self.trust
                    .ok_or(StorageError::InvalidSnapshot)
                    .and_then(|trust| {
                        self.verifier
                            .verify_revocations(
                                bytes,
                                trust,
                                self.revocations.map(VerifiedRevocations::snapshot),
                                self.now_utc,
                            )
                            .map(|verified| storage_metadata(verified.metadata()))
                            .map_err(|_| StorageError::InvalidSnapshot)
                    })
            }
        }
    }
}

const fn storage_kind(kind: SnapshotKind) -> StorageKind {
    match kind {
        SnapshotKind::Trust => StorageKind::Trust,
        SnapshotKind::Revocations => StorageKind::Revocations,
    }
}

const fn metadata(state: &DatabaseState, kind: SnapshotKind) -> &SnapshotMetadata {
    match kind {
        SnapshotKind::Trust => &state.trust,
        SnapshotKind::Revocations => &state.revocations,
    }
}

const fn times(metadata: SnapshotProperties) -> SnapshotTimes {
    SnapshotTimes {
        generated_at: metadata.generated_at,
        expires_at: metadata.expires_at,
    }
}

const fn storage_metadata(metadata: SnapshotProperties) -> ValidatedSnapshot {
    ValidatedSnapshot {
        snapshot_version: metadata.snapshot_version,
        generated_at: metadata.generated_at,
        expires_at: metadata.expires_at,
    }
}
