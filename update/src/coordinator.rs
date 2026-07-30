use alloc::string::ToString;

use crate::http::{FetchError, Response};
use crate::scheduler::{FailureClass, Scheduler, SnapshotKind};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SnapshotTimes {
    pub generated_at: u64,
    pub expires_at: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApplyError {
    InvalidSignature,
    Rollback,
    Expired,
    InvalidSnapshot,
    UnknownIssuer,
    Storage,
}

pub trait SnapshotRepository {
    fn etag(&self, kind: SnapshotKind) -> &str;

    fn apply(
        &mut self,
        kind: SnapshotKind,
        body: &[u8],
        etag: &str,
        now_utc: u64,
    ) -> Result<SnapshotTimes, ApplyError>;

    fn mark_checked(
        &mut self,
        kind: SnapshotKind,
        now_utc: u64,
    ) -> Result<SnapshotTimes, ApplyError>;
}

pub trait SnapshotFetcher {
    fn fetch(
        &mut self,
        kind: SnapshotKind,
        request_id: u64,
        if_none_match: &str,
    ) -> Result<Response, FetchError>;
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Statistics {
    pub trust_sync_attempts: u64,
    pub trust_sync_updated: u64,
    pub trust_sync_not_modified: u64,
    pub trust_sync_failures: u64,
    pub revocation_sync_attempts: u64,
    pub revocation_sync_updated: u64,
    pub revocation_sync_not_modified: u64,
    pub revocation_sync_failures: u64,
    pub snapshot_signature_failures: u64,
    pub snapshot_rollback_rejections: u64,
    pub snapshot_expiration_failures: u64,
    pub snapshot_storage_failures: u64,
    pub snapshot_recovery_count: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SyncResult {
    Never,
    Updated(SnapshotKind),
    NotModified(SnapshotKind),
    RetryScheduled(SnapshotKind),
    Rejected(SnapshotKind, ApplyError),
}

pub struct Coordinator {
    scheduler: Scheduler,
    statistics: Statistics,
    request_id: u64,
    last_result: SyncResult,
}

impl Coordinator {
    pub const fn network_ready(now_ms: u64) -> Self {
        Self {
            scheduler: Scheduler::network_ready(now_ms),
            statistics: Statistics {
                trust_sync_attempts: 0,
                trust_sync_updated: 0,
                trust_sync_not_modified: 0,
                trust_sync_failures: 0,
                revocation_sync_attempts: 0,
                revocation_sync_updated: 0,
                revocation_sync_not_modified: 0,
                revocation_sync_failures: 0,
                snapshot_signature_failures: 0,
                snapshot_rollback_rejections: 0,
                snapshot_expiration_failures: 0,
                snapshot_storage_failures: 0,
                snapshot_recovery_count: 0,
            },
            request_id: 0,
            last_result: SyncResult::Never,
        }
    }

    pub const fn scheduler(&self) -> &Scheduler {
        &self.scheduler
    }

    pub const fn statistics(&self) -> &Statistics {
        &self.statistics
    }

    pub const fn last_result(&self) -> SyncResult {
        self.last_result
    }

    pub fn record_recovery(&mut self) {
        self.statistics.snapshot_recovery_count =
            self.statistics.snapshot_recovery_count.saturating_add(1);
    }

    pub fn synchronize_due<F: SnapshotFetcher, R: SnapshotRepository>(
        &mut self,
        fetcher: &mut F,
        repository: &mut R,
        now_ms: u64,
        now_utc: u64,
    ) {
        if self.scheduler.is_due(SnapshotKind::Trust, now_ms) {
            let _ = self.synchronize_one(
                fetcher,
                repository,
                SnapshotKind::Trust,
                now_ms,
                now_utc,
                false,
            );
        }
        if self.scheduler.is_due(SnapshotKind::Revocations, now_ms)
            && self.synchronize_one(
                fetcher,
                repository,
                SnapshotKind::Revocations,
                now_ms,
                now_utc,
                true,
            ) == OneResult::UnknownIssuer
        {
            let _ = self.synchronize_one(
                fetcher,
                repository,
                SnapshotKind::Trust,
                now_ms,
                now_utc,
                false,
            );
            let _ = self.synchronize_one(
                fetcher,
                repository,
                SnapshotKind::Revocations,
                now_ms,
                now_utc,
                false,
            );
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn synchronize_one<F: SnapshotFetcher, R: SnapshotRepository>(
        &mut self,
        fetcher: &mut F,
        repository: &mut R,
        kind: SnapshotKind,
        now_ms: u64,
        now_utc: u64,
        defer_unknown_issuer: bool,
    ) -> OneResult {
        self.increment_attempt(kind);
        let request_id = self.next_request_id();
        let etag = repository.etag(kind).to_string();
        let response = match fetcher.fetch(kind, request_id, &etag) {
            Ok(response) => response,
            Err(_) => {
                self.retry(kind, now_ms, None);
                return OneResult::Finished;
            }
        };
        match response.status_code {
            200 => {
                let Some(etag) = response.etag.as_deref() else {
                    self.retry(kind, now_ms, None);
                    return OneResult::Finished;
                };
                match repository.apply(kind, &response.body, etag, now_utc) {
                    Ok(times) => {
                        self.increment_updated(kind);
                        self.scheduler.record_success(
                            kind,
                            now_ms,
                            now_utc,
                            times.generated_at,
                            times.expires_at,
                        );
                        self.last_result = SyncResult::Updated(kind);
                    }
                    Err(ApplyError::UnknownIssuer) if defer_unknown_issuer => {
                        return OneResult::UnknownIssuer;
                    }
                    Err(ApplyError::Storage) => {
                        self.statistics.snapshot_storage_failures =
                            self.statistics.snapshot_storage_failures.saturating_add(1);
                        self.retry(kind, now_ms, None);
                    }
                    Err(error) => self.reject(kind, error, now_ms),
                }
            }
            304 => match repository.mark_checked(kind, now_utc) {
                Ok(times) => {
                    self.increment_not_modified(kind);
                    self.scheduler.record_success(
                        kind,
                        now_ms,
                        now_utc,
                        times.generated_at,
                        times.expires_at,
                    );
                    self.last_result = SyncResult::NotModified(kind);
                }
                Err(ApplyError::Storage) => {
                    self.statistics.snapshot_storage_failures =
                        self.statistics.snapshot_storage_failures.saturating_add(1);
                    self.retry(kind, now_ms, None);
                }
                Err(error) => self.reject(kind, error, now_ms),
            },
            429 | 500 | 502 | 503 | 504 => self.retry(kind, now_ms, response.retry_after_seconds),
            _ => self.reject(kind, ApplyError::InvalidSnapshot, now_ms),
        }
        OneResult::Finished
    }

    fn next_request_id(&mut self) -> u64 {
        self.request_id = self.request_id.wrapping_add(1);
        if self.request_id == 0 {
            self.request_id = 1;
        }
        self.request_id
    }

    fn retry(&mut self, kind: SnapshotKind, now_ms: u64, retry_after_seconds: Option<u64>) {
        self.increment_failure(kind);
        self.scheduler.record_failure(
            kind,
            now_ms,
            FailureClass::Transient {
                retry_after_seconds,
            },
        );
        self.last_result = SyncResult::RetryScheduled(kind);
    }

    fn reject(&mut self, kind: SnapshotKind, error: ApplyError, now_ms: u64) {
        self.increment_failure(kind);
        match error {
            ApplyError::InvalidSignature => {
                self.statistics.snapshot_signature_failures = self
                    .statistics
                    .snapshot_signature_failures
                    .saturating_add(1);
            }
            ApplyError::Rollback => {
                self.statistics.snapshot_rollback_rejections = self
                    .statistics
                    .snapshot_rollback_rejections
                    .saturating_add(1);
            }
            ApplyError::Expired => {
                self.statistics.snapshot_expiration_failures = self
                    .statistics
                    .snapshot_expiration_failures
                    .saturating_add(1);
            }
            ApplyError::InvalidSnapshot | ApplyError::UnknownIssuer | ApplyError::Storage => {}
        }
        self.scheduler
            .record_failure(kind, now_ms, FailureClass::Security);
        self.last_result = SyncResult::Rejected(kind, error);
    }

    fn increment_attempt(&mut self, kind: SnapshotKind) {
        match kind {
            SnapshotKind::Trust => {
                self.statistics.trust_sync_attempts =
                    self.statistics.trust_sync_attempts.saturating_add(1)
            }
            SnapshotKind::Revocations => {
                self.statistics.revocation_sync_attempts =
                    self.statistics.revocation_sync_attempts.saturating_add(1)
            }
        }
    }

    fn increment_updated(&mut self, kind: SnapshotKind) {
        match kind {
            SnapshotKind::Trust => {
                self.statistics.trust_sync_updated =
                    self.statistics.trust_sync_updated.saturating_add(1)
            }
            SnapshotKind::Revocations => {
                self.statistics.revocation_sync_updated =
                    self.statistics.revocation_sync_updated.saturating_add(1)
            }
        }
    }

    fn increment_not_modified(&mut self, kind: SnapshotKind) {
        match kind {
            SnapshotKind::Trust => {
                self.statistics.trust_sync_not_modified =
                    self.statistics.trust_sync_not_modified.saturating_add(1)
            }
            SnapshotKind::Revocations => {
                self.statistics.revocation_sync_not_modified = self
                    .statistics
                    .revocation_sync_not_modified
                    .saturating_add(1)
            }
        }
    }

    fn increment_failure(&mut self, kind: SnapshotKind) {
        match kind {
            SnapshotKind::Trust => {
                self.statistics.trust_sync_failures =
                    self.statistics.trust_sync_failures.saturating_add(1)
            }
            SnapshotKind::Revocations => {
                self.statistics.revocation_sync_failures =
                    self.statistics.revocation_sync_failures.saturating_add(1)
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum OneResult {
    Finished,
    UnknownIssuer,
}
