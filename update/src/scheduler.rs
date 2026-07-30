pub const TRUST_PERIOD_MS: u64 = 24 * 60 * 60 * 1_000;
pub const REVOCATION_PERIOD_MS: u64 = 6 * 60 * 60 * 1_000;
pub const MAX_RETRY_AFTER_SECONDS: u64 = 6 * 60 * 60;
pub const EXPIRY_REVALIDATION_MS: u64 = 60 * 1_000;
pub const RETRY_BACKOFF_MS: [u64; 5] = [
    60 * 1_000,
    5 * 60 * 1_000,
    15 * 60 * 1_000,
    60 * 60 * 1_000,
    6 * 60 * 60 * 1_000,
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SnapshotKind {
    Trust,
    Revocations,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FailureClass {
    Transient { retry_after_seconds: Option<u64> },
    Security,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Deadline {
    next_attempt_ms: u64,
    transient_failures: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Scheduler {
    trust: Deadline,
    revocations: Deadline,
}

impl Scheduler {
    pub const fn network_ready(now_ms: u64) -> Self {
        Self {
            trust: Deadline {
                next_attempt_ms: now_ms,
                transient_failures: 0,
            },
            revocations: Deadline {
                next_attempt_ms: now_ms,
                transient_failures: 0,
            },
        }
    }

    pub const fn next_attempt_ms(&self, kind: SnapshotKind) -> u64 {
        self.deadline(kind).next_attempt_ms
    }

    pub const fn is_due(&self, kind: SnapshotKind, now_ms: u64) -> bool {
        now_ms >= self.next_attempt_ms(kind)
    }

    pub fn record_success(
        &mut self,
        kind: SnapshotKind,
        now_ms: u64,
        now_utc: u64,
        generated_at: u64,
        expires_at: u64,
    ) {
        let period_deadline = now_ms.saturating_add(period_ms(kind));
        let expiry_deadline = refresh_before_expiry_ms(now_ms, now_utc, generated_at, expires_at);
        *self.deadline_mut(kind) = Deadline {
            next_attempt_ms: period_deadline.min(expiry_deadline),
            transient_failures: 0,
        };
    }

    pub fn record_not_modified(
        &mut self,
        kind: SnapshotKind,
        now_ms: u64,
        now_utc: u64,
        generated_at: u64,
        expires_at: u64,
    ) {
        self.record_success(kind, now_ms, now_utc, generated_at, expires_at);
        let deadline = self.deadline_mut(kind);
        if deadline.next_attempt_ms <= now_ms {
            let until_expiry_ms = expires_at.saturating_sub(now_utc).saturating_mul(1_000);
            deadline.next_attempt_ms =
                now_ms.saturating_add(EXPIRY_REVALIDATION_MS.min(until_expiry_ms).max(1));
        }
    }

    pub fn record_failure(&mut self, kind: SnapshotKind, now_ms: u64, failure: FailureClass) {
        match failure {
            FailureClass::Transient {
                retry_after_seconds,
            } => {
                let deadline = self.deadline_mut(kind);
                let index = deadline.transient_failures.min(RETRY_BACKOFF_MS.len() - 1);
                let mut delay = RETRY_BACKOFF_MS[index];
                if let Some(retry_after) = retry_after_seconds {
                    delay = delay.max(
                        retry_after
                            .min(MAX_RETRY_AFTER_SECONDS)
                            .saturating_mul(1_000),
                    );
                }
                deadline.next_attempt_ms = now_ms.saturating_add(delay);
                deadline.transient_failures = deadline.transient_failures.saturating_add(1);
            }
            FailureClass::Security => {
                *self.deadline_mut(kind) = Deadline {
                    next_attempt_ms: now_ms.saturating_add(period_ms(kind)),
                    transient_failures: 0,
                };
            }
        }
    }

    const fn deadline(&self, kind: SnapshotKind) -> &Deadline {
        match kind {
            SnapshotKind::Trust => &self.trust,
            SnapshotKind::Revocations => &self.revocations,
        }
    }

    fn deadline_mut(&mut self, kind: SnapshotKind) -> &mut Deadline {
        match kind {
            SnapshotKind::Trust => &mut self.trust,
            SnapshotKind::Revocations => &mut self.revocations,
        }
    }
}

const fn period_ms(kind: SnapshotKind) -> u64 {
    match kind {
        SnapshotKind::Trust => TRUST_PERIOD_MS,
        SnapshotKind::Revocations => REVOCATION_PERIOD_MS,
    }
}

fn refresh_before_expiry_ms(now_ms: u64, now_utc: u64, generated_at: u64, expires_at: u64) -> u64 {
    let lifetime = expires_at.saturating_sub(generated_at);
    let refresh_utc = generated_at.saturating_add(lifetime.saturating_mul(3) / 4);
    let remaining_seconds = refresh_utc.saturating_sub(now_utc);
    now_ms.saturating_add(remaining_seconds.saturating_mul(1_000))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn network_ready_schedules_both_initial_fetches_immediately() {
        let scheduler = Scheduler::network_ready(42);
        assert!(scheduler.is_due(SnapshotKind::Trust, 42));
        assert!(scheduler.is_due(SnapshotKind::Revocations, 42));
    }

    #[test]
    fn success_uses_fixed_periods() {
        let mut scheduler = Scheduler::network_ready(0);
        scheduler.record_success(SnapshotKind::Trust, 1_000, 100, 100, 1_000_000);
        scheduler.record_success(SnapshotKind::Revocations, 1_000, 100, 100, 1_000_000);
        assert_eq!(
            scheduler.next_attempt_ms(SnapshotKind::Trust),
            1_000 + TRUST_PERIOD_MS
        );
        assert_eq!(
            scheduler.next_attempt_ms(SnapshotKind::Revocations),
            1_000 + REVOCATION_PERIOD_MS
        );
    }

    #[test]
    fn expiry_quarter_remaining_schedules_earlier_fetch() {
        let mut scheduler = Scheduler::network_ready(0);
        scheduler.record_success(SnapshotKind::Trust, 5_000, 200, 100, 500);
        assert_eq!(
            scheduler.next_attempt_ms(SnapshotKind::Trust),
            5_000 + 200 * 1_000
        );
        scheduler.record_success(SnapshotKind::Trust, 7_000, 450, 100, 500);
        assert_eq!(scheduler.next_attempt_ms(SnapshotKind::Trust), 7_000);
    }

    #[test]
    fn not_modified_near_expiry_does_not_create_a_busy_loop() {
        let mut scheduler = Scheduler::network_ready(0);
        scheduler.record_not_modified(SnapshotKind::Trust, 7_000, 450, 100, 500);
        assert_eq!(
            scheduler.next_attempt_ms(SnapshotKind::Trust),
            7_000 + 50_000
        );

        scheduler.record_not_modified(SnapshotKind::Trust, 60_000, 800, 100, 1_000);
        assert_eq!(
            scheduler.next_attempt_ms(SnapshotKind::Trust),
            60_000 + EXPIRY_REVALIDATION_MS
        );
    }

    #[test]
    fn transient_failures_follow_bounded_exponential_policy() {
        let mut scheduler = Scheduler::network_ready(0);
        for (index, delay) in [60, 300, 900, 3_600, 21_600, 21_600]
            .into_iter()
            .enumerate()
        {
            let now = index as u64 * 100;
            scheduler.record_failure(
                SnapshotKind::Trust,
                now,
                FailureClass::Transient {
                    retry_after_seconds: None,
                },
            );
            assert_eq!(
                scheduler.next_attempt_ms(SnapshotKind::Trust),
                now + delay * 1_000
            );
        }
    }

    #[test]
    fn retry_after_is_respected_and_capped() {
        let mut scheduler = Scheduler::network_ready(0);
        scheduler.record_failure(
            SnapshotKind::Revocations,
            10,
            FailureClass::Transient {
                retry_after_seconds: Some(600),
            },
        );
        assert_eq!(
            scheduler.next_attempt_ms(SnapshotKind::Revocations),
            10 + 600_000
        );
        scheduler.record_failure(
            SnapshotKind::Revocations,
            20,
            FailureClass::Transient {
                retry_after_seconds: Some(MAX_RETRY_AFTER_SECONDS + 1),
            },
        );
        assert_eq!(
            scheduler.next_attempt_ms(SnapshotKind::Revocations),
            20 + MAX_RETRY_AFTER_SECONDS * 1_000
        );
    }

    #[test]
    fn security_failure_suppresses_short_retry() {
        let mut scheduler = Scheduler::network_ready(0);
        scheduler.record_failure(SnapshotKind::Trust, 99, FailureClass::Security);
        assert_eq!(
            scheduler.next_attempt_ms(SnapshotKind::Trust),
            99 + TRUST_PERIOD_MS
        );
    }

    #[test]
    fn successful_fetch_resets_backoff() {
        let mut scheduler = Scheduler::network_ready(0);
        scheduler.record_failure(
            SnapshotKind::Trust,
            0,
            FailureClass::Transient {
                retry_after_seconds: None,
            },
        );
        scheduler.record_failure(
            SnapshotKind::Trust,
            1,
            FailureClass::Transient {
                retry_after_seconds: None,
            },
        );
        scheduler.record_success(SnapshotKind::Trust, 2, 100, 100, 1_000_000);
        scheduler.record_failure(
            SnapshotKind::Trust,
            3,
            FailureClass::Transient {
                retry_after_seconds: None,
            },
        );
        assert_eq!(scheduler.next_attempt_ms(SnapshotKind::Trust), 60_003);
    }
}
