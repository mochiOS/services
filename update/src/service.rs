use crate::coordinator::{Coordinator, Statistics};
use crate::filesystem::FileBackend;
use crate::http::{DeveloperCaFetcher, NetworkTransport};
use crate::notifier::{Notifier, SignatureTransport};
use crate::repository::CertificateRepository;
use crate::scheduler::SnapshotKind;
use crate::{DEVELOPER_ROOT_PUBLIC_KEYS, DEVELOPER_TRUST_DOMAIN};

const INITIALIZATION_RETRY_MS: u64 = 60_000;
const MAX_IDLE_SLEEP_MS: u64 = 60_000;

pub fn run() -> ! {
    mochi_user_platform::println!(
        "update.service: Developer Trust domain={}",
        DEVELOPER_TRUST_DOMAIN
    );
    let mut repository = load_repository();
    let start_ms = monotonic_milliseconds();
    let mut coordinator = Coordinator::network_ready(start_ms);
    if repository.recovered() {
        coordinator.record_recovery();
        mochi_user_platform::println!("update.service: certificate database recovered");
    }
    log_database(&repository);

    let mut fetcher = DeveloperCaFetcher::new(NetworkTransport);
    let mut notifier = Notifier::new(SignatureTransport);
    loop {
        let now_ms = monotonic_milliseconds();
        let now_utc = match mochi_user_platform::time::utc_seconds() {
            Ok(now) => now,
            Err(error) => {
                mochi_user_platform::println!(
                    "update.service: UTC unavailable errno={}",
                    errno(error)
                );
                sleep(INITIALIZATION_RETRY_MS);
                continue;
            }
        };
        let attempts_before = total_attempts(coordinator.statistics());
        let state_before = repository.state().clone();
        coordinator.synchronize_due(&mut fetcher, &mut repository, now_ms, now_utc);
        if let Err(error) = notifier.notify_changes(&state_before, repository.state()) {
            mochi_user_platform::println!(
                "update.service: signature notification failed errno={}",
                errno(error)
            );
        }
        if total_attempts(coordinator.statistics()) != attempts_before {
            log_sync(&coordinator, &repository);
        }
        let next = coordinator
            .scheduler()
            .next_attempt_ms(SnapshotKind::Trust)
            .min(
                coordinator
                    .scheduler()
                    .next_attempt_ms(SnapshotKind::Revocations),
            );
        sleep(next.saturating_sub(now_ms).clamp(1, MAX_IDLE_SLEEP_MS));
    }
}

fn load_repository() -> CertificateRepository<'static, FileBackend> {
    loop {
        let now_utc = match mochi_user_platform::time::utc_seconds() {
            Ok(now) => now,
            Err(error) => {
                mochi_user_platform::println!(
                    "update.service: UTC unavailable during database load errno={}",
                    errno(error)
                );
                sleep(INITIALIZATION_RETRY_MS);
                continue;
            }
        };
        let backend = match FileBackend::system() {
            Ok(backend) => backend,
            Err(error) => {
                mochi_user_platform::println!(
                    "update.service: certificate directory unavailable error={:?}",
                    error
                );
                sleep(INITIALIZATION_RETRY_MS);
                continue;
            }
        };
        match CertificateRepository::load(backend, DEVELOPER_ROOT_PUBLIC_KEYS, now_utc) {
            Ok(repository) => return repository,
            Err(error) => {
                mochi_user_platform::println!(
                    "update.service: certificate database load failed error={:?}",
                    error
                );
                sleep(INITIALIZATION_RETRY_MS);
            }
        }
    }
}

fn monotonic_milliseconds() -> u64 {
    loop {
        match mochi_user_platform::time::monotonic_milliseconds() {
            Ok(now) => return now,
            Err(error) => {
                mochi_user_platform::println!(
                    "update.service: monotonic clock unavailable errno={}",
                    errno(error)
                );
                sleep(INITIALIZATION_RETRY_MS);
            }
        }
    }
}

fn sleep(milliseconds: u64) {
    if mochi_user_platform::thread::sleep_milliseconds(milliseconds).is_err() {
        mochi_user_platform::thread::yield_now();
    }
}

fn errno(error: mochi_user_platform::syscall::SysError) -> u64 {
    match error.errno() {
        Some(errno) => errno,
        None => 0,
    }
}

fn total_attempts(statistics: &Statistics) -> u64 {
    statistics
        .trust_sync_attempts
        .saturating_add(statistics.revocation_sync_attempts)
}

fn log_database(repository: &CertificateRepository<'_, FileBackend>) {
    let state = repository.state();
    mochi_user_platform::println!(
        "update.service: trust version={} generated_at={} expires_at={} last_checked={} etag={} slot={:?}",
        state.trust.snapshot_version,
        state.trust.generated_at,
        state.trust.expires_at,
        state.trust.last_checked_at,
        state.trust.etag.as_str(),
        state.active_trust_slot
    );
    let revocation_count = repository
        .revocations()
        .map_or(0, |snapshot| snapshot.snapshot().content.revocations.len());
    mochi_user_platform::println!(
        "update.service: revocations version={} generated_at={} expires_at={} count={} last_checked={} etag={} slot={:?}",
        state.revocations.snapshot_version,
        state.revocations.generated_at,
        state.revocations.expires_at,
        revocation_count,
        state.revocations.last_checked_at,
        state.revocations.etag.as_str(),
        state.active_revocation_slot
    );
}

fn log_sync(coordinator: &Coordinator, repository: &CertificateRepository<'_, FileBackend>) {
    let statistics = coordinator.statistics();
    let scheduler = coordinator.scheduler();
    mochi_user_platform::println!(
        "update.service: sync result={:?} next_trust_ms={} next_revocations_ms={}",
        coordinator.last_result(),
        scheduler.next_attempt_ms(SnapshotKind::Trust),
        scheduler.next_attempt_ms(SnapshotKind::Revocations)
    );
    mochi_user_platform::println!(
        "update.service: stats trust={}/{}/{} failures={} revocations={}/{}/{} failures={} signature_failures={} rollback_rejections={} expiration_failures={} storage_failures={} recoveries={}",
        statistics.trust_sync_attempts,
        statistics.trust_sync_updated,
        statistics.trust_sync_not_modified,
        statistics.trust_sync_failures,
        statistics.revocation_sync_attempts,
        statistics.revocation_sync_updated,
        statistics.revocation_sync_not_modified,
        statistics.revocation_sync_failures,
        statistics.snapshot_signature_failures,
        statistics.snapshot_rollback_rejections,
        statistics.snapshot_expiration_failures,
        statistics.snapshot_storage_failures,
        statistics.snapshot_recovery_count
    );
    log_database(repository);
}
