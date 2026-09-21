use crate::coordinator::{Coordinator, Statistics, network_access_unavailable};
use crate::diagnostics::Agent as DiagnosticsAgent;
use crate::download::RangeDownloader;
use crate::filesystem::FileBackend;
use crate::http::{DeveloperCaFetcher, NetworkTransport};
use crate::notifier::{Notifier, SignatureTransport};
use crate::repository::CertificateRepository;
use crate::scheduler::SnapshotKind;
use crate::{DEVELOPER_ROOT_PUBLIC_KEYS, DEVELOPER_TRUST_DOMAIN};
use mochios_boot_selection::Slot;

const INITIALIZATION_RETRY_MS: u64 = 60_000;
const MAX_IDLE_SLEEP_MS: u64 = 60_000;
const TRIAL_CONFIRMATION_DELAY_MS: u64 = 5_000;

pub fn run() -> ! {
    let (boot_slot, running_slot) = match mochi_user_platform::boot::system_slot() {
        Ok(slot) if slot == u64::from(mochi_user_platform::boot::BOOT_SYSTEM_SLOT_LEGACY) => ("legacy", None),
        Ok(slot) if slot == u64::from(mochi_user_platform::boot::BOOT_SYSTEM_SLOT_A) => ("A", Some(Slot::A)),
        Ok(slot) if slot == u64::from(mochi_user_platform::boot::BOOT_SYSTEM_SLOT_B) => ("B", Some(Slot::B)),
        _ => ("unavailable", None),
    };
    if let Some(slot) = running_slot {
        // Reaching update.service is necessary but not sufficient evidence of a
        // healthy boot. Give the mounted System/Data filesystems and the core
        // service set time to settle before making the trial permanent.
        sleep(TRIAL_CONFIRMATION_DELAY_MS);
        confirm_trial(slot, boot_slot);
    } else {
        let _ = mochi_user_platform::logger::write_status_fmt(format_args!(
            "update.service: boot system slot={boot_slot}\n"
        ));
    }
    mochi_user_platform::logln!(
        "update.service: Developer Trust domain={}",
        DEVELOPER_TRUST_DOMAIN
    );
    let mut repository = load_repository();
    let start_ms = monotonic_milliseconds();
    let mut coordinator = Coordinator::network_ready(start_ms);
    let mut diagnostics = DiagnosticsAgent::new(start_ms);
    if repository.recovered() {
        coordinator.record_recovery();
        mochi_user_platform::logln!("update.service: certificate database recovered");
    }
    log_database(&repository);

    let mut fetcher = DeveloperCaFetcher::new(NetworkTransport);
    let mut notifier = Notifier::new(SignatureTransport);
    let mut reported_missing_database_offline = false;
    loop {
        let now_ms = monotonic_milliseconds();
        let now_utc = match mochi_user_platform::time::utc_seconds() {
            Ok(now) => now,
            Err(error) => {
                mochi_user_platform::logln!(
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
        let offer = diagnostics.tick(&mut NetworkTransport, now_ms, now_utc);
        if let (Some(slot), Some(offer)) = (running_slot, offer) {
            install_offer(slot, &offer, now_ms);
        }
        if let Err(error) = notifier.notify_changes(&state_before, repository.state()) {
            mochi_user_platform::logln!(
                "update.service: signature notification failed errno={}",
                errno(error)
            );
        }
        if total_attempts(coordinator.statistics()) != attempts_before {
            log_sync(&coordinator, &repository);
            let missing_database_offline = certificate_database_absent(&repository)
                && network_access_unavailable(coordinator.last_error());
            if missing_database_offline && !reported_missing_database_offline {
                mochi_user_platform::logln!(
                    "update.service: no local Developer trust or revocation data is available and the network is not connected; connect to a network to enable package signature verification"
                );
            }
            reported_missing_database_offline = missing_database_offline;
        }
        let next = coordinator
            .scheduler()
            .next_attempt_ms(SnapshotKind::Trust)
            .min(
                coordinator
                    .scheduler()
                    .next_attempt_ms(SnapshotKind::Revocations),
            )
            .min(diagnostics.next_due_ms());
        sleep(next.saturating_sub(now_ms).clamp(1, MAX_IDLE_SLEEP_MS));
    }
}

fn confirm_trial(running: Slot, boot_slot: &str) {
    let mut disk = crate::installer::SystemDisk::boot_disk();
    let layout = match crate::installer::discover_layout(&mut disk) {
        Ok(layout) => layout,
        Err(error) => {
            let _ = mochi_user_platform::logger::write_status_fmt(format_args!(
                "update.service: boot system slot={boot_slot}; boot-state layout unavailable error={error:?}\n"
            ));
            return;
        }
    };
    let result = crate::installer::confirm_running(&mut disk, layout, running);
    match result {
        Ok(true) => {
            let _ = crate::diagnostics::record_boot_outcome(running, true);
            let _ = mochi_user_platform::logger::write_status_fmt(format_args!(
                "update.service: boot system slot={boot_slot}; confirmed first boot of slot {running:?}\n"
            ));
        }
        Ok(false) => {
            let _ = crate::diagnostics::record_boot_outcome(running, false);
        }
        Err(error) => {
            let _ = mochi_user_platform::logger::write_status_fmt(format_args!(
                "update.service: boot system slot={boot_slot}; boot confirmation unavailable error={error:?}\n"
            ));
        }
    }
}

fn install_offer(running: Slot, offer: &crate::os_update::VerifiedManifest, request_id: u64) {
    let Some((current_version, current_build)) = crate::diagnostics::release_identity() else {
        mochi_user_platform::logln!("update.service: local release identity is unavailable");
        return;
    };
    let mut disk = crate::installer::SystemDisk::boot_disk();
    let layout = match crate::installer::discover_layout(&mut disk) {
        Ok(layout) => layout,
        Err(error) => {
            mochi_user_platform::logln!("update.service: update layout rejected error={error:?}");
            return;
        }
    };
    let mut source = RangeDownloader::new(NetworkTransport, offer.url(), offer.size_bytes(), request_id.max(1));
    match crate::installer::install(
        &mut disk, &mut source, layout, running, current_build, offer, crate::SYSTEM_PUBLIC_KEYS,
    ) {
        Ok(target) => {
            if let Err(error) = crate::diagnostics::record_staged_update(
                &current_version, current_build, offer, target,
            ) {
                mochi_user_platform::logln!("update.service: staged update result metadata unavailable kind={:?}", error.kind());
            }
            mochi_user_platform::logln!(
                "update.service: update verified and staged target={target:?} build={}; reboot required",
                offer.build_number(),
            );
        }
        Err(error) => mochi_user_platform::logln!("update.service: update installation failed error={error:?}"),
    }
}

fn certificate_database_absent(repository: &CertificateRepository<'_, FileBackend>) -> bool {
    repository.trust().is_none() && repository.revocations().is_none()
}

fn load_repository() -> CertificateRepository<'static, FileBackend> {
    loop {
        let now_utc = match mochi_user_platform::time::utc_seconds() {
            Ok(now) => now,
            Err(error) => {
                mochi_user_platform::logln!(
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
                mochi_user_platform::logln!(
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
                mochi_user_platform::logln!(
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
                mochi_user_platform::logln!(
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
    mochi_user_platform::logln!(
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
    mochi_user_platform::logln!(
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
    mochi_user_platform::logln!(
        "update.service: sync result={:?} last_error={:?} next_trust_ms={} next_revocations_ms={}",
        coordinator.last_result(),
        coordinator.last_error(),
        scheduler.next_attempt_ms(SnapshotKind::Trust),
        scheduler.next_attempt_ms(SnapshotKind::Revocations)
    );
    mochi_user_platform::logln!(
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
