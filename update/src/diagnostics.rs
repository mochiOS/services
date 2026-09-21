//! Consent-gated public API polling and durable report delivery.

use std::fs;
use std::io;
use std::io::Write;
use std::path::{Path, PathBuf};

use mochios_net_device_protocol::HttpMethod;
use serde_json::{Value, json};

use crate::http::Transport;
use crate::os_update::{self, Version};
use crate::public_api::{self, Response};

const CONFIG_PATH: &str = "/var/config/diagnostics/settings.conf";
const DATA_ROOT: &str = "/var/lib/diagnostics";
const INSTALL_DATE_PATH: &str = "/var/lib/diagnostics/install_date";
const DEVICE_ID_PATH: &str = "/var/lib/diagnostics/device_id";
const QUEUE_ROOT: &str = "/var/lib/diagnostics/queue";
const UPDATE_ROOT: &str = "/var/lib/update";
const PENDING_UPDATE_PATH: &str = "/var/lib/update/pending-result.json";
const POLL_PERIOD_MS: u64 = 6 * 60 * 60 * 1_000;
const CONSENT_CHECK_MS: u64 = 60_000;
const RETRY_SECONDS: [u64; 5] = [60, 300, 900, 3_600, 21_600];
const VERSION_TOML: &str = include_str!("../../../version.toml");

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Delivery {
    Accepted,
    Retry(u64),
    Quarantine,
}

pub fn delivery_for(status: u16, retry_after: Option<u64>, attempt: usize) -> Delivery {
    match status {
        200 | 201 => Delivery::Accepted,
        429 | 500..=599 => Delivery::Retry(
            RETRY_SECONDS[attempt.min(RETRY_SECONDS.len() - 1)]
                .max(retry_after.unwrap_or(0)),
        ),
        _ => Delivery::Quarantine,
    }
}

fn valid_id(value: &str, min: usize, max: usize) -> bool {
    (min..=max).contains(&value.len())
        && value.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
}

fn valid_date(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() != 10 || bytes[4] != b'-' || bytes[7] != b'-' {
        return false;
    }
    let Ok(year) = value[0..4].parse::<u32>() else { return false };
    let Ok(month) = value[5..7].parse::<u32>() else { return false };
    let Ok(day) = value[8..10].parse::<u32>() else { return false };
    if !(2020..=2100).contains(&year) || !(1..=12).contains(&month) {
        return false;
    }
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let days = [31, if leap { 29 } else { 28 }, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    (1..=days[(month - 1) as usize]).contains(&day)
}

fn date_from_unix(seconds: u64) -> Option<String> {
    let days = i64::try_from(seconds / 86_400).ok()?;
    let shifted = days.checked_add(719_468)?;
    let era = if shifted >= 0 { shifted } else { shifted - 146_096 } / 146_097;
    let day_of_era = shifted - era * 146_097;
    let year_of_era = (day_of_era - day_of_era / 1_460 + day_of_era / 36_524
        - day_of_era / 146_096) / 365;
    let mut year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_phase = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_phase + 2) / 5 + 1;
    let month = month_phase + if month_phase < 10 { 3 } else { -9 };
    year += i64::from(month <= 2);
    let result = format!("{year:04}-{month:02}-{day:02}");
    valid_date(&result).then_some(result)
}

pub(crate) fn release_identity() -> Option<(String, u64)> {
    let mut version = None;
    let mut build = None;
    for line in VERSION_TOML.lines() {
        if let Some(value) = line.strip_prefix("release = ") {
            let value = value.trim_matches('"');
            if Version::parse(value).is_some() {
                version = Some(value.to_owned());
            }
        } else if let Some(value) = line.strip_prefix("build = ") {
            build = value.parse::<u64>().ok();
        }
    }
    Some((version?, build?))
}

fn consent_enabled(contents: &str) -> bool {
    let mut enabled = None;
    let mut consent = None;
    for line in contents.lines() {
        if let Some(value) = line.strip_prefix("diagnostics_enabled=") {
            if enabled.is_some() { return false; }
            enabled = Some(value);
        }
        if let Some(value) = line.strip_prefix("diagnostics_consent=") {
            if consent.is_some() { return false; }
            consent = Some(value);
        }
    }
    enabled == Some("true") && consent == Some("true")
}

fn queue_files(root: &Path) -> io::Result<Vec<PathBuf>> {
    let mut backups = Vec::new();
    let mut files = Vec::new();
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().is_some_and(|extension| extension == "backup") && path.is_file() {
            backups.push(path.with_extension("json"));
        } else if path.extension().is_some_and(|extension| extension == "json") && path.is_file() {
            files.push(path);
        }
    }
    for path in backups {
        recover_atomic(&path)?;
        if path.is_file() && !files.contains(&path) {
            files.push(path);
        }
    }
    files.sort();
    Ok(files)
}

fn purge_queue() -> io::Result<()> {
    let root = Path::new(QUEUE_ROOT);
    let quarantine = Path::new(DATA_ROOT).join("quarantine");
    for directory in [root, quarantine.as_path()] {
        if !directory.exists() { continue; }
        for entry in fs::read_dir(directory)? {
            let path = entry?.path();
            if matches!(path.extension().and_then(|value| value.to_str()), Some("json" | "pending" | "backup")) {
                fs::remove_file(path)?;
            }
        }
    }
    Ok(())
}

fn purge_reportable_update_result() -> io::Result<()> {
    recover_atomic(Path::new(PENDING_UPDATE_PATH))?;
    let Ok(bytes) = fs::read(PENDING_UPDATE_PATH) else { return Ok(()) };
    let pending: Value = serde_json::from_slice(&bytes)?;
    if pending.get("outcome").is_some() {
        fs::remove_file(PENDING_UPDATE_PATH)?;
    }
    Ok(())
}

fn recover_atomic(path: &Path) -> io::Result<()> {
    let backup = path.with_extension("backup");
    if backup.exists() {
        if path.exists() {
            fs::remove_file(backup)?;
        } else {
            fs::rename(backup, path)?;
        }
    }
    Ok(())
}

fn save_atomic(path: &Path, bytes: &[u8]) -> io::Result<()> {
    recover_atomic(path)?;
    let temporary = path.with_extension("pending");
    let backup = path.with_extension("backup");
    fs::write(&temporary, bytes)?;
    let had_original = path.exists();
    if had_original {
        fs::rename(path, &backup)?;
    }
    if let Err(error) = fs::rename(&temporary, path) {
        if had_original {
            let _ = fs::rename(&backup, path);
        }
        return Err(error);
    }
    if had_original {
        let _ = fs::remove_file(backup);
    }
    Ok(())
}

fn daily_report_marker(path: &Path) -> Option<PathBuf> {
    let stem = path.file_stem()?.to_str()?;
    let date = stem.strip_prefix("basic-")?;
    valid_date(date).then(|| path.with_extension("sent"))
}

fn mark_daily_sent(path: &Path) -> io::Result<()> {
    let Some(marker) = daily_report_marker(path) else { return Ok(()); };
    match fs::OpenOptions::new().write(true).create_new(true).open(marker) {
        Ok(_) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => Ok(()),
        Err(error) => Err(error),
    }
}

fn update_result_body(
    pending: &Value,
    event_id: &str,
    device: &str,
    occurred_on: &str,
) -> Option<Value> {
    if !valid_id(event_id, 16, 64) || !valid_id(device, 16, 128) || !valid_date(occurred_on) {
        return None;
    }
    let source = pending.get("source")?;
    let target = pending.get("target")?;
    let valid_release = |release: &Value| {
        release.get("version").and_then(Value::as_str).and_then(Version::parse).is_some()
            && release.get("build_number").and_then(Value::as_u64).is_some_and(|build| build > 0)
            && matches!(release.get("architecture").and_then(Value::as_str), Some("x86_64" | "aarch64"))
    };
    if !valid_release(source) || !valid_release(target)
        || source.get("architecture") != target.get("architecture")
    {
        return None;
    }
    let outcome = pending.get("outcome")?.as_str()?;
    if !matches!(outcome, "first_boot_succeeded" | "rolled_back") { return None; }
    Some(json!({
        "event_id": event_id,
        "device_id": device,
        "basic_diagnostics_consent": true,
        "occurred_on": occurred_on,
        "source": source,
        "target": target,
        "outcome": outcome,
        "error_code": null,
    }))
}

#[cfg(target_os = "mochios")]
fn poll_jitter_ms() -> u64 {
    let mut bytes = [0u8; 8];
    if mochi_user_platform::random::fill(&mut bytes).is_err() {
        return 900_000;
    }
    u64::from_le_bytes(bytes) % 1_800_001
}

#[cfg(target_os = "mochios")]
fn uuid_v4() -> io::Result<String> {
    let mut bytes = [0u8; 16];
    mochi_user_platform::random::fill(&mut bytes)
        .map_err(|_| io::Error::other("secure random unavailable"))?;
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Ok(format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]
    ))
}

#[cfg(target_os = "mochios")]
fn device_id() -> io::Result<String> {
    recover_atomic(Path::new(DEVICE_ID_PATH))?;
    if let Ok(value) = fs::read_to_string(DEVICE_ID_PATH) {
        let value = value.trim();
        if valid_id(value, 16, 128) { return Ok(value.to_owned()); }
        return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid device ID"));
    }
    if !Path::new(DATA_ROOT).is_dir() {
        fs::create_dir_all(DATA_ROOT)?;
    }
    let value = uuid_v4()?;
    save_atomic(Path::new(DEVICE_ID_PATH), format!("{value}\n").as_bytes())?;
    Ok(value)
}

#[cfg(target_os = "mochios")]
fn install_date(first_valid_date: &str) -> io::Result<String> {
    match fs::read_to_string(INSTALL_DATE_PATH) {
        Ok(value) => return Ok(value.trim().to_owned()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    if !Path::new(DATA_ROOT).is_dir() {
        fs::create_dir_all(DATA_ROOT)?;
    }
    // Setup can precede a valid real-time clock. Record the first valid UTC
    // date instead of inventing an installation date while the clock is wrong.
    match fs::OpenOptions::new().write(true).create_new(true).open(INSTALL_DATE_PATH) {
        Ok(mut file) => {
            file.write_all(first_valid_date.as_bytes())?;
            file.write_all(b"\n")?;
            Ok(first_valid_date.to_owned())
        }
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            fs::read_to_string(INSTALL_DATE_PATH).map(|value| value.trim().to_owned())
        }
        Err(error) => Err(error),
    }
}

#[cfg(target_os = "mochios")]
fn queue_basic(now_utc: u64, device: &str) -> io::Result<()> {
    let last_active_date = date_from_unix(now_utc)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid UTC date"))?;
    if !Path::new(QUEUE_ROOT).is_dir() {
        fs::create_dir_all(QUEUE_ROOT)?;
    }
    let path = Path::new(QUEUE_ROOT).join(format!("basic-{last_active_date}.json"));
    recover_atomic(&path)?;
    let quarantined = Path::new(DATA_ROOT).join("quarantine").join(format!("basic-{last_active_date}.json"));
    if path.exists()
        || path.with_extension("sent").exists()
        || path.with_extension("rejected").exists()
        || quarantined.exists()
    {
        return Ok(());
    }
    let install_date = install_date(&last_active_date)?;
    let install_date = install_date.trim();
    if !valid_date(install_date) || install_date > last_active_date.as_str() {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid install date"));
    }
    let (version, build_number) = release_identity()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid build metadata"))?;
    let event_id = uuid_v4()?;
    let body = json!({
        "event_id": event_id,
        "device_id": device,
        "basic_diagnostics_consent": true,
        "additional_diagnostics_consent": false,
        "os": {"version": version, "build_number": build_number, "architecture": std::env::consts::ARCH},
        "install_date": install_date,
        "last_active_date": last_active_date,
        "boot_succeeded": true,
        "previous_shutdown": "unknown",
        "ram_band": "unknown",
        "is_mochi_pc": false,
        "frequent_apps": null,
        "country_or_region": null,
    });
    let record = json!({"endpoint":"/diagnostics", "body":body, "attempts":0, "next_attempt_utc":now_utc});
    save_atomic(&path, &serde_json::to_vec(&record)?)
}

#[cfg(target_os = "mochios")]
pub fn record_staged_update(
    source_version: &str,
    source_build: u64,
    target: &os_update::VerifiedManifest,
    target_slot: mochios_boot_selection::Slot,
) -> io::Result<()> {
    if Version::parse(source_version).is_none() || source_build == 0 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid source release"));
    }
    fs::create_dir_all(UPDATE_ROOT)?;
    let pending = json!({
        "source": {
            "version": source_version,
            "build_number": source_build,
            "architecture": std::env::consts::ARCH,
        },
        "target": {
            "version": target.version(),
            "build_number": target.build_number(),
            "architecture": target.architecture(),
        },
        "target_slot": match target_slot {
            mochios_boot_selection::Slot::A => "A",
            mochios_boot_selection::Slot::B => "B",
        },
    });
    save_atomic(Path::new(PENDING_UPDATE_PATH), &serde_json::to_vec(&pending)?)
}

#[cfg(target_os = "mochios")]
pub fn record_boot_outcome(running: mochios_boot_selection::Slot, confirmed: bool) -> io::Result<()> {
    recover_atomic(Path::new(PENDING_UPDATE_PATH))?;
    let Ok(bytes) = fs::read(PENDING_UPDATE_PATH) else { return Ok(()) };
    let mut pending: Value = serde_json::from_slice(&bytes)?;
    if pending.get("outcome").is_some() { return Ok(()); }
    let running = match running { mochios_boot_selection::Slot::A => "A", mochios_boot_selection::Slot::B => "B" };
    let target = pending.get("target_slot").and_then(Value::as_str)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing target slot"))?;
    if confirmed && target != running {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "confirmed wrong target slot"));
    }
    pending["outcome"] = json!(if target == running { "first_boot_succeeded" } else { "rolled_back" });
    save_atomic(Path::new(PENDING_UPDATE_PATH), &serde_json::to_vec(&pending)?)
}

#[cfg(target_os = "mochios")]
fn queue_update_result(now_utc: u64, device: &str) -> io::Result<()> {
    recover_atomic(Path::new(PENDING_UPDATE_PATH))?;
    let Ok(bytes) = fs::read(PENDING_UPDATE_PATH) else { return Ok(()) };
    let mut pending: Value = serde_json::from_slice(&bytes)?;
    if pending.get("outcome").is_none() { return Ok(()); }
    let occurred_on = date_from_unix(now_utc)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid UTC date"))?;
    let event_id = match pending.get("event_id").and_then(Value::as_str) {
        Some(event_id) if valid_id(event_id, 16, 64) => event_id.to_owned(),
        Some(_) => return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid update event ID")),
        None => {
            let event_id = uuid_v4()?;
            pending["event_id"] = json!(event_id);
            pending["occurred_on"] = json!(occurred_on);
            save_atomic(Path::new(PENDING_UPDATE_PATH), &serde_json::to_vec(&pending)?)?;
            event_id
        }
    };
    let occurred_on = pending.get("occurred_on").and_then(Value::as_str).unwrap_or(&occurred_on);
    let body = update_result_body(&pending, &event_id, device, occurred_on)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid update result"))?;
    fs::create_dir_all(QUEUE_ROOT)?;
    let path = Path::new(QUEUE_ROOT).join(format!("update-{event_id}.json"));
    if !path.exists() {
        let record = json!({"endpoint":"/update-results", "body":body, "attempts":0, "next_attempt_utc":now_utc});
        save_atomic(&path, &serde_json::to_vec(&record)?)?;
    }
    fs::remove_file(PENDING_UPDATE_PATH)
}

#[cfg(target_os = "mochios")]
pub struct Agent {
    next_poll_ms: u64,
    next_consent_check_ms: u64,
    request_id: u64,
    previously_allowed: bool,
}

#[cfg(target_os = "mochios")]
impl Agent {
    pub const fn new(start_ms: u64) -> Self {
        Self { next_poll_ms: start_ms, next_consent_check_ms: start_ms, request_id: 0, previously_allowed: false }
    }
    pub const fn next_due_ms(&self) -> u64 {
        if self.next_poll_ms < self.next_consent_check_ms {
            self.next_poll_ms
        } else {
            self.next_consent_check_ms
        }
    }

    fn next_id(&mut self) -> u64 {
        self.request_id = self.request_id.wrapping_add(1).max(1);
        self.request_id
    }

    pub fn tick<T: Transport>(
        &mut self,
        transport: &mut T,
        now_ms: u64,
        now_utc: u64,
    ) -> Option<os_update::VerifiedManifest> {
        let allowed = fs::read_to_string(CONFIG_PATH)
            .map(|contents| consent_enabled(&contents))
            .unwrap_or(false);
        if allowed && !self.previously_allowed {
            self.next_poll_ms = now_ms;
        }
        self.previously_allowed = allowed;
        if !allowed {
            if let Err(error) = purge_queue() {
                mochi_user_platform::logln!("update.service: diagnostics queue purge failed kind={:?}", error.kind());
            }
            if let Err(error) = purge_reportable_update_result() {
                mochi_user_platform::logln!("update.service: pending update result purge failed kind={:?}", error.kind());
            }
        }
        self.next_consent_check_ms = now_ms.saturating_add(CONSENT_CHECK_MS);
        if allowed {
            match device_id() {
                Ok(device) => {
                    if let Err(error) = queue_basic(now_utc, &device) {
                        mochi_user_platform::logln!("update.service: daily diagnostics not queued kind={:?}", error.kind());
                    }
                    if let Err(error) = queue_update_result(now_utc, &device) {
                        mochi_user_platform::logln!("update.service: update result not queued kind={:?}", error.kind());
                    }
                }
                Err(error) => {
                    mochi_user_platform::logln!("update.service: diagnostics device ID unavailable kind={:?}", error.kind());
                }
            }
        }
        let offer = if now_ms >= self.next_poll_ms { self.poll(transport, now_ms) } else { None };
        if allowed { self.flush(transport, now_utc); }
        offer
    }

    fn poll<T: Transport>(&mut self, transport: &mut T, now_ms: u64) -> Option<os_update::VerifiedManifest> {
        let health = self.get(transport, "/health");
        if !matches!(health.as_ref(), Ok(response) if response.status == 200) {
            self.next_poll_ms = now_ms.saturating_add(CONSENT_CHECK_MS);
            return None;
        }
        let distribution = self.get(transport, "/distribution/status");
        if !matches!(distribution.as_ref(), Ok(response) if response.status == 200) {
            self.next_poll_ms = now_ms.saturating_add(CONSENT_CHECK_MS);
            return None;
        }
        let stopped = distribution.ok()
            .and_then(|response| serde_json::from_slice::<Value>(&response.body).ok())
            .and_then(|value| value.get("stopped").and_then(Value::as_bool))
            .unwrap_or(true);
        if let Some((version, build)) = release_identity() {
            let path = format!("/updates/check?version={version}&build={build}&architecture={}", std::env::consts::ARCH);
            if let Ok(response) = self.get(transport, &path) {
                let status = os_update::check_http_response(
                    &response,
                    std::env::consts::ARCH,
                    os_update::TRUSTED_RELEASE_KEYS,
                );
                mochi_user_platform::logln!(
                    "update.service: public update check status={:?} distribution_stopped={} request_id={:?}",
                    status.as_ref().map(os_update::CheckStatus::name), stopped, response.request_id,
                );
                if let Err(os_update::CheckError::RateLimited(seconds)) = &status {
                    self.next_poll_ms = now_ms.saturating_add((*seconds).max(60).saturating_mul(1_000));
                    return None;
                }
                if status == Err(os_update::CheckError::ServiceUnavailable) {
                    self.next_poll_ms = now_ms.saturating_add(CONSENT_CHECK_MS);
                    return None;
                }
                if !stopped {
                    if let Ok(os_update::CheckStatus::Available(manifest)) = status {
                        self.next_poll_ms = now_ms.saturating_add(POLL_PERIOD_MS - 900_000 + poll_jitter_ms());
                        return Some(manifest);
                    }
                }
            } else {
                self.next_poll_ms = now_ms.saturating_add(CONSENT_CHECK_MS);
                return None;
            }
        }
        self.next_poll_ms = now_ms.saturating_add(POLL_PERIOD_MS - 900_000 + poll_jitter_ms());
        None
    }

    fn get<T: Transport>(&mut self, transport: &mut T, path: &str) -> Result<Response, public_api::ApiError> {
        let result = public_api::request(transport, self.next_id(), HttpMethod::Get, path, &[]);
        if let Ok(response) = &result { log_response(path, response); }
        result
    }

    fn flush<T: Transport>(&mut self, transport: &mut T, now_utc: u64) {
        let Ok(paths) = queue_files(Path::new(QUEUE_ROOT)) else { return; };
        for path in paths {
            if path.with_extension("rejected").exists()
                || daily_report_marker(&path).is_some_and(|marker| marker.exists())
            {
                let _ = fs::remove_file(path);
                continue;
            }
            if !fs::read_to_string(CONFIG_PATH)
                .map(|contents| consent_enabled(&contents))
                .unwrap_or(false)
            {
                let _ = purge_queue();
                return;
            }
            let Ok(bytes) = fs::read(&path) else { continue; };
            let Ok(mut record) = serde_json::from_slice::<Value>(&bytes) else { continue; };
            let Some(endpoint) = record.get("endpoint").and_then(Value::as_str) else { continue; };
            // Crash reports need a separate, per-crash confirmation path.
            if !matches!(endpoint, "/diagnostics" | "/update-results") { continue; }
            let endpoint = endpoint.to_owned();
            let next_attempt = record.get("next_attempt_utc").and_then(Value::as_u64).unwrap_or(0);
            if next_attempt > now_utc { continue; }
            let Some(body) = record.get("body") else { continue; };
            let Ok(body) = serde_json::to_vec(body) else { continue; };
            let attempts = record.get("attempts").and_then(Value::as_u64).unwrap_or(0) as usize;
            let result = public_api::request(transport, self.next_id(), HttpMethod::Post, &endpoint, &body);
            let disposition = match result {
                Ok(response) => {
                    log_response(&endpoint, &response);
                    delivery_for(response.status, response.retry_after_seconds, attempts)
                }
                Err(_) => Delivery::Retry(RETRY_SECONDS[attempts.min(RETRY_SECONDS.len() - 1)]),
            };
            match disposition {
                Delivery::Accepted => {
                    if mark_daily_sent(&path).is_ok() {
                        let _ = fs::remove_file(path);
                    }
                }
                Delivery::Quarantine => {
                    let quarantine = Path::new(DATA_ROOT).join("quarantine");
                    if !quarantine.is_dir() {
                        let _ = fs::create_dir_all(&quarantine);
                    }
                    let moved = path.file_name().is_some_and(|name| {
                        fs::rename(&path, quarantine.join(name)).is_ok()
                    });
                    if !moved {
                        let rejected = path.with_extension("rejected");
                        let marked = match fs::OpenOptions::new().write(true).create_new(true).open(rejected) {
                            Ok(_) => true,
                            Err(error) => error.kind() == io::ErrorKind::AlreadyExists,
                        };
                        if marked {
                            let _ = fs::remove_file(&path);
                        }
                    }
                }
                Delivery::Retry(delay) => {
                    record["attempts"] = json!(attempts.saturating_add(1));
                    record["next_attempt_utc"] = json!(now_utc.saturating_add(delay).saturating_add(poll_jitter_ms() / 30_000));
                    if let Ok(bytes) = serde_json::to_vec(&record) { let _ = save_atomic(&path, &bytes); }
                    break;
                }
            }
        }
    }
}

#[cfg(target_os = "mochios")]
fn log_response(endpoint: &str, response: &Response) {
    mochi_user_platform::logln!(
        "update.service: public API endpoint={} status={} request_id={}",
        endpoint,
        response.status,
        response.request_id.as_deref().unwrap_or("missing"),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requires_explicit_consent_even_when_enabled_by_default() {
        assert!(!consent_enabled("diagnostics_enabled=true\n"));
        assert!(consent_enabled("diagnostics_enabled=true\ndiagnostics_consent=true\n"));
        assert!(!consent_enabled("diagnostics_enabled=false\ndiagnostics_consent=true\n"));
        assert!(!consent_enabled("diagnostics_enabled=true\ndiagnostics_consent=true\ndiagnostics_consent=false\n"));
    }

    #[test]
    fn validates_real_calendar_dates() {
        assert!(valid_date("2026-09-19"));
        assert!(valid_date("2024-02-29"));
        assert!(!valid_date("2025-02-29"));
        assert_eq!(date_from_unix(0), None);
    }

    #[test]
    fn daily_marker_accepts_only_dated_basic_reports() {
        let daily = Path::new("/var/lib/diagnostics/queue/basic-2026-09-19.json");
        assert_eq!(
            daily_report_marker(daily).as_deref(),
            Some(Path::new("/var/lib/diagnostics/queue/basic-2026-09-19.sent")),
        );
        assert!(daily_report_marker(Path::new("/var/lib/diagnostics/queue/basic-2026-02-30.json")).is_none());
        assert!(daily_report_marker(Path::new("/var/lib/diagnostics/queue/crash-2026-09-19.json")).is_none());
    }

    #[test]
    fn response_policy_matches_api_contract() {
        assert_eq!(delivery_for(201, None, 0), Delivery::Accepted);
        assert_eq!(delivery_for(200, None, 0), Delivery::Accepted);
        assert_eq!(delivery_for(429, Some(120), 0), Delivery::Retry(120));
        assert_eq!(delivery_for(503, None, 2), Delivery::Retry(900));
        assert_eq!(delivery_for(409, None, 0), Delivery::Quarantine);
    }

    #[test]
    fn ids_are_strict() {
        assert!(valid_id("4dd15b59-6733-4e36-b993-e206c87219cb", 16, 64));
        assert!(!valid_id("../secrets", 16, 64));
    }

    #[test]
    fn release_metadata_comes_from_version_toml() {
        let (version, build) = release_identity().expect("release metadata");
        assert!(!version.is_empty());
        assert!(build > 0);
    }

    #[test]
    fn update_result_is_bound_to_source_target_and_outcome() {
        let pending = json!({
            "source":{"version":"26.9","build_number":1234,"architecture":"x86_64"},
            "target":{"version":"26.10","build_number":1300,"architecture":"x86_64"},
            "outcome":"first_boot_succeeded",
        });
        let body = update_result_body(
            &pending,
            "5e614437-c6e2-49a1-a94a-6240057ff9a7",
            "2e71caf1-2182-49c7-a817-1a6ceacde381",
            "2026-09-21",
        ).unwrap();
        assert_eq!(body["target"]["build_number"], 1300);
        assert_eq!(body["outcome"], "first_boot_succeeded");
        let mut wrong_architecture = pending;
        wrong_architecture["target"]["architecture"] = json!("aarch64");
        assert!(update_result_body(
            &wrong_architecture,
            "5e614437-c6e2-49a1-a94a-6240057ff9a7",
            "2e71caf1-2182-49c7-a817-1a6ceacde381",
            "2026-09-21",
        ).is_none());
    }
}
