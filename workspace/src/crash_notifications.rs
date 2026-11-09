//! Local crash windows are owned by a separate, existing Settings process.
//! Keep this work off the session's blocking IPC dispatcher.
use super::platform as p;
use serde_json::Value;
use std::{
    collections::BTreeSet,
    time::{Duration, Instant},
};

pub fn start() -> std::io::Result<()> {
    // A failed clock read must not replay every historical crash as a new one.
    let started = p::time::monotonic_nanoseconds()
        .map_err(|error| std::io::Error::other(format!("crash watcher clock: {error:?}")))?;
    std::thread::Builder::new()
        .name("crash-notifications".into())
        .spawn(move || {
            let mut seen = BTreeSet::new();
            let mut active: Option<p::execution_peer::ProcessReference> = None;
            let mut reporter_pids = BTreeSet::new();
            let mut pending: Option<(String, usize)> = None;
            let mut next_window = Instant::now();
            let mut last_error = None;
            loop {
                if let Some(process) = &active {
                    if p::process::handle_status(process.0)
                        .is_ok_and(|status| status.state == p::process::PROCESS_STATE_EXITED)
                    {
                        active = None;
                        next_window = Instant::now() + Duration::from_secs(30);
                    }
                }
                let snapshot = p::diagnostic::reports::list().and_then(|bytes| {
                    let body: Value = serde_json::from_slice(&bytes)
                        .map_err(|_| p::syscall::SysError::from_raw(p::syscall::EIO as i64))?;
                    if body["schema_version"] != 1
                        || body["collector_session"].as_str().is_none()
                        || body["reports"]
                            .as_array()
                            .is_none_or(|reports| reports.len() > 128)
                    {
                        return Err(p::syscall::SysError::from_raw(p::syscall::EIO as i64));
                    }
                    Ok(body)
                });
                match snapshot {
                    Ok(body) => {
                        last_error = None;
                        let reports = body["reports"].as_array().unwrap();
                        for report in reports {
                            let Some(id) = report["id"]
                                .as_str()
                                .filter(|id| p::diagnostic::reports::valid_id(id))
                            else {
                                continue;
                            };
                            if report["collector_session"] != body["collector_session"]
                                || report["timestamp_monotonic_ns"].as_u64().unwrap_or(0) < started
                                || report["process_id"]
                                    .as_u64()
                                    .is_some_and(|pid| reporter_pids.contains(&pid))
                                || !seen.insert(id.to_owned())
                            {
                                continue;
                            }
                            let count = pending
                                .as_ref()
                                .map_or(1, |(_, count)| count.saturating_add(1));
                            pending = Some((id.to_owned(), count));
                        }
                        // No unbounded per-session allocation.
                        seen.retain(|id| reports.iter().any(|r| r["id"].as_str() == Some(id)));
                    }
                    Err(error) if last_error != Some(error.raw()) => {
                        p::logln!("workspace.service: crash history unavailable: {error:?}");
                        last_error = Some(error.raw());
                    }
                    Err(_) => {}
                }
                if active.is_none() && Instant::now() >= next_window {
                    if let Some((id, count)) = &pending {
                        let arguments = [
                            format!("--show-crash={id}"),
                            format!("--crash-count={count}"),
                        ];
                        match super::launch_executable(
                            "/system/applications/Settings.app/entry.elf",
                            &arguments,
                        ) {
                            Ok(pid) => {
                                reporter_pids.insert(pid);
                                while reporter_pids.len() > 128 {
                                    reporter_pids.pop_first();
                                }
                                // Retain the actual spawned object; never infer liveness by name.
                                match p::process::open_handle_for_process_id(
                                    pid,
                                    p::handle::HANDLE_RIGHT_WAIT,
                                ) {
                                    Ok(handle) => {
                                        active = Some(p::execution_peer::ProcessReference(handle))
                                    }
                                    Err(_) => {
                                        next_window = Instant::now() + Duration::from_secs(30);
                                    }
                                }
                                pending = None;
                            }
                            Err(error) => {
                                p::logln!("workspace.service: crash window launch failed: {error}");
                                next_window = Instant::now() + Duration::from_secs(30);
                            }
                        }
                    }
                }
                std::thread::sleep(Duration::from_secs(1));
            }
        })
        .map(|_| ())
}
