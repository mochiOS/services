//! Local native termination reports. Detailed evidence is never enqueued to
//! update.service's external diagnostics transport.
use crate::report_storage::Directory;
use mochi_user_platform as p;
use p::diagnostic::{EXIT_KIND_EXCEPTION, EXIT_RECORD_LEN, ExitRecord};
use serde_json::json;
use std::sync::atomic::{AtomicU64, Ordering};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

static SESSION: AtomicU64 = AtomicU64::new(0);
pub fn session_id() -> p::syscall::SysResult<u64> {
    let current = SESSION.load(Ordering::Acquire);
    if current != 0 {
        return Ok(current);
    }
    let value = p::service_ready::generate_token()?;
    Ok(
        match SESSION.compare_exchange(0, value, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => value,
            Err(existing) => existing,
        },
    )
}

pub fn image_name(session: u64, process: u64, revision: u64, digest: &str) -> String {
    format!("image-{session:016x}-{process}-{revision}-{digest}.json")
}

pub struct Collector {
    cursor: u64,
    buffer: [u8; EXIT_RECORD_LEN * 8],
    session: Option<u64>,
    last_error: Option<i64>,
    pending: Option<(String, Vec<u8>, u64)>,
}
impl Collector {
    pub fn new() -> Self {
        Self {
            cursor: 0,
            buffer: [0; EXIT_RECORD_LEN * 8],
            session: None,
            last_error: None,
            pending: None,
        }
    }
    pub fn tick(&mut self) {
        let Self {
            cursor,
            buffer,
            session,
            last_error,
            pending,
        } = self;
        let result = (|| {
            if let Some((name, bytes, next)) = pending.as_ref() {
                Directory::open("crashes")?.store(name, bytes, 128)?;
                crate::report_api::remember(name, bytes);
                *cursor = *next;
                *pending = None;
            }
            let session = match *session {
                Some(id) => id,
                None => {
                    let id = session_id()?;
                    *session = Some(id);
                    id
                }
            };
            let (count, read) = p::diagnostic::read_exits(*cursor, buffer)?;
            if count == 0 {
                *cursor = read.next_cursor;
                return Ok(());
            }
            let reports = Directory::open("crashes")?;
            let first = *cursor + read.dropped;
            for (index, bytes) in buffer[..count].chunks_exact(EXIT_RECORD_LEN).enumerate() {
                let record = ExitRecord::from_bytes(bytes)
                    .ok_or(p::syscall::SysError::from_raw(p::syscall::EIO as i64))?;
                let position = first + (index * EXIT_RECORD_LEN) as u64;
                if record.kind != EXIT_KIND_EXCEPTION {
                    // grep/compilers and other commands routinely return a
                    // nonzero status. This is not evidence of a crash.
                    *cursor = position + EXIT_RECORD_LEN as u64;
                    continue;
                }
                let name = format!("crash-{session:016x}-{position:020}.json");
                let image_digest = hex(&record.image_digest);
                let image = Directory::open("images")
                    .ok()
                    .and_then(|images| {
                        images
                            .read(&image_name(
                                session,
                                record.process_id,
                                record.image_revision,
                                &image_digest,
                            ))
                            .ok()
                    })
                    .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok());
                let body = json!({
                    "schema_version": 1,
                    "collector_session": format!("{session:016x}"),
                    "cursor": position,
                    "records_lost_before": if index == 0 { read.dropped / EXIT_RECORD_LEN as u64 } else { 0 },
                    "os_version_toml": include_str!("../../../version.toml"),
                    "evidence": "native",
                    "kind": if record.kind == EXIT_KIND_EXCEPTION { "exception_termination" } else { "nonzero_exit" },
                    "timestamp_monotonic_ns": record.timestamp_ns,
                    "collected_utc_seconds": p::time::utc_seconds().ok(),
                    "process_id": record.process_id, "thread_id": record.thread_id,
                    "image_revision": record.image_revision,
                    "exit_code": record.exit_code,
                    "architecture": record.architecture,
                    "image_digest_kind": record.digest_kind,
                    "image_sha256": image_digest,
                    "exception": if record.kind == EXIT_KIND_EXCEPTION { Some(json!({
                        "vector": record.vector, "cause": record.cause,
                        "error_code": format!("0x{:x}", record.error_code),
                        "instruction": format!("0x{:x}", record.instruction),
                        "stack_pointer": format!("0x{:x}", record.stack_pointer),
                        "address": format!("0x{:x}", record.address),
                    })) } else { None },
                    "image": image,
                    "owner_uid": image.as_ref().and_then(|image| image["owner_uid"].as_u64()),
                    "owner_generation": image.as_ref().and_then(|image| image["owner_generation"].as_u64()),
                    "image_metadata_available": image.is_some(),
                });
                let bytes = serde_json::to_vec_pretty(&body)
                    .map_err(|_| p::syscall::SysError::from_raw(p::syscall::EIO as i64))?;
                *pending = Some((name, bytes, position + EXIT_RECORD_LEN as u64));
                let (name, bytes, _) = pending.as_ref().unwrap();
                reports.store(name, bytes, 128)?;
                crate::report_api::remember(name, bytes);
                // Commit one record only after publication and directory sync.
                *cursor = position + EXIT_RECORD_LEN as u64;
                *pending = None;
            }
            Ok::<_, p::syscall::SysError>(())
        })();
        match result {
            Ok(()) => *last_error = None,
            Err(error) if *last_error != Some(error.raw()) => {
                let _ = p::io::write(
                    p::io::STDERR,
                    format!("logger.service: crash persistence failed: {:?}\n", error).as_bytes(),
                );
                *last_error = Some(error.raw());
            }
            Err(_) => {}
        }
    }
}
