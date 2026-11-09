//! A private read broker, never an upload endpoint. No path or caller-supplied
//! PID selects authority; account ownership comes from the native IPC sender.
use crate::{posix_io::with_client, report_storage::Directory};
use mochi_user_platform as p;
use p::{diagnostic::reports as wire, execution_peer, handle, ipc};
use serde_json::{Value, json};
use std::sync::Mutex;

type Result<T> = p::syscall::SysResult<T>;
static CATALOGUE: Mutex<Option<Vec<Value>>> = Mutex::new(None);
fn error(raw: u64) -> p::syscall::SysError {
    p::syscall::SysError::from_raw(raw as i64)
}

fn summary(id: &str, bytes: &[u8]) -> Option<Value> {
    let report: Value = serde_json::from_slice(bytes).ok()?;
    if !wire::valid_id(id) || report["schema_version"] != 1 {
        return None;
    }
    Some(
        json!({"id":id, "collector_session":report["collector_session"],
        "timestamp_monotonic_ns":report["timestamp_monotonic_ns"],
        "collected_utc_seconds":report["collected_utc_seconds"],
        "process_id":report["process_id"], "image_sha256":report["image_sha256"],
        "owner_uid":report["owner_uid"], "owner_generation":report["owner_generation"],
        "package_id":report["image"]["package_id"],
        "package_name":report["image"]["package_name"],
        "package_version":report["image"]["package_version"]}),
    )
}

fn insert(entries: &mut Vec<Value>, entry: Value) {
    entries.retain(|old| old["id"] != entry["id"]);
    entries.push(entry);
    entries.sort_by_key(|entry| {
        (
            entry["collected_utc_seconds"].as_u64().unwrap_or(0),
            entry["timestamp_monotonic_ns"].as_u64().unwrap_or(0),
        )
    });
    if entries.len() > 128 {
        entries.drain(..entries.len() - 128);
    }
}

pub fn initialize() -> Result<()> {
    let mut state = CATALOGUE.lock().map_err(|_| error(p::syscall::EIO))?;
    if state.is_some() {
        return Ok(());
    }
    let directory = Directory::open("crashes")?;
    let mut entries = Vec::new();
    for name in directory.names()? {
        // A damaged or unsafe old file is never served, but must not hide
        // every other report. The directory itself has already been checked.
        if let Ok(bytes) = directory.read(&name) {
            if let Some(entry) = summary(&name, &bytes) {
                insert(&mut entries, entry);
            }
        }
    }
    *state = Some(entries);
    Ok(())
}

pub fn remember(id: &str, bytes: &[u8]) {
    if let Some(entry) = summary(id, bytes) {
        if let Ok(mut state) = CATALOGUE.lock() {
            if let Some(entries) = state.as_mut() {
                insert(entries, entry);
            }
        }
    }
}

#[derive(PartialEq, Eq)]
struct Reader {
    uid: u32,
    generation: u64,
}
impl Reader {
    fn capture(sender: u64) -> Result<Self> {
        let peer = execution_peer::capture(sender)?;
        let package = peer
            .context
            .package_id
            .get(..peer.context.package_id_len as usize)
            .ok_or_else(|| error(p::syscall::EACCES))?;
        if !matches!(package, b"org.mochios.settings" | b"org.mochios.workspace") {
            return Err(error(p::syscall::EACCES));
        }
        let trusted = execution_peer::capture_builtin(sender, package)?;
        if trusted.image != peer.image {
            return Err(error(p::syscall::EACCES));
        }
        let process = execution_peer::ProcessReference(p::process::open_handle_for_endpoint(
            sender,
            handle::HANDLE_RIGHT_WAIT | handle::HANDLE_RIGHT_TRANSFER,
        )?);
        let credentials = with_client(|c| {
            c.process_session_info(mochios_posix_client::ObjectHandleAttachment {
                handle: process.0,
                rights: handle::HANDLE_RIGHT_WAIT,
            })
        })?;
        if credentials.real_uid != credentials.effective_uid
            || p::process::image_info(Some(process.0))? != peer.image
            || execution_peer::capture_builtin(sender, package)?.image != peer.image
        {
            return Err(error(p::syscall::EACCES));
        }
        let generation = with_client(|c| c.account_generation(credentials.real_uid))?;
        if generation == 0 {
            return Err(error(p::syscall::EACCES));
        }
        Ok(Self {
            uid: credentials.real_uid,
            generation,
        })
    }
    fn permits(&self, report: &Value) -> bool {
        self.uid == 0
            || (report["owner_uid"].as_u64() == Some(self.uid as u64)
                && report["owner_generation"].as_u64() == Some(self.generation))
    }
}

pub fn recognizes(request: &[u8]) -> bool {
    request.starts_with(wire::LIST) || request.starts_with(wire::READ)
}

fn snapshot(sender: u64, request: &[u8], attached: &ipc::IpcObjectHandles) -> Result<Vec<u8>> {
    if !attached.is_user_delivery() || attached.count != 0 {
        return Err(error(p::syscall::EACCES));
    }
    let reader = Reader::capture(sender)?;
    let bytes = if request == wire::LIST {
        let state = CATALOGUE.lock().map_err(|_| error(p::syscall::EIO))?;
        let entries = state.as_ref().ok_or_else(|| error(p::syscall::EAGAIN))?;
        serde_json::to_vec(&json!({"schema_version":1,
            "collector_session":format!("{:016x}", crate::crash::session_id()?),
            "reports":entries.iter().filter(|entry| reader.permits(entry)).collect::<Vec<_>>()
        }))
        .map_err(|_| error(p::syscall::EIO))?
    } else {
        let id = std::str::from_utf8(&request[8..]).map_err(|_| error(p::syscall::EINVAL))?;
        if !wire::valid_id(id) {
            return Err(error(p::syscall::EINVAL));
        }
        let bytes = Directory::open("crashes")?.read(id)?;
        let report: Value = serde_json::from_slice(&bytes).map_err(|_| error(p::syscall::EIO))?;
        if !reader.permits(&report) {
            return Err(error(p::syscall::EACCES));
        }
        bytes
    };
    if bytes.len() > wire::MAX_SNAPSHOT {
        return Err(error(p::syscall::EIO));
    }
    if reader != Reader::capture(sender)? {
        return Err(error(p::syscall::EACCES));
    }
    Ok(bytes)
}

pub fn reply(sender: u64, request: &[u8], attached: &ipc::IpcObjectHandles) {
    let result = snapshot(sender, request, attached).and_then(|bytes| {
        let object = p::memory_object::MemoryObject::create(bytes.len() as u64)?;
        let mut offset = 0;
        while offset < bytes.len() {
            let end = bytes.len().min(offset + 4096);
            let count = handle::write_at(object.handle(), &bytes[offset..end], offset as u64)?;
            if count == 0 || count > end - offset {
                return Err(error(p::syscall::EIO));
            }
            offset += count;
        }
        Ok((object, bytes.len()))
    });
    let mut reply = [0; 16];
    match result {
        Ok((object, length)) => {
            reply[8..].copy_from_slice(&(length as u64).to_le_bytes());
            let mut handles = ipc::IpcObjectHandles::default();
            handles.count = 1;
            handles.handles[0] = ipc::IpcObjectHandle {
                handle: object.handle(),
                rights: handle::HANDLE_RIGHT_READ,
                reserved: 0,
            };
            let _ = ipc::reply_object_handles(sender, &reply, &handles);
        }
        Err(error) => {
            reply[..8].copy_from_slice(&error.raw().to_le_bytes());
            let _ = ipc::reply(sender, &reply);
        }
    }
}
