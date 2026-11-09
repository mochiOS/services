//! Metadata from an authenticated image authorizer. The attached Process is
//! the subject; an asserted PID never selects another process's report.
use mochi_user_platform as p;
use serde_json::{Value, json};

fn denied() -> p::syscall::SysError {
    p::syscall::SysError::from_raw(p::syscall::EACCES as i64)
}
fn hash(value: &Value) -> Option<&str> {
    value.as_str().filter(|text| {
        text.len() == 64
            && text
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn receive(
    sender: u64,
    request: &[u8],
    attached: &p::ipc::IpcObjectHandles,
) -> p::syscall::SysResult<()> {
    if request.len() != 16
        || &request[..8] != p::diagnostic::IMAGE_METADATA_OPCODE
        || !attached.is_user_delivery()
        || attached.count != 2
        || p::capability::check_thread(sender, "capabilities.manage") != Ok(1)
    {
        return Err(denied());
    }
    let process = attached.handles[0];
    let metadata = attached.handles[1];
    if process.handle == 0
        || metadata.handle == 0
        || process.reserved != 0
        || metadata.reserved != 0
        || process.rights != p::handle::HANDLE_RIGHT_WAIT
        || metadata.rights != p::handle::HANDLE_RIGHT_READ
    {
        return Err(denied());
    }
    let length = usize::try_from(u64::from_le_bytes(
        request[8..].try_into().map_err(|_| denied())?,
    ))
    .map_err(|_| denied())?;
    if length == 0 || length > p::diagnostic::MAX_IMAGE_METADATA_BYTES {
        return Err(denied());
    }
    let before = p::process::image_info(Some(process.handle))?;
    let mut bytes = vec![0; length];
    let mut offset = 0;
    while offset < length {
        let end = length.min(offset + 4096);
        let count = p::handle::read_at(metadata.handle, &mut bytes[offset..end], offset as u64)?;
        if count == 0 || count > length - offset {
            return Err(denied());
        }
        offset += count;
    }
    let body: Value = serde_json::from_slice(&bytes).map_err(|_| denied())?;
    let revision = body["image_revision"].as_u64().ok_or_else(denied)?;
    let digest = hash(&body["native_image_sha256"]).ok_or_else(denied)?;
    // Prospective replacement metadata is usable only if a later native exit
    // independently reports this exact revision and digest. No authority is
    // conferred by recording it, even if the prepared exec never commits.
    if body["schema_version"] != 1
        || before != p::process::image_info(Some(process.handle))?
        || p::capability::check_thread(sender, "capabilities.manage") != Ok(1)
        || !((revision == before.image_revision && digest == hex(&before.digest))
            || before.image_revision.checked_add(1) == Some(revision))
    {
        return Err(denied());
    }
    let package = body["package_id"]
        .as_str()
        .filter(|s| !s.is_empty() && s.len() <= 256)
        .ok_or_else(denied)?;
    let modules = body["modules"]
        .as_array()
        .filter(|v| v.len() <= 128)
        .ok_or_else(denied)?;
    for module in modules {
        hash(&module["source_sha256"]).ok_or_else(denied)?;
        let path = module["path"]
            .as_str()
            .filter(|s| s.starts_with('/') && s.len() <= 4096 && !s.contains(['\0', '\\']))
            .ok_or_else(denied)?;
        if path[1..]
            .split('/')
            .any(|s| s.is_empty() || matches!(s, "." | ".."))
        {
            return Err(denied());
        }
        module["load_bias"].as_u64().ok_or_else(denied)?;
        let ranges = module["ranges"]
            .as_array()
            .filter(|v| v.len() <= 64)
            .ok_or_else(denied)?;
        for range in ranges {
            let start = range["start"].as_u64().ok_or_else(denied)?;
            let end = range["end"].as_u64().ok_or_else(denied)?;
            let flags = range["flags"].as_u64().ok_or_else(denied)?;
            if start > end || end > 0x8000_0000_0000 || flags & !7 != 0 {
                return Err(denied());
            }
        }
    }
    let package_name = body["package_name"]
        .as_str()
        .filter(|s| s.len() <= 256)
        .ok_or_else(denied)?;
    let package_version = body["package_version"]
        .as_str()
        .filter(|s| s.len() <= 128)
        .ok_or_else(denied)?;
    let normalized = json!({"schema_version":1, "evidence":"authenticated_launcher",
        "process_id":before.process_id, "image_revision":revision, "native_image_sha256":digest,
        "package_id":package, "modules":modules,
        "package_name":package_name, "package_version":package_version,
        "initial_modules_complete":body["initial_modules_complete"].as_bool().ok_or_else(denied)?,
        "later_dynamic_loads_captured":false});
    let bytes = serde_json::to_vec(&normalized).map_err(|_| denied())?;
    let name = crate::crash::image_name(
        crate::crash::session_id()?,
        before.process_id,
        revision,
        digest,
    );
    crate::report_storage::Directory::open("images")?.store(&name, &bytes, 256)
}
