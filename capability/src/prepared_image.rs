//! Trusted launchers receive only the bytes authorized for this IPC caller.
//! Neither filesystem discovery nor executable pathname policy enters mnu.

use mochi_user_platform as platform;
use platform::syscall::{EACCES, EINVAL, EIO, ENOENT, SysError};

pub(crate) fn prepare(
    state: &crate::state::CapabilityServiceState,
    sender: u64,
    class: u64,
    path: &str,
    read: crate::resolver::FileReader,
) -> Result<platform::memory_object::MemoryObject, SysError> {
    // This API exposes image bytes, not merely an execute permit. Require
    // read-all authority before any read, and restrict it to trusted brokers.
    for capability in ["capabilities.manage", "fs.read.all", "process.spawn"] {
        if platform::capability::check_thread(sender, capability) != Ok(1) {
            return Err(SysError::from_raw(EACCES as i64));
        }
    }
    let class = platform::service::ExecutionClass::from_raw(class)
        .ok_or(SysError::from_raw(EINVAL as i64))?;
    let record = state
        .package_index
        .by_binary
        .get(path)
        .ok_or(SysError::from_raw(ENOENT as i64))?;
    let caps = crate::resolver::binary_caps(&record.manifest, &record.manifest_path, path, read)?;
    let identity =
        crate::resolver::application_identity(&record.manifest, &record.manifest_path, read)?;
    let bytes = read(path)?;
    if bytes.len() > 64 * 1024 * 1024 {
        return Err(SysError::from_raw(mochios_posix_protocol::STATUS_EFBIG as i64));
    }
    let image = platform::memory_object::MemoryObject::create_resizable(bytes.len() as u64)?;
    let mut written = 0;
    while written < bytes.len() {
        let count = platform::handle::write_at(image.handle(), &bytes[written..], written as u64)?;
        if count == 0 || count > bytes.len() - written {
            return Err(SysError::from_raw(EIO as i64));
        }
        written += count;
    }
    crate::resolver::authorize_spawn_image(sender, path, &identity, caps, class, &bytes)?;
    Ok(image)
}
