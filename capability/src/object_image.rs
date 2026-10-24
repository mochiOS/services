//! Path-independent, attenuating image authorization from explicit IPC objects.
use mochi_user_platform as platform;
use mochi_user_syscall::{EACCES, EINVAL, EIO, SysError};
use sha2::{Digest, Sha256};

pub(crate) fn authorize(
    sender: u64,
    request: &[u8],
    attached: &platform::ipc::IpcObjectHandles,
) -> Result<(), SysError> {
    let identity = platform::capability::decode_authorize_exec_object_request(request)
        .map_err(|_| SysError::from_raw(EINVAL as i64))?;
    if !attached.is_user_delivery() || attached.count != 1 {
        return Err(SysError::from_raw(EINVAL as i64));
    }
    let image = attached.handles[0];
    if image.handle == 0 || image.reserved != 0 {
        return Err(SysError::from_raw(EINVAL as i64));
    }
    if image.rights != platform::handle::HANDLE_RIGHT_READ
        || platform::capability::check_thread(sender, "process.spawn") != Ok(1)
    {
        return Err(SysError::from_raw(EACCES as i64));
    }
    let digest = digest_image(image.handle)?;
    use mnu_abi::exec::{
        EXEC_AUTHORIZATION_CLASS_PREFIX, EXEC_AUTHORIZATION_KIND_IMAGE_REPLACE_INHERIT,
        EXEC_AUTHORIZATION_KIND_PREFIX, EXECUTABLE_DIGEST_PREFIX,
    };
    // The native inheritance mode accepts no identity override or grant list.
    // No package index, path reopen, ambient file access or signer assertion is
    // needed: this is a new image within the caller's existing security domain.
    let mut fields = alloc::format!(
        "{EXEC_AUTHORIZATION_KIND_PREFIX}{EXEC_AUTHORIZATION_KIND_IMAGE_REPLACE_INHERIT}\0{EXEC_AUTHORIZATION_CLASS_PREFIX}unprivileged\0{EXECUTABLE_DIGEST_PREFIX}"
    );
    for byte in digest {
        use core::fmt::Write;
        let _ = write!(fields, "{byte:02x}");
    }
    fields.push('\0');
    fields.push('\0');
    platform::service::authorize_exec_for_requester(sender, identity, fields.as_bytes(), &[])
        .map(|_| ())
}

fn digest_image(image: u32) -> Result<[u8; 32], SysError> {
    const MAX_IMAGE_BYTES: u64 = 64 * 1024 * 1024;
    let mut digest = Sha256::new();
    let mut offset = 0;
    let mut bytes = [0; mnu_abi::provider::MAX_DATA_LEN];
    loop {
        let count = platform::handle::read_at(image, &mut bytes, offset)?;
        if count > bytes.len() {
            return Err(SysError::from_raw(EIO as i64));
        }
        if count == 0 {
            return Ok(digest.finalize().into());
        }
        offset = offset
            .checked_add(count as u64)
            .filter(|offset| *offset <= MAX_IMAGE_BYTES)
            .ok_or_else(|| SysError::from_raw(mochios_posix_protocol::STATUS_EFBIG as i64))?;
        digest.update(&bytes[..count]);
    }
}
