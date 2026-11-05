//! Path-independent, attenuating image authorization from explicit IPC objects.
use mochi_user_platform as platform;
use mochi_user_syscall::{EACCES, EINVAL, SysError};

pub(crate) fn authorize(
    state: &crate::state::CapabilityServiceState,
    sender: u64,
    request: &[u8],
    attached: &platform::ipc::IpcObjectHandles,
) -> Result<(), SysError> {
    prepare(sender, request, attached)?.authorize(state)
}

pub(crate) struct Source<'a> {
    sender: u64,
    handle: u32,
    length: u64,
    digest: [u8; 32],
    key: &'a str,
}
impl<'a> Source<'a> {
    pub(crate) fn length(&self) -> u64 {
        self.length
    }
    pub(crate) fn authorize(
        self,
        state: &crate::state::CapabilityServiceState,
    ) -> Result<(), SysError> {
        self.captured(state)?.authorize(&state.app_prompt_policy)
    }
    pub(crate) fn captured(
        self,
        state: &crate::state::CapabilityServiceState,
    ) -> Result<crate::signed_image::Captured<'a>, SysError> {
        let snapshot = crate::signed_image::capture(self.handle, self.length)?;
        use sha2::{Digest, Sha256};
        if <[u8; 32]>::from(Sha256::digest(&snapshot)) != self.digest {
            return Err(SysError::from_raw(EACCES as i64));
        }
        let selection = crate::signed_image::select_snapshot(state, None, &snapshot)?;
        Ok(crate::signed_image::Captured {
            selection,
            source: snapshot,
            sender: self.sender,
            key: self.key,
        })
    }
}

pub(crate) fn prepare<'a>(
    sender: u64,
    request: &'a [u8],
    attached: &platform::ipc::IpcObjectHandles,
) -> Result<Source<'a>, SysError> {
    let (digest, identity) = platform::capability::decode_authorize_exec_object_request(request)
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
    // The legacy transport's digest is only a consistency hint. Query RAM
    // backing before any read; arbitrary Providers cannot enter this broker.
    let length = platform::memory::object_length(u64::from(image.handle))?;
    Ok(Source {
        sender,
        handle: image.handle,
        length,
        digest,
        key: identity,
    })
}

/// The native layer captures the authenticated sender's current identity,
/// measured image and ordinary grants; the opaque key only binds the one-shot.
pub(crate) fn authorize_captured(sender: u64, request: &[u8]) -> Result<(), SysError> {
    let identity = platform::capability::decode_authorize_captured_image_request(request)
        .map_err(|_| SysError::from_raw(EINVAL as i64))?;
    if platform::capability::check_thread(sender, "process.spawn") != Ok(1) {
        return Err(SysError::from_raw(EACCES as i64));
    }
    use mnu_abi::exec::{
        EXEC_AUTHORIZATION_CLASS_PREFIX, EXEC_AUTHORIZATION_KIND_PREFIX,
        EXEC_AUTHORIZATION_KIND_SPAWN_INHERIT,
    };
    let fields = alloc::format!(
        "{EXEC_AUTHORIZATION_KIND_PREFIX}{EXEC_AUTHORIZATION_KIND_SPAWN_INHERIT}\0{EXEC_AUTHORIZATION_CLASS_PREFIX}unprivileged\0\0"
    );
    platform::service::authorize_exec_for_requester(sender, identity, fields.as_bytes(), &[])
        .map(|_| ())
}
