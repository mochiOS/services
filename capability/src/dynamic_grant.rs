use alloc::vec::Vec;

use mochi_user_platform as platform;

pub(crate) fn is_trusted_prompt_broker(
    trusted: &crate::trusted_images::TrustedImages,
    endpoint: u64,
) -> bool {
    use crate::trusted_images::Role;
    crate::consent_peer::capture(endpoint)
        .and_then(|peer| trusted.role(&peer))
        .is_ok_and(|role| matches!(role, Some(Role::TextPrompt | Role::Workspace)))
}

pub(crate) fn is_trusted_workspace(
    trusted: &crate::trusted_images::TrustedImages,
    endpoint: u64,
) -> bool {
    crate::consent_peer::capture(endpoint)
        .and_then(|peer| trusted.role(&peer))
        .is_ok_and(|role| role == Some(crate::trusted_images::Role::Workspace))
}

/// Legacy scalar decisions carry no transaction or independent input evidence.
/// Retire the synchronous exchange before enabling verified text frontends.
pub(crate) fn prompt_shell_for_capability(
    _shell_endpoint: u64,
    _executable: &str,
    _capability: &str,
    _reason: &str,
) -> Result<platform::capability::CapabilityDecision, mochi_user_syscall::SysError> {
    Err(mochi_user_syscall::SysError::from_raw(
        mochi_user_syscall::NativeError::Unsupported.into_raw() as i64,
    ))
}

pub(crate) fn transfer_user_grant(
    requester_thread: u64,
    capability: &str,
    executable: &str,
) -> Result<(), mochi_user_syscall::SysError> {
    let mut payload = Vec::with_capacity(capability.len() + 1 + executable.len());
    payload.extend_from_slice(capability.as_bytes());
    payload.push(0x1f);
    payload.extend_from_slice(executable.as_bytes());
    platform::syscall::call3(
        platform::syscall::SyscallNumber::CapTransfer,
        requester_thread,
        payload.as_ptr() as u64,
        payload.len() as u64,
    )
    .map(|_| ())
}

pub(crate) fn validate_grant_resource(
    capability: &str,
    resource: Option<&str>,
) -> Result<(), mochi_user_syscall::SysError> {
    // A path string is not object authority. The retired kernel registry had
    // no access-control consumer; it must not report a fictitious grant or
    // fall back to a process-wide file capability. A FileHandle broker is
    // required before resource-scoped file permissions can be authorized.
    if resource.is_some() && matches!(capability, "fs.read.user" | "fs.write.user") {
        return Err(mochi_user_syscall::SysError::from_raw(
            mochi_user_syscall::NativeError::Unsupported.into_raw() as i64,
        ));
    }
    Ok(())
}

pub(crate) fn read_request_str(
    bytes: &[u8],
    len: u16,
) -> Result<&str, mochi_user_syscall::SysError> {
    let len = len as usize;
    if len > bytes.len() {
        return Err(mochi_user_syscall::SysError::from_raw(
            mochi_user_syscall::EINVAL as i64,
        ));
    }
    core::str::from_utf8(&bytes[..len])
        .map_err(|_| mochi_user_syscall::SysError::from_raw(mochi_user_syscall::EINVAL as i64))
}
