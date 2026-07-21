use alloc::vec::Vec;
use core::convert::TryInto;

use mochi_user_platform as platform;
use mochi_user_syscall as syscall;
use sha2::{Digest, Sha256};

use crate::package_index::PackageIndex;
use crate::persistent_grant::append_persistent_grant;
use crate::policy::is_known_capability;
use crate::resolver::binary_caps;

fn current_process_id() -> Result<u64, mochi_user_syscall::SysError> {
    syscall::call0(syscall::SyscallNumber::GetPid)
}

pub(crate) fn prompt_shell_for_capability(
    shell_endpoint: u64,
    executable: &str,
    capability: &str,
    reason: &str,
) -> Result<(), mochi_user_syscall::SysError> {
    if shell_endpoint == 0 {
        return Err(mochi_user_syscall::SysError::from_raw(
            mochi_user_syscall::EACCES as i64,
        ));
    }
    if executable.len() > 256 || capability.len() > 64 || reason.len() > 128 {
        return Err(mochi_user_syscall::SysError::from_raw(
            mochi_user_syscall::EINVAL as i64,
        ));
    }

    let process_id = current_process_id()?;
    let request = platform::capability::CapabilityRequest::new_prompt(
        process_id,
        executable,
        [0; 32],
        capability,
        None,
        Some(reason),
        true,
        platform::capability::CapabilityClass::UserGrantable,
    )
    .map_err(|_| mochi_user_syscall::SysError::from_raw(mochi_user_syscall::EINVAL as i64))?;

    let mut reply = [0u8; 8];
    let msg = syscall::call5(
        syscall::SyscallNumber::IpcCall,
        shell_endpoint,
        (&request as *const platform::capability::CapabilityRequest) as u64,
        core::mem::size_of::<platform::capability::CapabilityRequest>() as u64,
        reply.as_mut_ptr() as u64,
        reply.len() as u64,
    )?;
    if (msg & 0xffff_ffff) < 4 {
        return Err(mochi_user_syscall::SysError::from_raw(
            mochi_user_syscall::EINVAL as i64,
        ));
    }
    let decision =
        u32::from_le_bytes(reply[..4].try_into().map_err(|_| {
            mochi_user_syscall::SysError::from_raw(mochi_user_syscall::EINVAL as i64)
        })?);
    if decision == platform::capability::CapabilityDecision::AllowOnce as u32
        || decision == platform::capability::CapabilityDecision::AllowForProcess as u32
        || decision == platform::capability::CapabilityDecision::AllowPersistently as u32
        || decision == platform::capability::CapabilityDecision::AllowAllUserGrantable as u32
    {
        Ok(())
    } else {
        Err(mochi_user_syscall::SysError::from_raw(
            mochi_user_syscall::EACCES as i64,
        ))
    }
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

pub(crate) fn authorize_dynamic_capability(
    index: &PackageIndex,
    decision: platform::capability::CapabilityDecision,
    requester_thread: u64,
    request: &platform::capability::CapabilityRequest,
) -> Result<(), mochi_user_syscall::SysError> {
    if request.opcode != platform::capability::CAPABILITY_PROMPT_OPCODE
        || request.process_id == 0
        || requester_thread == 0
        || request.interactive == 0
    {
        return Err(mochi_user_syscall::SysError::from_raw(
            mochi_user_syscall::EINVAL as i64,
        ));
    }
    if decision == platform::capability::CapabilityDecision::Deny {
        return Err(mochi_user_syscall::SysError::from_raw(
            mochi_user_syscall::EACCES as i64,
        ));
    }
    if request.capability_class != platform::capability::CapabilityClass::UserGrantable {
        return Err(mochi_user_syscall::SysError::from_raw(
            mochi_user_syscall::EACCES as i64,
        ));
    }

    let executable = read_request_str(&request.executable.path, request.executable.path_len)?;
    let mut digest = [0u8; 32];
    let needs_digest = request.executable.digest != [0; 32]
        || matches!(
            decision,
            platform::capability::CapabilityDecision::AllowPersistently
                | platform::capability::CapabilityDecision::AllowAllUserGrantable
        );
    if needs_digest {
        let executable_bytes = platform::file::read_to_end_path(executable)?;
        let actual_digest = Sha256::digest(&executable_bytes);
        digest.copy_from_slice(&actual_digest);
        if request.executable.digest != [0; 32] && request.executable.digest != digest {
            return Err(mochi_user_syscall::SysError::from_raw(
                mochi_user_syscall::EACCES as i64,
            ));
        }
    }

    let capability = read_request_str(&request.capability, request.capability_len)?;
    if !is_known_capability(capability)
        || platform::capability::capability_from_string(capability)
            != platform::capability::CapabilityClass::UserGrantable
    {
        return Err(mochi_user_syscall::SysError::from_raw(
            mochi_user_syscall::EACCES as i64,
        ));
    }
    if let Some(record) = index.by_binary.get(executable) {
        let manifest =
            platform::package::read_manifest(&record.manifest_path).ok_or_else(|| {
                mochi_user_syscall::SysError::from_raw(mochi_user_syscall::EINVAL as i64)
            })?;
        let declared_caps = binary_caps(&manifest, executable)?;
        if !declared_caps.iter().any(|cap| cap.as_str() == capability) {
            return Err(mochi_user_syscall::SysError::from_raw(
                mochi_user_syscall::EACCES as i64,
            ));
        }
    }
    if matches!(
        decision,
        platform::capability::CapabilityDecision::AllowPersistently
            | platform::capability::CapabilityDecision::AllowAllUserGrantable
    ) {
        let resource = if request.resource.path_len == 0 {
            None
        } else {
            Some(read_request_str(
                &request.resource.path,
                request.resource.path_len,
            )?)
        };
        append_persistent_grant(
            executable,
            &digest,
            capability,
            resource,
            decision == platform::capability::CapabilityDecision::AllowAllUserGrantable,
        )?;
    }

    transfer_user_grant(requester_thread, capability, executable)
}
