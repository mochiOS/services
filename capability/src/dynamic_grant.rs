use alloc::vec::Vec;
use core::convert::TryInto;

use mochi_user_platform as platform;
use mochi_user_syscall as syscall;
use sha2::{Digest, Sha256};

use crate::package_index::PackageIndex;
use crate::persistent_grant::append_persistent_grant;
use crate::policy::is_known_capability;
use crate::resolver::binary_caps;

const TRUSTED_PROMPT_PACKAGE_ID: &[u8] = b"org.mochios.msh";
const TRUSTED_WORKSPACE_PACKAGE_ID: &[u8] = b"org.mochios.workspace";
const BUILT_IN_DEVELOPER_ID: &[u8] = b"org.mochios.system";
const BUILT_IN_PROVENANCE: u8 = 1;

pub(crate) fn is_trusted_prompt_broker(endpoint: u64) -> bool {
    trusted_broker_package(endpoint).is_some()
}

pub(crate) fn is_trusted_workspace(endpoint: u64) -> bool {
    trusted_broker_package(endpoint) == Some(TRUSTED_WORKSPACE_PACKAGE_ID)
}

fn trusted_broker_package(endpoint: u64) -> Option<&'static [u8]> {
    let Ok(context) = platform::process::thread_security_context(endpoint) else {
        return None;
    };
    let package_len = context.package_id_len as usize;
    let developer_len = context.developer_id_len as usize;
    let trusted_identity = package_len <= context.package_id.len()
        && developer_len <= context.developer_id.len()
        && &context.developer_id[..developer_len] == BUILT_IN_DEVELOPER_ID
        && context.subject_key_id == [0; 32]
        && context.provenance == BUILT_IN_PROVENANCE;
    if !trusted_identity {
        return None;
    }
    let package = &context.package_id[..package_len];
    if package == TRUSTED_PROMPT_PACKAGE_ID {
        Some(TRUSTED_PROMPT_PACKAGE_ID)
    } else if package == TRUSTED_WORKSPACE_PACKAGE_ID {
        Some(TRUSTED_WORKSPACE_PACKAGE_ID)
    } else {
        None
    }
}

fn current_process_id() -> Result<u64, mochi_user_syscall::SysError> {
    syscall::call0(syscall::SyscallNumber::GetPid)
}

pub(crate) fn prompt_shell_for_capability(
    shell_endpoint: u64,
    executable: &str,
    capability: &str,
    reason: &str,
) -> Result<platform::capability::CapabilityDecision, mochi_user_syscall::SysError> {
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
    match decision {
        value if value == platform::capability::CapabilityDecision::AllowOnce as u32 => {
            Ok(platform::capability::CapabilityDecision::AllowOnce)
        }
        value if value == platform::capability::CapabilityDecision::AllowForProcess as u32 => {
            Ok(platform::capability::CapabilityDecision::AllowForProcess)
        }
        value if value == platform::capability::CapabilityDecision::AllowPersistently as u32 => {
            Ok(platform::capability::CapabilityDecision::AllowPersistently)
        }
        value if value
            == platform::capability::CapabilityDecision::AllowAllUserGrantable as u32 =>
        {
            Ok(platform::capability::CapabilityDecision::AllowAllUserGrantable)
        }
        _ => Err(mochi_user_syscall::SysError::from_raw(
            mochi_user_syscall::EACCES as i64,
        )),
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

pub(crate) fn transfer_scoped_path_grant(
    requester_thread: u64,
    path: &str,
    writable: bool,
    executable: &str,
) -> Result<(), mochi_user_syscall::SysError> {
    if path.is_empty() || path.len() > 4095 || path.as_bytes().contains(&0) {
        return Err(mochi_user_syscall::SysError::from_raw(
            mochi_user_syscall::EINVAL as i64,
        ));
    }
    let mode = if writable { "read-write" } else { "read" };
    let mut payload = Vec::with_capacity(16 + path.len() + executable.len());
    payload.extend_from_slice(b"fs.scope.");
    payload.extend_from_slice(mode.as_bytes());
    payload.push(b'@');
    payload.extend_from_slice(path.as_bytes());
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
    let context = platform::process::thread_security_context(requester_thread)?;
    if context.process_id != request.process_id {
        return Err(mochi_user_syscall::SysError::from_raw(
            mochi_user_syscall::EACCES as i64,
        ));
    }
    if decision == platform::capability::CapabilityDecision::Deny {
        return Err(mochi_user_syscall::SysError::from_raw(
            mochi_user_syscall::EACCES as i64,
        ));
    }
    // A named process capability has no single-operation consumption point.
    // Treating AllowOnce as a process-lifetime transfer would silently widen
    // the user's decision. One-shot grants are therefore valid only for the
    // launch gate or for a future operation-specific authority protocol.
    if decision == platform::capability::CapabilityDecision::AllowOnce {
        return Err(mochi_user_syscall::SysError::from_raw(
            mochi_user_syscall::ENOTSUP as i64,
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
    let record = index.by_binary.get(executable).ok_or_else(|| {
        mochi_user_syscall::SysError::from_raw(mochi_user_syscall::EACCES as i64)
    })?;
    let manifest = platform::package::read_manifest(&record.manifest_path).ok_or_else(|| {
        mochi_user_syscall::SysError::from_raw(mochi_user_syscall::EINVAL as i64)
    })?;
    let declared_caps = binary_caps(&manifest, &record.manifest_path, executable)?;
    if !declared_caps.iter().any(|cap| cap.as_str() == capability) {
        return Err(mochi_user_syscall::SysError::from_raw(
            mochi_user_syscall::EACCES as i64,
        ));
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
            &context,
            capability,
            resource,
            decision == platform::capability::CapabilityDecision::AllowAllUserGrantable,
        )?;
    }

    let resource = if request.resource.path_len == 0 {
        None
    } else {
        Some(read_request_str(
            &request.resource.path,
            request.resource.path_len,
        )?)
    };
    match (capability, resource) {
        ("fs.read.user", Some(path)) => {
            transfer_scoped_path_grant(requester_thread, path, false, executable)
        }
        ("fs.write.user", Some(path)) => {
            transfer_scoped_path_grant(requester_thread, path, true, executable)
        }
        _ => transfer_user_grant(requester_thread, capability, executable),
    }
}
