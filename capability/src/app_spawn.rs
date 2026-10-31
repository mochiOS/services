use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use mochi_user_platform as platform;

use crate::package_index::PackageIndex;
use crate::persistent_grant::has_persistent_grant;
use crate::policy::{AppPromptPolicy, needs_app_prompt};
use crate::resolver::{CapabilityDenyReason, verified_manifest};

pub(crate) const SPAWN_APP_OPCODE: u32 = 0x4150_5053;
use mochios_posix_client::launch_arguments::ENVIRONMENT_PREFIX;

#[repr(C)]
#[derive(Clone, Copy)]
struct SpawnAppRequestHeader {
    opcode: u32,
    shell_endpoint: u64,
    interactive: u8,
    reserved: [u8; 7],
}

fn parse_nul_list(
    bytes: &[u8],
    max_items: usize,
) -> Result<Vec<String>, mochi_user_syscall::SysError> {
    let mut out = Vec::new();
    for part in bytes.split(|byte| *byte == 0) {
        if part.is_empty() {
            continue;
        }
        let text = core::str::from_utf8(part).map_err(|_| {
            mochi_user_syscall::SysError::from_raw(mochi_user_syscall::EINVAL as i64)
        })?;
        out.push(text.to_string());
        if out.len() > max_items {
            return Err(mochi_user_syscall::SysError::from_raw(
                mochi_user_syscall::EINVAL as i64,
            ));
        }
    }
    Ok(out)
}

pub(crate) fn spawn_application_from_manifest(
    index: &PackageIndex,
    policy: &AppPromptPolicy,
    trusted_images: &crate::trusted_images::TrustedImages,
    sender: u64,
    buf: &[u8],
    posix_endpoint: platform::handle::Handle,
    scope: mochios_posix_client::ObjectHandleAttachment<u32>,
) -> Result<u64, mochi_user_syscall::SysError> {
    crate::persistent_grant::validate_posix_endpoint(posix_endpoint)?;
    if buf.len() <= core::mem::size_of::<SpawnAppRequestHeader>() || index.duplicate {
        return Err(mochi_user_syscall::SysError::from_raw(
            mochi_user_syscall::EINVAL as i64,
        ));
    }
    if platform::capability::check_thread(sender, "process.spawn")? == 0 {
        return Err(mochi_user_syscall::SysError::from_raw(
            mochi_user_syscall::EACCES as i64,
        ));
    }

    let header = unsafe { core::ptr::read_unaligned(buf.as_ptr().cast::<SpawnAppRequestHeader>()) };
    if header.opcode != SPAWN_APP_OPCODE {
        return Err(mochi_user_syscall::SysError::from_raw(
            mochi_user_syscall::EINVAL as i64,
        ));
    }
    let items = parse_nul_list(&buf[core::mem::size_of::<SpawnAppRequestHeader>()..], 64)?;
    let Some(entry_path) = items.first() else {
        return Err(mochi_user_syscall::SysError::from_raw(
            mochi_user_syscall::EINVAL as i64,
        ));
    };
    if !entry_path.starts_with('/') {
        return Err(mochi_user_syscall::SysError::from_raw(
            mochi_user_syscall::EINVAL as i64,
        ));
    }

    let mut spawn_items = Vec::new();
    // GUI launches establish a user environment; explicit argv/envp launches
    // below preserve the caller's environment, including an absent PATH.
    if !items[1..].iter().any(|item| {
        item.strip_prefix(ENVIRONMENT_PREFIX)
            .is_some_and(|entry| entry.starts_with("PATH="))
    }) {
        let path = core::str::from_utf8(
            mochios_posix_client::configuration::DEFAULT_EXECUTABLE_PATH,
        )
        .map_err(|_| mochi_user_syscall::SysError::from_raw(mochi_user_syscall::EINVAL as i64))?;
        spawn_items.push(format!("{ENVIRONMENT_PREFIX}PATH={path}"));
    }
    spawn_items.push(format!(
        "{}MOCHI_EXECUTABLE_PATH={}",
        ENVIRONMENT_PREFIX, entry_path
    ));
    spawn_items.push(format!(
        "{}MOCHI_SHELL_ENDPOINT={}",
        ENVIRONMENT_PREFIX, header.shell_endpoint
    ));
    spawn_items.push(format!(
        "{}MOCHI_STDIO_ENDPOINT={}",
        ENVIRONMENT_PREFIX, header.shell_endpoint
    ));
    spawn_items.push(format!(
        "{}MOCHI_PROMPT_MODE={}",
        ENVIRONMENT_PREFIX, "deny"
    ));
    spawn_items.extend(items[1..].iter().cloned());
    let arguments = crate::native_app::Arguments::legacy(entry_path, &spawn_items)?;
    spawn_authorized(
        index,
        policy,
        trusted_images,
        sender,
        &arguments,
        posix_endpoint,
        scope,
        None,
    )
}

pub(crate) fn spawn_application_with_stdio(
    index: &PackageIndex,
    policy: &AppPromptPolicy,
    trusted_images: &crate::trusted_images::TrustedImages,
    sender: u64,
    request: platform::capability::application_launch::Decoded<'_>,
    posix_endpoint: platform::handle::Handle,
    scope: mochios_posix_client::ObjectHandleAttachment<u32>,
    stdio: &crate::app_stdio::Stdio,
) -> Result<u64, mochi_user_syscall::SysError> {
    let arguments = crate::native_app::Arguments {
        path: request.path,
        arguments: request.arguments.iter().map(str::as_bytes).collect(),
        environment: request.environment.iter().map(str::as_bytes).collect(),
    };
    spawn_authorized(
        index,
        policy,
        trusted_images,
        sender,
        &arguments,
        posix_endpoint,
        scope,
        Some(stdio),
    )
}

fn spawn_authorized(
    index: &PackageIndex,
    policy: &AppPromptPolicy,
    trusted_images: &crate::trusted_images::TrustedImages,
    sender: u64,
    arguments: &crate::native_app::Arguments<'_>,
    posix_endpoint: platform::handle::Handle,
    scope: mochios_posix_client::ObjectHandleAttachment<u32>,
    stdio: Option<&crate::app_stdio::Stdio>,
) -> Result<u64, mochi_user_syscall::SysError> {
    crate::persistent_grant::validate_posix_endpoint(posix_endpoint)?;
    if index.duplicate || platform::capability::check_thread(sender, "process.spawn")? == 0 {
        return Err(mochi_user_syscall::SysError::from_raw(
            mochi_user_syscall::EACCES as i64,
        ));
    }
    let entry_path = arguments.path;
    let manifest_record = index
        .by_binary
        .get(entry_path)
        .ok_or_else(|| mochi_user_syscall::SysError::from_raw(mochi_user_syscall::ENOENT as i64))?;
    let verified = verified_manifest(
        &manifest_record.manifest_path,
        crate::persistent_grant::read_file,
    )?;
    let manifest = &verified.manifest;
    let binary = manifest
        .binary(entry_path)
        .ok_or_else(|| mochi_user_syscall::SysError::from_raw(mochi_user_syscall::EINVAL as i64))?;
    if binary.kind.as_deref() != Some("application") {
        return Err(mochi_user_syscall::SysError::from_raw(
            mochi_user_syscall::EACCES as i64,
        ));
    }

    let mut capability_decision = verified.decide_capabilities(entry_path)?;
    let requested_caps = capability_decision.requested.clone();
    let identity = &verified.identity;
    let requester_context = crate::persistent_grant::requester_context(sender)?;
    let captured =
        crate::persistent_grant::with_client(|client| client.read_scope_source_info(scope))?;
    let scope_session = crate::requester_context::scope_session(&requester_context, captured)?;
    let mut grant_context = crate::requester_context::RequesterContext::default();
    grant_context.effective_uid = scope_session.effective_uid;
    grant_context.effective_gid = scope_session.effective_gid;
    grant_context.subject_key_id = identity.subject_key_id;
    grant_context.provenance = identity.provenance as u8;
    let package_id = identity.package_id.as_bytes();
    let developer_id = identity.developer_id.as_bytes();
    if package_id.len() > grant_context.package_id.len()
        || developer_id.len() > grant_context.developer_id.len()
    {
        return Err(mochi_user_syscall::SysError::from_raw(
            mochi_user_syscall::EINVAL as i64,
        ));
    }
    grant_context.package_id_len = package_id.len() as u16;
    grant_context.developer_id_len = developer_id.len() as u16;
    grant_context.package_id[..package_id.len()].copy_from_slice(package_id);
    grant_context.developer_id[..developer_id.len()].copy_from_slice(developer_id);
    let mut user_allowed = Vec::new();
    for cap in &requested_caps {
        if platform::capability::capability_from_string(cap.as_str())
            != platform::capability::CapabilityClass::UserGrantable
        {
            user_allowed.push(cap.clone());
            continue;
        }
        if !needs_app_prompt(policy, cap) {
            user_allowed.push(cap.clone());
            continue;
        }
        if has_persistent_grant(&grant_context, cap, None) {
            user_allowed.push(cap.clone());
            continue;
        }
        // The retired scalar prompt exchange cannot prove fresh user input.
        // The asynchronous consent controller must own this continuation.
        return Err(mochi_user_syscall::SysError::from_raw(
            mochi_user_syscall::NativeError::Unsupported.into_raw() as i64,
        ));
    }
    // A caller holding process.spawn delegates launch policy to this service;
    // it is not required to possess every capability of the application it
    // launches.  The earlier process.spawn check is therefore the explicit
    // caller ceiling for this path.
    let caller_allowed = requested_caps.clone();
    capability_decision =
        capability_decision.apply_runtime_constraints(&user_allowed, &caller_allowed);
    if !capability_decision.is_allowed() {
        platform::logln!(
            "capability.service: app launch denied path={} reason={:?} denied={:?}",
            entry_path,
            capability_decision.deny_reason,
            capability_decision.denied
        );
        let errno =
            if capability_decision.deny_reason == Some(CapabilityDenyReason::UnknownCapability) {
                mochi_user_syscall::EINVAL
            } else {
                mochi_user_syscall::EACCES
            };
        return Err(mochi_user_syscall::SysError::from_raw(errno as i64));
    }
    let caps = capability_decision.effective;
    crate::native_app::launch(
        trusted_images,
        arguments,
        posix_endpoint,
        sender,
        requester_context.process_id,
        scope,
        verified,
        &caps,
        stdio,
        |package_id| {
            let record = index.by_package.get(package_id).ok_or_else(|| {
                mochi_user_syscall::SysError::from_raw(mochi_user_syscall::ENOENT as i64)
            })?;
            verified_manifest(&record.manifest_path, crate::persistent_grant::read_file)
        },
    )
}

// Early service bootstrap still uses the legacy metadata encoder until its
// independent launch path is migrated. Application creation never uses it.
