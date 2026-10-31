use alloc::string::String;
use alloc::vec::Vec;

use mochi_user_platform as platform;
use sha2::{Digest, Sha256};

use crate::app_spawn::{SPAWN_APP_OPCODE, spawn_application_from_manifest};
use crate::persistent_grant::{
    authorize_persistent_capability, has_persistent_grant, install_posix_endpoint,
};
use crate::policy::needs_app_prompt;
use crate::resolver::{
    CapabilityDenyReason, application_identity, authorize_spawn, binary_caps,
    decide_binary_capabilities, encode_exec_authorization_args, encode_identity_args,
    encode_nul_list, resolve_capabilities_for_path,
};
use crate::state::CapabilityServiceState;

const REPLY_OK: u64 = 0;

// This protocol carries positive POSIX wire errors, not native mechanism tags
// or newlib C errno values. Only successful replies may carry zero.
fn error_status(error: mochi_user_syscall::SysError) -> u64 {
    u64::from(mochios_posix_protocol::status::normalize_failure(error.raw()).unsigned_abs())
}

fn capability_reply(sender: u64, status: u64) {
    let status = if status == REPLY_OK {
        REPLY_OK
    } else {
        error_status(mochi_user_syscall::SysError::from_raw(status as i64))
    };
    let _ = platform::ipc::reply(sender, &status.to_le_bytes());
}

fn close_received_handles(handles: &platform::ipc::IpcObjectHandles) {
    let count = core::cmp::min(handles.count as usize, handles.handles.len());
    for attached in &handles.handles[..count] {
        if attached.handle != 0 {
            let _ = platform::handle::close(attached.handle);
        }
    }
}

fn reply_capabilities(sender: u64, result: Result<Vec<String>, mochi_user_syscall::SysError>) {
    let (status, capabilities) = match result {
        Ok(caps) => (REPLY_OK, encode_nul_list(&caps)),
        Err(err) => {
            let status = error_status(err);
            (status, Vec::new())
        }
    };
    let reply = platform::capability::encode_resolve_capabilities_reply(status, &capabilities);
    let _ = platform::ipc::reply(sender, &reply);
}

fn reply_execution_security(
    sender: u64,
    result: Result<(Vec<String>, Vec<String>), mochi_user_syscall::SysError>,
) {
    let (status, identity, capabilities) = match result {
        Ok((identity, capabilities)) => (
            REPLY_OK,
            encode_nul_list(&identity),
            encode_nul_list(&capabilities),
        ),
        Err(error) => (error_status(error), Vec::new(), Vec::new()),
    };
    let reply = platform::capability::encode_resolve_execution_security_reply(
        status,
        &identity,
        &capabilities,
    );
    match reply {
        Ok(reply) => {
            let _ = platform::ipc::reply(sender, &reply);
        }
        Err(_) => capability_reply(sender, mochi_user_syscall::EINVAL),
    }
}

fn reply_spawn(sender: u64, result: Result<u64, mochi_user_syscall::SysError>) {
    let mut reply = [0u8; 16];
    match result {
        Ok(pid) => {
            reply[..8].copy_from_slice(&0u64.to_le_bytes());
            reply[8..16].copy_from_slice(&pid.to_le_bytes());
        }
        Err(err) => {
            reply[..8].copy_from_slice(&error_status(err).to_le_bytes());
        }
    }
    let _ = platform::ipc::reply(sender, &reply);
}

fn parse_persistent_query(
    buf: &[u8],
) -> Result<platform::capability::CapabilityRequest, mochi_user_syscall::SysError> {
    platform::capability::decode_request(buf)
        .map_err(|_| mochi_user_syscall::SysError::from_raw(mochi_user_syscall::EINVAL as i64))
}

pub(crate) fn serve_capability_requests(mut state: CapabilityServiceState) -> ! {
    // Service startup needs authorization before the POSIX endpoint exists.
    // The authenticated handoff below switches this phase permanently; a
    // runtime read failure must never retry through the bootstrap path.
    let mut authorization_reader: crate::resolver::FileReader = crate::bootstrap_file::read_file;
    let endpoint = match platform::ipc::create() {
        Ok(endpoint) => endpoint,
        Err(err) => {
            platform::logln!(
                "capability.service: endpoint create failed errno={}",
                err.errno().unwrap_or(0)
            );
            platform::process::exit(1);
        }
    };
    platform::logln!("capability.service: ready");
    let mut buf = [0u8; 1024];
    let mut input_authority: Option<crate::consent_input::Channel> = None;
    let mut display_authority: Option<crate::consent_presentation::Channel> = None;
    let mut desktop_sessions = crate::consent_presentation::Sessions::default();
    #[cfg(mochios_presentation_probe_307)]
    let mut presentation_probe: Option<crate::presentation_probe::Probe> = None;
    #[cfg(mochios_consent_input_probe_306)]
    let mut input_probe: Option<crate::consent_input_probe::Probe> = None;
    loop {
        let mut attached = platform::ipc::IpcObjectHandles::default();
        let msg = match platform::ipc::wait_object_handles(endpoint, &mut buf, &mut attached) {
            Ok(msg) => msg,
            Err(_) => {
                platform::thread::yield_now();
                continue;
            }
        };
        let sender = msg >> 32;
        let len = (msg & 0xffff_ffff) as usize;
        let slice = &buf[..len.min(buf.len())];
        let opcode = if slice.len() >= 4 {
            u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]])
        } else {
            0
        };
        #[cfg(mochios_presentation_probe_307)]
        if matches!(
            opcode,
            crate::presentation_probe::HELLO | crate::presentation_probe::STATUS
        ) {
            let result = (|| {
                if slice.len() != 4 || attached.count != 0 || !attached.is_user_delivery() {
                    return Err(mochi_user_syscall::SysError::from_raw(-22));
                }
                let channel = display_authority.as_ref()
                    .ok_or_else(|| mochi_user_syscall::SysError::from_raw(-13))?;
                if opcode == crate::presentation_probe::HELLO {
                    if presentation_probe.is_some() {
                        return Err(mochi_user_syscall::SysError::from_raw(-16));
                    }
                    let (probe, reply) = crate::presentation_probe::Probe::begin(
                        sender, &state.trusted_images, channel,
                    )?;
                    presentation_probe = Some(probe);
                    Ok(reply)
                } else {
                    presentation_probe.as_ref()
                        .ok_or_else(|| mochi_user_syscall::SysError::from_raw(-2))?
                        .status(sender, &state.trusted_images, channel)
                }
            })();
            close_received_handles(&attached);
            match result {
                Ok(reply) => { let _ = platform::ipc::reply(sender, &reply); }
                Err(error) => capability_reply(sender, error_status(error)),
            }
            continue;
        }
        #[cfg(mochios_process_domain_probe_308)]
        if opcode == u32::from_le_bytes(*b"DM08") {
            let result = (|| {
                if slice.len() != 4 || attached.count != 0 || !attached.is_user_delivery() {
                    return Err(mochi_user_syscall::SysError::from_raw(-22));
                }
                let requester = crate::consent_peer::capture(sender)?;
                let channel = display_authority.as_ref()
                    .ok_or_else(|| mochi_user_syscall::SysError::from_raw(-13))?;
                desktop_sessions.authenticate_member(channel, &requester)?;
                if state.trusted_images.role(&requester)? != Some(crate::trusted_images::Role::TextPrompt) {
                    return Err(mochi_user_syscall::SysError::from_raw(-13));
                }
                Ok(())
            })();
            close_received_handles(&attached);
            capability_reply(sender, result.err().map_or(0, error_status));
            continue;
        }
        if opcode == platform::capability::presentation::SESSION_OPCODE {
            let result = (|| {
                if !attached.is_user_delivery() {
                    return Err(mochi_user_syscall::SysError::from_raw(
                        mochi_user_syscall::EACCES as i64,
                    ));
                }
                let context =
                    platform::capability::presentation::decode_session(slice).map_err(|_| {
                        mochi_user_syscall::SysError::from_raw(mochi_user_syscall::EINVAL as i64)
                    })?;
                let domain = if context.active {
                    if attached.count != 1 || attached.handles[0].handle == 0
                        || attached.handles[0].reserved != 0
                        || attached.handles[0].rights != platform::handle::HANDLE_RIGHT_TRANSFER
                    { return Err(mochi_user_syscall::SysError::from_raw(-22)); }
                    let domain = crate::consent_presentation::DomainReference(attached.handles[0].handle);
                    attached.handles[0] = Default::default();
                    attached.count = 0;
                    Some(domain)
                } else {
                    if attached.count != 0 { return Err(mochi_user_syscall::SysError::from_raw(-22)); }
                    None
                };
                // Revoke pending observations before any remote publication.
                // No renderer reply can keep a previous session alive.
                let generation = state.authorization_generation;
                desktop_sessions.publish(
                    sender,
                    context,
                    domain,
                    &state.trusted_images,
                    &mut display_authority,
                    || {
                        state.consent.observe(
                            |_, _, _| crate::consent::Current {
                                requester: None,
                                presenter: None,
                                input: None,
                                session: None,
                                policy_generation: generation,
                                foreground: false,
                            },
                            |_, _| {},
                        );
                        if let Some(channel) = input_authority.as_mut() {
                            let _ = channel.cancel();
                        }
                    },
                )?;
                Ok(())
            })();
            close_received_handles(&attached);
            capability_reply(sender, result.err().map_or(0, error_status));
            continue;
        }
        #[cfg(mochios_consent_input_probe_306)]
        if opcode == crate::consent_input_probe::START {
            if slice.len() != 4
                || attached.count != 0
                || !attached.is_user_delivery()
                || platform::capability::check_thread(sender, "capabilities.manage") != Ok(1)
            {
                close_received_handles(&attached);
                capability_reply(sender, 13);
                continue;
            }
            let (probe, event) = crate::consent_input_probe::Probe::start(
                sender,
                &mut state.consent,
                input_authority.as_mut().expect("installed input authority"),
            )
            .expect("native consent input probe start");
            input_probe = Some(probe);
            let _ = platform::ipc::reply(
                sender,
                &platform::capability::input_authority::encode_event(event).unwrap(),
            );
            continue;
        }
        if opcode == platform::capability::input_authority::INSTALL_OPCODE {
            let result = (|| {
                if slice.len() != 4
                    || attached.count != 0
                    || !attached.is_user_delivery()
                    || platform::capability::check_thread(sender, "capabilities.manage") != Ok(1)
                    || state.consent.len() != 0
                {
                    return Err(mochi_user_syscall::SysError::from_raw(
                        mochi_user_syscall::EACCES as i64,
                    ));
                }
                if let Some(channel) = &input_authority {
                    channel.current()?;
                } else {
                    input_authority = Some(crate::consent_input::Channel::connect(
                        &state.trusted_images,
                    )?);
                }
                Ok(())
            })();
            close_received_handles(&attached);
            capability_reply(sender, result.err().map_or(0, error_status));
            continue;
        }
        if opcode == platform::capability::input_authority::EVENT_OPCODE {
            let result = (|| {
                if attached.count != 0 || !attached.is_user_delivery() {
                    return Err(mochi_user_syscall::SysError::from_raw(
                        mochi_user_syscall::EACCES as i64,
                    ));
                }
                let channel = input_authority.as_mut().ok_or_else(|| {
                    mochi_user_syscall::SysError::from_raw(mochi_user_syscall::EACCES as i64)
                })?;
                let event = channel.receive(sender, slice)?;
                let transition = event.observation.transition.into();
                state
                    .consent
                    .input(
                        channel.route().source,
                        event.correlation,
                        channel.route(),
                        event.observation.serial,
                        transition,
                        platform::time::monotonic_nanoseconds()?,
                    )
                    .map_err(|_| {
                        mochi_user_syscall::SysError::from_raw(mochi_user_syscall::EACCES as i64)
                    })?;
                #[cfg(mochios_consent_input_probe_306)]
                if let Some(probe) = input_probe.as_mut() {
                    if probe
                        .observe(event, &mut state.consent, channel)
                        .expect("native input evidence checks")
                    {
                        input_probe = None;
                    }
                }
                Ok(())
            })();
            close_received_handles(&attached);
            capability_reply(sender, result.err().map_or(0, error_status));
            continue;
        }
        #[cfg(mochios_verified_launch_probe_305)]
        if opcode == u32::from_le_bytes(*b"MR05") {
            let role = crate::consent_peer::capture(sender)
                .and_then(|peer| state.trusted_images.role(&peer));
            let status = if slice.len() == 4
                && attached.count == 0
                && matches!(role, Ok(Some(crate::trusted_images::Role::TextPrompt)))
            {
                0
            } else {
                mochi_user_syscall::EACCES
            };
            close_received_handles(&attached);
            capability_reply(sender, status);
            continue;
        }
        if opcode == platform::capability::INSTALL_POSIX_ENDPOINT_OPCODE {
            let valid_attachment = attached.is_user_delivery()
                && attached.count == 1
                && attached.handles[0].handle != 0
                && attached.handles[0].reserved == 0
                && attached.handles[0].rights & platform::handle::HANDLE_RIGHT_SEND != 0;
            let status = if slice.len() != core::mem::size_of::<u32>() || !valid_attachment {
                mochi_user_syscall::EINVAL
            } else if platform::capability::check_thread(sender, "capabilities.manage") != Ok(1) {
                mochi_user_syscall::EACCES
            } else {
                let endpoint = attached.handles[0].handle;
                attached.handles[0].handle = 0;
                install_posix_endpoint(endpoint)
                    .and_then(|_| {
                        authorization_reader = crate::persistent_grant::read_file;
                        // Mutable Data packages become visible only through
                        // the runtime filesystem and authenticated session.
                        state.refresh_package_index()
                    })
                    .map(|_| REPLY_OK)
                    .unwrap_or_else(error_status)
            };
            close_received_handles(&attached);
            if status != REPLY_OK {
                let _ = platform::write_fmt(
                    platform::io::STDERR,
                    format_args!(
                        "capability.service: POSIX endpoint handoff failed status={}\n",
                        status as i64
                    ),
                );
            }
            capability_reply(sender, status);
            continue;
        }
        if opcode == platform::capability::application_launch::OPCODE {
            let result = (|| {
                if !attached.is_user_delivery()
                    || attached.count != 4
                    || attached.handles[0].handle == 0
                    || attached.handles[0].reserved != 0
                    || attached.handles[0].rights
                        != mochios_posix_protocol::read_scope::ATTACH_RIGHTS
                {
                    return Err(mochi_user_syscall::SysError::from_raw(
                        mochi_user_syscall::EINVAL as i64,
                    ));
                }
                let request =
                    platform::capability::application_launch::decode(slice).map_err(|_| {
                        mochi_user_syscall::SysError::from_raw(mochi_user_syscall::EINVAL as i64)
                    })?;
                let stdio =
                    crate::app_stdio::Stdio::new(&attached.handles[1..4], request.stdio_metadata)?;
                let endpoint = crate::persistent_grant::launch_endpoint()?;
                let result = crate::app_spawn::spawn_application_with_stdio(
                    &state.package_index,
                    &state.app_prompt_policy,
                    &state.trusted_images,
                    sender,
                    request,
                    endpoint,
                    mochios_posix_client::ObjectHandleAttachment {
                        handle: attached.handles[0].handle,
                        rights: attached.handles[0].rights,
                    },
                    &stdio,
                );
                let _ = platform::handle::close(endpoint);
                result
            })();
            close_received_handles(&attached);
            reply_spawn(sender, result);
            continue;
        }
        if opcode == SPAWN_APP_OPCODE {
            let required = platform::handle::HANDLE_RIGHT_SEND
                | platform::handle::HANDLE_RIGHT_DUPLICATE
                | platform::handle::HANDLE_RIGHT_TRANSFER;
            let valid = attached.count == 2
                && attached.is_user_delivery()
                && attached.handles[0].handle != 0
                && attached.handles[0].reserved == 0
                && attached.handles[0].rights == required
                && attached.handles[1].handle != 0
                && attached.handles[1].reserved == 0
                && attached.handles[1].rights == mochios_posix_protocol::read_scope::ATTACH_RIGHTS;
            let result = if valid {
                spawn_application_from_manifest(
                    &state.package_index,
                    &state.app_prompt_policy,
                    &state.trusted_images,
                    sender,
                    slice,
                    attached.handles[0].handle,
                    mochios_posix_client::ObjectHandleAttachment {
                        handle: attached.handles[1].handle,
                        rights: attached.handles[1].rights,
                    },
                )
            } else {
                Err(mochi_user_syscall::SysError::from_raw(
                    mochi_user_syscall::EINVAL as i64,
                ))
            };
            close_received_handles(&attached);
            reply_spawn(sender, result);
            continue;
        }
        if opcode == platform::capability::AUTHORIZE_EXEC_OBJECT_OPCODE {
            let result = crate::object_image::authorize(sender, slice, &attached);
            close_received_handles(&attached);
            capability_reply(sender, result.err().map(error_status).unwrap_or(REPLY_OK));
            continue;
        }
        if attached.count != 0 || !attached.is_user_delivery() {
            close_received_handles(&attached);
            capability_reply(sender, mochi_user_syscall::EINVAL);
            continue;
        }
        if opcode == platform::capability::AUTHORIZE_CAPTURED_IMAGE_OPCODE {
            let result = crate::object_image::authorize_captured(sender, slice);
            capability_reply(sender, result.err().map(error_status).unwrap_or(REPLY_OK));
            continue;
        }
        if opcode == platform::capability::RESOLVE_CAPABILITIES_OPCODE {
            let result = platform::capability::decode_resolve_capabilities_request(slice)
                .map_err(|_| {
                    mochi_user_syscall::SysError::from_raw(mochi_user_syscall::EINVAL as i64)
                })
                .and_then(|path| {
                    resolve_capabilities_for_path(&state.package_index, path, authorization_reader)
                });
            reply_capabilities(sender, result);
            continue;
        }
        if opcode == platform::capability::PREPARE_EXECUTION_IMAGE_OPCODE {
            let result = platform::capability::decode_prepare_execution_image_request(slice)
                .map_err(|_| {
                    mochi_user_syscall::SysError::from_raw(mochi_user_syscall::EINVAL as i64)
                })
                .and_then(|(class, path)| {
                    crate::prepared_image::prepare(
                        &state,
                        sender,
                        class,
                        path,
                        authorization_reader,
                    )
                });
            match result {
                Ok(image) => {
                    let mut handles = platform::ipc::IpcObjectHandles::default();
                    handles.count = 1;
                    handles.handles[0] = platform::ipc::IpcObjectHandle {
                        handle: image.handle(),
                        reserved: 0,
                        rights: platform::handle::HANDLE_RIGHT_READ,
                    };
                    let _ =
                        platform::ipc::reply_object_handles(sender, &0u64.to_le_bytes(), &handles);
                    // On success IPC owns the receiver reference. On failure
                    // only this local owner exists; either way Drop is correct.
                }
                Err(error) => capability_reply(sender, error_status(error)),
            }
            continue;
        }
        if opcode == platform::capability::RESOLVE_EXECUTION_SECURITY_OPCODE {
            let result = platform::capability::decode_resolve_execution_security_request(slice)
                .map_err(|_| {
                    mochi_user_syscall::SysError::from_raw(mochi_user_syscall::EINVAL as i64)
                })
                .and_then(|(execution_class_raw, path)| {
                    let execution_class =
                        platform::service::ExecutionClass::from_raw(execution_class_raw)
                            .ok_or_else(|| {
                                mochi_user_syscall::SysError::from_raw(
                                    mochi_user_syscall::EINVAL as i64,
                                )
                            })?;
                    let record = state.package_index.by_binary.get(path).ok_or_else(|| {
                        mochi_user_syscall::SysError::from_raw(mochi_user_syscall::ENOENT as i64)
                    })?;
                    let caps = binary_caps(
                        &record.manifest,
                        &record.manifest_path,
                        path,
                        authorization_reader,
                    )?
                    .to_vec();
                    let identity = application_identity(
                        &record.manifest,
                        &record.manifest_path,
                        authorization_reader,
                    )?;
                    let mut identity_items = Vec::new();
                    encode_identity_args(&identity, &mut identity_items);
                    authorize_spawn(
                        sender,
                        path,
                        &identity,
                        &caps,
                        execution_class,
                        authorization_reader,
                    )?;
                    Ok((identity_items, caps))
                });
            reply_execution_security(sender, result);
            continue;
        }
        if opcode == platform::capability::AUTHORIZE_EXEC_OPCODE {
            let result = platform::capability::decode_authorize_exec_request(slice)
                .map_err(|_| {
                    mochi_user_syscall::SysError::from_raw(mochi_user_syscall::EINVAL as i64)
                })
                .and_then(|path| {
                    let record = state.package_index.by_binary.get(path).ok_or_else(|| {
                        mochi_user_syscall::SysError::from_raw(mochi_user_syscall::EACCES as i64)
                    })?;
                    let mut capability_decision = decide_binary_capabilities(
                        &record.manifest,
                        &record.manifest_path,
                        path,
                        crate::persistent_grant::read_file,
                    )?;
                    let identity = application_identity(
                        &record.manifest,
                        &record.manifest_path,
                        crate::persistent_grant::read_file,
                    )?;
                    let requester_context = crate::persistent_grant::requester_context(sender)?;
                    let package_id = identity.package_id.as_bytes();
                    let developer_id = identity.developer_id.as_bytes();
                    if package_id.len() > requester_context.package_id.len()
                        || developer_id.len() > requester_context.developer_id.len()
                    {
                        return Err(mochi_user_syscall::SysError::from_raw(
                            mochi_user_syscall::EINVAL as i64,
                        ));
                    }
                    let requester_package_len = requester_context.package_id_len as usize;
                    let requester_developer_len = requester_context.developer_id_len as usize;
                    let same_identity = requester_package_len <= requester_context.package_id.len()
                        && requester_developer_len <= requester_context.developer_id.len()
                        && &requester_context.package_id[..requester_package_len] == package_id
                        && &requester_context.developer_id[..requester_developer_len]
                            == developer_id
                        && requester_context.subject_key_id == identity.subject_key_id
                        && requester_context.provenance == identity.provenance as u8;
                    let mut target_context = crate::requester_context::RequesterContext::default();
                    target_context.effective_uid = requester_context.effective_uid;
                    target_context.effective_gid = requester_context.effective_gid;
                    target_context.package_id_len = package_id.len() as u16;
                    target_context.developer_id_len = developer_id.len() as u16;
                    target_context.package_id[..package_id.len()].copy_from_slice(package_id);
                    target_context.developer_id[..developer_id.len()].copy_from_slice(developer_id);
                    target_context.subject_key_id = identity.subject_key_id;
                    target_context.provenance = identity.provenance as u8;
                    let mut user_allowed = Vec::new();
                    let mut caller_allowed = Vec::new();
                    for capability in &capability_decision.requested {
                        let already_held =
                            platform::capability::check_thread(sender, capability) == Ok(1);
                        let user_grantable =
                            platform::capability::capability_from_string(capability)
                                == platform::capability::CapabilityClass::UserGrantable;
                        let policy_allows = user_grantable
                            && !needs_app_prompt(&state.app_prompt_policy, capability);
                        let user_authorized = !user_grantable
                            || same_identity
                            || has_persistent_grant(&target_context, capability, None)
                            || policy_allows;

                        if already_held {
                            caller_allowed.push(capability.clone());
                        }
                        if user_authorized {
                            user_allowed.push(capability.clone());
                        }
                    }
                    capability_decision = capability_decision
                        .apply_runtime_constraints(&user_allowed, &caller_allowed);
                    if !capability_decision.is_allowed() {
                        platform::logln!(
                            "capability.service: exec denied path={} reason={:?} denied={:?}",
                            path,
                            capability_decision.deny_reason,
                            capability_decision.denied
                        );
                        let errno = if capability_decision.deny_reason
                            == Some(CapabilityDenyReason::UnknownCapability)
                        {
                            mochi_user_syscall::EINVAL
                        } else {
                            mochi_user_syscall::EACCES
                        };
                        return Err(mochi_user_syscall::SysError::from_raw(errno as i64));
                    }
                    let caps = capability_decision.effective;
                    let mut identity_items = Vec::new();
                    encode_identity_args(&identity, &mut identity_items);
                    let executable = crate::persistent_grant::read_file(path)?;
                    let digest = Sha256::digest(&executable);
                    let mut digest_hex = String::with_capacity(64);
                    for byte in digest {
                        use core::fmt::Write;
                        let _ = write!(digest_hex, "{byte:02x}");
                    }
                    identity_items.push(alloc::format!(
                        "{}{digest_hex}",
                        mnu_abi::exec::EXECUTABLE_DIGEST_PREFIX
                    ));
                    identity_items.push(alloc::format!(
                        "{}{}",
                        mnu_abi::exec::EXEC_AUTHORIZATION_KIND_PREFIX,
                        mnu_abi::exec::EXEC_AUTHORIZATION_KIND_IMAGE_REPLACE
                    ));
                    identity_items.push(alloc::format!(
                        "{}unprivileged",
                        mnu_abi::exec::EXEC_AUTHORIZATION_CLASS_PREFIX
                    ));
                    let identity_nul = encode_exec_authorization_args(&identity_items)?;
                    let caps_nul = encode_nul_list(&caps);
                    platform::service::authorize_exec_for_requester(
                        sender,
                        path,
                        &identity_nul,
                        &caps_nul,
                    )
                    .map(|_| ())
                });
            capability_reply(
                sender,
                result.map(|_| REPLY_OK).unwrap_or_else(error_status),
            );
            continue;
        }
        if opcode == platform::capability::PACKAGE_INDEX_CHANGED_OPCODE {
            let status = if slice.len() != core::mem::size_of::<u32>() {
                mochi_user_syscall::EINVAL
            } else if platform::capability::check_thread(sender, "package.install") != Ok(1) {
                mochi_user_syscall::EACCES
            } else {
                state
                    .refresh_package_index()
                    .map(|_| REPLY_OK)
                    .unwrap_or_else(error_status)
            };
            capability_reply(sender, status);
            continue;
        }
        if opcode == platform::capability::CAPABILITY_DECISION_OPCODE {
            // An authenticated presenter is not evidence of a fresh user act.
            // Only the transaction/input-authority controller may authorize it.
            capability_reply(
                sender,
                mochi_user_syscall::NativeError::Unsupported.into_raw(),
            );
            continue;
        }
        if opcode == platform::capability::CAPABILITY_PERSISTENT_QUERY_OPCODE {
            let status = parse_persistent_query(slice)
                .and_then(|request| {
                    authorize_persistent_capability(&state.package_index, sender, &request)
                })
                .map(|_| REPLY_OK)
                .unwrap_or_else(error_status);
            capability_reply(sender, status);
            continue;
        }
        capability_reply(sender, mochi_user_syscall::EINVAL);
    }
}
