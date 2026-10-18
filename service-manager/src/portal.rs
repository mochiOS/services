use mochi_user_platform as platform;
use mochios_linux_portal_protocol::{
    Access, AuthorizeStorageRequest, AuthorizeStorageResponse, GRANT_RESPONSE_LEN,
    GrantDirectoryRequest, GrantDirectoryResponse, NETWORK_RESPONSE_LEN, Opcode,
    RequestNetworkRequest, RequestNetworkResponse, STORAGE_RESPONSE_LEN,
    StorageAction as PortalStorageAction, decode_opcode,
};
use mochios_permission_prompt_protocol::{MAX_MESSAGE_LEN, PromptRequest, StorageAction};

use crate::service_launcher;
use crate::session::ActiveSession;
use crate::spawn_support::errno;

#[derive(Default)]
pub(crate) struct PermissionPrompts {
    process: Option<PermissionPromptProcess>,
    pub(crate) deferred: alloc::collections::VecDeque<crate::readiness::DeferredMessage>,
}

struct PermissionPromptProcess {
    process: crate::native_process::NativeProcess,
    endpoint: platform::handle::Handle,
    token: u64,
}

impl Drop for PermissionPromptProcess {
    fn drop(&mut self) {
        self.process.terminate();
        let _ = platform::handle::close(self.endpoint);
    }
}

pub(crate) fn handle(
    request_bytes: &[u8],
    sender: u64,
    session: Option<ActiveSession>,
    logger_endpoint: u64,
    prompt_process: &mut PermissionPrompts,
) {
    match decode_opcode(request_bytes) {
        Ok(Opcode::GrantDirectory) => handle_directory(
            request_bytes,
            sender,
            session,
            logger_endpoint,
            prompt_process,
        ),
        Ok(Opcode::RequestNetwork) => handle_network(
            request_bytes,
            sender,
            session,
            logger_endpoint,
            prompt_process,
        ),
        Ok(Opcode::AuthorizeStorage) => handle_storage(
            request_bytes,
            sender,
            session,
            logger_endpoint,
            prompt_process,
        ),
        _ => reply_invalid(request_bytes, sender),
    }
}

fn handle_storage(
    request_bytes: &[u8],
    sender: u64,
    session: Option<ActiveSession>,
    logger_endpoint: u64,
    prompt_process: &mut PermissionPrompts,
) {
    let request_id = request_id(request_bytes);
    let result = AuthorizeStorageRequest::decode(request_bytes)
        .map_err(|_| mochi_user_syscall::EINVAL)
        .and_then(|request| {
            let session = session.ok_or(mochios_posix_protocol::STATUS_EPERM as i64 as u64)?;
            authorize_storage(sender, session, &request)?;
            let action = match request.action {
                PortalStorageAction::Use => StorageAction::Use,
                PortalStorageAction::Create => StorageAction::Create,
                PortalStorageAction::Delete => StorageAction::Delete,
            };
            platform::logln!(
                "service-manager.service: storage prompt action={:?} target={}",
                action,
                request.target
            );
            run_prompt(
                logger_endpoint,
                prompt_process,
                PromptRequest::Storage {
                    token: 1,
                    application: "Installer.app",
                    action,
                    target: request.target,
                },
            )
        });
    let response = AuthorizeStorageResponse {
        request_id,
        status: result.map_or_else(crate::portal_status::failure_status, |_| 0),
    };
    let mut output = [0u8; STORAGE_RESPONSE_LEN];
    if let Ok(length) = response.encode(&mut output) {
        let _ = platform::ipc::reply(sender, &output[..length]);
    }
}

fn authorize_storage(
    sender: u64,
    session: ActiveSession,
    request: &AuthorizeStorageRequest<'_>,
) -> Result<(), u64> {
    if request.session_id != session.id || request.bundle_id != "org.mochios.installer" {
        return Err(mochios_posix_protocol::STATUS_EPERM as i64 as u64);
    }
    if sender_process(sender).is_none()
        || platform::capability::check_thread(sender, "device.storage") != Ok(1)
    {
        return Err(mochi_user_syscall::EACCES);
    }
    Ok(())
}

fn handle_directory(
    request_bytes: &[u8],
    sender: u64,
    session: Option<ActiveSession>,
    logger_endpoint: u64,
    prompt_process: &mut PermissionPrompts,
) {
    let request_id = request_bytes
        .get(8..16)
        .and_then(|bytes| bytes.try_into().ok())
        .map(u64::from_le_bytes)
        .unwrap_or(0);
    let result = GrantDirectoryRequest::decode(request_bytes)
        .map_err(|_| mochi_user_syscall::EINVAL)
        .and_then(|request| {
            let session = session.ok_or(mochios_posix_protocol::STATUS_EPERM as i64 as u64)?;
            authorize_request(sender, session, &request)?;
            prompt(logger_endpoint, prompt_process, &request)
        });
    let (status, grant_id) = match result {
        Ok(grant_id) => (0, grant_id),
        Err(error) => (crate::portal_status::failure_status(error), 0),
    };
    let response = GrantDirectoryResponse {
        request_id,
        status,
        grant_id,
    };
    let mut output = [0u8; GRANT_RESPONSE_LEN];
    if let Ok(length) = response.encode(&mut output) {
        let _ = platform::ipc::reply(sender, &output[..length]);
    }
}

fn handle_network(
    request_bytes: &[u8],
    sender: u64,
    session: Option<ActiveSession>,
    logger_endpoint: u64,
    prompt_process: &mut PermissionPrompts,
) {
    let request_id = request_id(request_bytes);
    let result = RequestNetworkRequest::decode(request_bytes)
        .map_err(|_| mochi_user_syscall::EINVAL)
        .and_then(|request| {
            let session = session.ok_or(mochios_posix_protocol::STATUS_EPERM as i64 as u64)?;
            authorize_network(sender, session, &request)?;
            prompt_network(logger_endpoint, prompt_process, request.bundle_id)
        });
    let response = RequestNetworkResponse {
        request_id,
        status: result.map_or_else(crate::portal_status::failure_status, |_| 0),
    };
    let mut output = [0u8; NETWORK_RESPONSE_LEN];
    if let Ok(length) = response.encode(&mut output) {
        let _ = platform::ipc::reply(sender, &output[..length]);
    }
}

fn authorize_network(
    sender: u64,
    session: ActiveSession,
    request: &RequestNetworkRequest<'_>,
) -> Result<(), u64> {
    let linux_pid = session
        .linux_pid
        .ok_or(mochios_posix_protocol::STATUS_EPERM as i64 as u64)?;
    if request.session_id != session.id || Some(linux_pid) != sender_process(sender) {
        return Err(mochios_posix_protocol::STATUS_EPERM as i64 as u64);
    }
    let user = user_for_uid(session.identity.uid)
        .ok_or(mochios_posix_protocol::STATUS_EPERM as i64 as u64)?;
    (request.user == user.name)
        .then_some(())
        .ok_or(mochios_posix_protocol::STATUS_EPERM as i64 as u64)
}

fn prompt_network(
    logger_endpoint: u64,
    prompt_process: &mut PermissionPrompts,
    bundle_id: &str,
) -> Result<(), u64> {
    let application = application_name(bundle_id);
    platform::logln!("service-manager.service: network prompt application={application}");
    run_prompt(
        logger_endpoint,
        prompt_process,
        PromptRequest::Network {
            token: 1,
            application: &application,
        },
    )
}

fn reply_invalid(request: &[u8], sender: u64) {
    let response = RequestNetworkResponse {
        request_id: request_id(request),
        status: mochi_user_syscall::EINVAL as i32,
    };
    let mut output = [0u8; NETWORK_RESPONSE_LEN];
    if let Ok(length) = response.encode(&mut output) {
        let _ = platform::ipc::reply(sender, &output[..length]);
    }
}

fn request_id(bytes: &[u8]) -> u64 {
    bytes
        .get(8..16)
        .and_then(|value| value.try_into().ok())
        .map(u64::from_le_bytes)
        .unwrap_or(0)
}

fn authorize_request(
    sender: u64,
    session: ActiveSession,
    request: &GrantDirectoryRequest<'_>,
) -> Result<(), u64> {
    let linux_pid = session
        .linux_pid
        .ok_or(mochios_posix_protocol::STATUS_EPERM as i64 as u64)?;
    if request.session_id != session.id || Some(linux_pid) != sender_process(sender) {
        return Err(mochios_posix_protocol::STATUS_EPERM as i64 as u64);
    }
    let user = user_for_uid(session.identity.uid)
        .ok_or(mochios_posix_protocol::STATUS_EPERM as i64 as u64)?;
    if request.user != user.name {
        return Err(mochios_posix_protocol::STATUS_EPERM as i64 as u64);
    }
    let home = alloc::format!("/home/{}", user.name);
    let in_home = request.path == home
        || request
            .path
            .strip_prefix(home.as_str())
            .is_some_and(|suffix| suffix.starts_with('/'));
    let readable_system = request.path == "/applications"
        || request.path.starts_with("/applications/")
        || request.path == "/libraries"
        || request.path.starts_with("/libraries/");
    if (!in_home && !readable_system) || (request.access.writable() && !in_home) {
        return Err(mochi_user_syscall::EACCES);
    }
    if std::fs::metadata(request.path)
        .map(|metadata| !metadata.is_dir())
        .unwrap_or(true)
    {
        return Err(mochi_user_syscall::ENOENT);
    }
    Ok(())
}

fn prompt(
    logger_endpoint: u64,
    prompt_process: &mut PermissionPrompts,
    request: &GrantDirectoryRequest<'_>,
) -> Result<u64, u64> {
    let application = application_name(request.bundle_id);
    platform::logln!(
        "service-manager.service: portal prompt application={} path={}",
        application,
        request.path
    );
    run_prompt(
        logger_endpoint,
        prompt_process,
        PromptRequest::Directory {
            token: 1,
            application: &application,
            path: request.path,
            writable: request.access == Access::READ_WRITE,
        },
    )?;
    platform::service_ready::generate_token().map_err(errno)
}

pub(crate) fn prewarm(prompt_process: &mut PermissionPrompts, logger_endpoint: u64) {
    if prompt_process.process.is_some() {
        return;
    }
    let token = match platform::service_ready::generate_token() {
        Ok(token) => token,
        Err(error) => {
            platform::logln!(
                "service-manager.service: permission prompt token failed errno={}",
                errno(error)
            );
            return;
        }
    };
    let result = (|| {
        let target = platform::service_ready::Target {
            endpoint: platform::ipc::create()?,
            token,
        };
        let process =
            service_launcher::spawn_permission_prompt_server(logger_endpoint, token, target)?;
        let endpoint = match crate::readiness::wait_for_published_endpoint(
            token,
            process.watch_target(),
            &mut prompt_process.deferred,
        ) {
            Ok(endpoint) => endpoint,
            Err(error) => {
                process.terminate();
                platform::logln!(
                    "service-manager.service: permission prompt readiness failed error={:?}",
                    error
                );
                return Err(mochi_user_syscall::SysError::from_raw(
                    mochi_user_syscall::EIO as i64,
                ));
            }
        };
        Ok(PermissionPromptProcess {
            process,
            endpoint,
            token,
        })
    })();
    prompt_process.process = result
        .map_err(|error| {
            platform::logln!(
                "service-manager.service: permission prompt prewarm failed errno={}",
                errno(error)
            );
            error
        })
        .ok();
}

fn run_prompt(
    logger_endpoint: u64,
    prompt_process: &mut PermissionPrompts,
    request: PromptRequest<'_>,
) -> Result<(), u64> {
    prewarm(prompt_process, logger_endpoint);
    let prompt = prompt_process
        .process
        .take()
        .ok_or(mochi_user_syscall::EIO)?;
    let request = match request {
        PromptRequest::Network { application, .. } => PromptRequest::Network {
            token: prompt.token,
            application,
        },
        PromptRequest::Directory {
            application,
            path,
            writable,
            ..
        } => PromptRequest::Directory {
            token: prompt.token,
            application,
            path,
            writable,
        },
        PromptRequest::Storage {
            application,
            action,
            target,
            ..
        } => PromptRequest::Storage {
            token: prompt.token,
            application,
            action,
            target,
        },
    };
    let mut encoded = [0u8; MAX_MESSAGE_LEN];
    let length = request
        .encode(&mut encoded)
        .map_err(|_| mochi_user_syscall::EINVAL)?;
    let mut reply = [0u8; 4];
    let mut handles = platform::ipc::IpcObjectHandles::default();
    let result = platform::ipc::call_object_handles(
        prompt.endpoint,
        &encoded[..length],
        &mut reply,
        &mut handles,
    )
    .map_err(|error| {
        platform::logln!(
            "service-manager.service: permission prompt IPC failed endpoint={} errno={}",
            prompt.endpoint,
            errno(error)
        );
        errno(error)
    })
    .and_then(|message| {
        let length = (message & 0xffff_ffff) as usize;
        if length != reply.len() || handles.count != 0 {
            for attached in handles
                .handles
                .iter()
                .take((handles.count as usize).min(handles.handles.len()))
            {
                if attached.handle != 0 {
                    let _ = platform::handle::close(attached.handle);
                }
            }
            platform::logln!(
                "service-manager.service: permission prompt reply invalid endpoint={} bytes={}",
                prompt.endpoint,
                length
            );
            return Err(mochi_user_syscall::EIO);
        }
        let status = i32::from_le_bytes(reply);
        platform::logln!(
            "service-manager.service: permission prompt reply endpoint={} status={}",
            prompt.endpoint,
            status
        );
        if status == 0 {
            Ok(())
        } else {
            Err(status.unsigned_abs() as u64)
        }
    });
    drop(prompt);
    prewarm(prompt_process, logger_endpoint);
    result
}

fn application_name(bundle_id: &str) -> alloc::string::String {
    let user_manifest = alloc::format!("/var/lib/packages/{bundle_id}/manifest.toml");
    let system_manifest = alloc::format!("/system/packages/{bundle_id}/manifest.toml");
    let read_manifest = |path: &str| {
        let text = std::fs::read_to_string(path).ok()?;
        platform::package::parse_manifest(&text)
    };
    read_manifest(&system_manifest)
        .or_else(|| read_manifest(&user_manifest))
        .filter(|manifest| manifest.package_id == bundle_id)
        .map(|manifest| {
            if manifest.package_name.ends_with(".app") {
                manifest.package_name
            } else {
                alloc::format!("{}.app", manifest.package_name)
            }
        })
        .unwrap_or_else(|| "Application".to_owned())
}

fn sender_process(sender: u64) -> Option<u64> {
    platform::ipc::endpoint_owner_process(sender).ok()
}

fn user_for_uid(uid: u32) -> Option<mochios_user_database::UserRecord> {
    use mochios_user_database::{DATABASE_PATH, UserDatabase};
    let bytes = std::fs::read(DATABASE_PATH).ok()?;
    UserDatabase::parse(&bytes).ok()?.find_uid(uid).cloned()
}

#[cfg(test)]
mod tests {
    #[test]
    fn access_policy_only_allows_writes_below_the_session_home() {
        let home = "/home/alice";
        assert!(
            "/home/alice/Develop"
                .strip_prefix(home)
                .is_some_and(|tail| tail.starts_with('/'))
        );
        assert!(
            !"/home/alice2"
                .strip_prefix(home)
                .is_some_and(|tail| tail.starts_with('/'))
        );
        assert!("/applications/Files.app".starts_with("/applications/"));
    }
}
