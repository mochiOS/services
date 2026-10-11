use mochi_user_platform as platform;

use crate::launch_arguments::encode_native_launch;
use crate::launch_arguments::encode_spawn_args;
use crate::native_process::NativeProcess;
use crate::service_config::{
    DRIVERS, FixedService, ReadyTarget, ServiceSpec, driver_arguments, fixed_service_arguments,
    fixed_service_spec, mboot_agent_arguments,
};
use crate::spawn_support::{resolve_execution_security, sys_error};

const SESSION_USER_ARG_PREFIX: &str = "--session-user=";
const LOCK_USER_ARG_PREFIX: &str = "--lock-user=";
use mnu_abi::exec::{ENVIRONMENT_PREFIX, INHERITED_HANDLE_PREFIX};

const POSIX_CHILD_HANDLE_RIGHTS: u64 = platform::handle::HANDLE_RIGHT_SEND
    | platform::handle::HANDLE_RIGHT_DUPLICATE
    | platform::handle::HANDLE_RIGHT_TRANSFER;
const FILESYSTEM_CHILD_HANDLE_RIGHTS: u64 = POSIX_CHILD_HANDLE_RIGHTS;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct DriverManagerTarget {
    pub(crate) endpoint: u64,
    pub(crate) token: u64,
}

fn spawn(
    spec: ServiceSpec,
    arguments: &[alloc::string::String],
) -> Result<u64, mochi_user_syscall::SysError> {
    let mut arguments = arguments.to_vec();
    let security = resolve_execution_security(spec.path, spec.execution_class)?;
    if spec.security_identity {
        for identity_item in security.identity.into_iter().rev() {
            arguments.insert(0, identity_item);
        }
    }
    let arguments =
        encode_spawn_args(&arguments).map_err(|_| sys_error(mochi_user_syscall::EINVAL))?;
    platform::service::spawn_manifest(
        spec.path,
        spec.execution_class,
        Some(arguments.as_slice()),
        Some(security.capabilities.as_slice()),
    )
}

fn spawn_with_credentials(
    spec: ServiceSpec,
    arguments: &[alloc::string::String],
    identity: platform::service_ready::SessionIdentity,
) -> Result<u64, mochi_user_syscall::SysError> {
    let mut arguments = arguments.to_vec();
    let security = resolve_execution_security(spec.path, spec.execution_class)?;
    if spec.security_identity {
        for identity_item in security.identity.into_iter().rev() {
            arguments.insert(0, identity_item);
        }
    }
    let arguments =
        encode_spawn_args(&arguments).map_err(|_| sys_error(mochi_user_syscall::EINVAL))?;
    platform::service::spawn_manifest_with_credentials(
        spec.path,
        spec.execution_class,
        identity.uid,
        identity.gid,
        Some(arguments.as_slice()),
        Some(security.capabilities.as_slice()),
    )
}

pub(crate) fn spawn_drivers(
    logger_endpoint: u64,
    manager: DriverManagerTarget,
    posix_endpoint: platform::handle::Handle,
) -> Result<NativeProcess, mochi_user_syscall::SysError> {
    let mut arguments = driver_arguments(logger_endpoint, manager.endpoint, manager.token);
    append_posix_handle(&mut arguments, Some(posix_endpoint));
    spawn_native(DRIVERS, "drivers.service", &arguments, posix_endpoint)
}

pub(crate) fn spawn_fixed_service(
    service: FixedService,
    logger_endpoint: u64,
    ready_target: Option<platform::service_ready::Target>,
    filesystem_endpoint: Option<platform::handle::Handle>,
    posix_endpoint: Option<platform::handle::Handle>,
) -> Result<u64, mochi_user_syscall::SysError> {
    // Migrated services must not fall back to legacy pathname creation.
    if matches!(
        service,
        FixedService::Input | FixedService::Display | FixedService::Compositor
    ) {
        return Err(sys_error(mochi_user_syscall::EINVAL));
    }
    let ready_target = ready_target.map(|target| ReadyTarget {
        endpoint: target.endpoint,
        token: target.token,
    });
    let mut arguments = fixed_service_arguments(service, logger_endpoint, ready_target);
    if service == FixedService::Posix {
        append_filesystem_handle(&mut arguments, filesystem_endpoint);
    }
    append_posix_handle(&mut arguments, posix_endpoint);
    spawn(fixed_service_spec(service), &arguments)
}

pub(crate) fn spawn_input_service(
    logger_endpoint: u64,
    ready_target: platform::service_ready::Target,
    posix_endpoint: platform::handle::Handle,
) -> Result<NativeProcess, mochi_user_syscall::SysError> {
    spawn_native_fixed(
        FixedService::Input,
        "input.service",
        logger_endpoint,
        ready_target,
        posix_endpoint,
    )
}

pub(crate) fn spawn_display_service(
    logger_endpoint: u64,
    ready_target: platform::service_ready::Target,
    posix_endpoint: platform::handle::Handle,
) -> Result<NativeProcess, mochi_user_syscall::SysError> {
    spawn_native_fixed(
        FixedService::Display,
        "display.driver",
        logger_endpoint,
        ready_target,
        posix_endpoint,
    )
}

pub(crate) fn spawn_compositor_service(
    logger_endpoint: u64,
    posix_endpoint: platform::handle::Handle,
) -> Result<NativeProcess, mochi_user_syscall::SysError> {
    let mut arguments = fixed_service_arguments(FixedService::Compositor, logger_endpoint, None);
    append_posix_handle(&mut arguments, Some(posix_endpoint));
    spawn_native(
        fixed_service_spec(FixedService::Compositor),
        "compositor.service",
        &arguments,
        posix_endpoint,
    )
}

fn spawn_native_fixed(
    service: FixedService,
    label: &str,
    logger_endpoint: u64,
    ready_target: platform::service_ready::Target,
    posix_endpoint: platform::handle::Handle,
) -> Result<NativeProcess, mochi_user_syscall::SysError> {
    let spec = fixed_service_spec(service);
    let mut arguments = fixed_service_arguments(
        service,
        logger_endpoint,
        Some(ReadyTarget {
            endpoint: ready_target.endpoint,
            token: ready_target.token,
        }),
    );
    append_posix_handle(&mut arguments, Some(posix_endpoint));
    spawn_native(spec, label, &arguments, posix_endpoint)
}

fn spawn_native(
    spec: ServiceSpec,
    label: &str,
    arguments: &[String],
    posix_endpoint: platform::handle::Handle,
) -> Result<NativeProcess, mochi_user_syscall::SysError> {
    use mochios_posix_client::{Client, ClientError, OpenAtBase, SyscallEndpointTransport};
    let mut random = [0; 16];
    platform::random::fill(&mut random)?;
    let metadata = encode_native_launch(spec.path, label, arguments, random)
        .map_err(|_| sys_error(mochi_user_syscall::EINVAL))?;
    let client = Client::new(SyscallEndpointTransport::new(posix_endpoint));
    let client_error = |error| match error {
        ClientError::Transport(error) => error,
        ClientError::Remote(errno) => sys_error(errno.unsigned_abs() as u64),
        _ => sys_error(mochi_user_syscall::EIO),
    };
    // Endpoint possession is not a POSIX session. Register the authenticated
    // caller before asking the service to resolve a process-root pathname.
    client.register_session().map_err(client_error)?;
    let image = client
        .open_at(
            OpenAtBase::ProcessRoot,
            mochios_posix_protocol::OPEN_READ,
            0,
            spec.path,
        )
        .map_err(client_error)?;
    // The source reference comes only from this IPC attachment, not a PID/FD
    // capture API. Always release it, including authorization/create failure.
    let result = (|| {
        resolve_execution_security(spec.path, spec.execution_class)?;
        NativeProcess::create_and_resume(image.handle, &metadata)
    })();
    let _ = platform::handle::close(image.handle);
    result
}

pub(crate) fn spawn_mboot_agent(
    logger_endpoint: u64,
    stage_token: u64,
) -> Result<u64, mochi_user_syscall::SysError> {
    spawn(
        fixed_service_spec(FixedService::MbootAgent),
        &mboot_agent_arguments(logger_endpoint, stage_token),
    )
}

pub(crate) fn spawn_user_session(
    service: FixedService,
    logger_endpoint: u64,
    identity: platform::service_ready::SessionIdentity,
    session_id: u64,
    ready_target: Option<platform::service_ready::Target>,
    posix_endpoint: Option<platform::handle::Handle>,
) -> Result<u64, mochi_user_syscall::SysError> {
    let ready_target = ready_target.map(|target| ReadyTarget {
        endpoint: target.endpoint,
        token: target.token,
    });
    let mut arguments = fixed_service_arguments(service, logger_endpoint, ready_target);
    append_posix_handle(&mut arguments, posix_endpoint);
    if let Some(user) = session_user(identity.uid) {
        arguments.push(alloc::format!("{SESSION_USER_ARG_PREFIX}{}", user.name));
        for (name, value) in [
            ("HOME", user.home.as_str()),
            ("USER", user.name.as_str()),
            ("LOGNAME", user.name.as_str()),
            ("SHELL", "/bin/msh"),
        ] {
            arguments.push(alloc::format!("{ENVIRONMENT_PREFIX}{name}={value}"));
        }
        arguments.push(alloc::format!(
            "{ENVIRONMENT_PREFIX}MOCHI_SESSION_ID={session_id}"
        ));
    }
    spawn_with_credentials(fixed_service_spec(service), &arguments, identity)
}

fn append_posix_handle(arguments: &mut Vec<String>, endpoint: Option<platform::handle::Handle>) {
    if let Some(endpoint) = endpoint.filter(|endpoint| *endpoint != 0) {
        arguments.push(alloc::format!(
            "{INHERITED_HANDLE_PREFIX}{}:{endpoint}:{POSIX_CHILD_HANDLE_RIGHTS}",
            mochios_posix_protocol::CONTROL_HANDLE_KEY,
        ));
    }
}

fn append_filesystem_handle(
    arguments: &mut Vec<String>,
    endpoint: Option<platform::handle::Handle>,
) {
    if let Some(endpoint) = endpoint.filter(|endpoint| *endpoint != 0) {
        arguments.push(alloc::format!(
            "{INHERITED_HANDLE_PREFIX}{}:{endpoint}:{FILESYSTEM_CHILD_HANDLE_RIGHTS}",
            mochios_filesystem_protocol::CONTROL_HANDLE_KEY,
        ));
    }
}

pub(crate) fn spawn_secure_ui(
    logger_endpoint: u64,
    target: platform::service_ready::Target,
    lock_uid: Option<u32>,
) -> Result<u64, mochi_user_syscall::SysError> {
    let mut arguments = fixed_service_arguments(
        FixedService::SecureUi,
        logger_endpoint,
        Some(ReadyTarget {
            endpoint: target.endpoint,
            token: target.token,
        }),
    );
    if let Some(user) = lock_uid.and_then(|uid| session_user(uid)) {
        arguments.push(alloc::format!("{LOCK_USER_ARG_PREFIX}{}", user.name));
    }
    spawn(fixed_service_spec(FixedService::SecureUi), &arguments)
}

pub(crate) fn spawn_portal_prompt(
    logger_endpoint: u64,
    application: &str,
    path: &str,
    writable: bool,
) -> Result<u64, mochi_user_syscall::SysError> {
    let mut arguments = fixed_service_arguments(FixedService::SecureUi, logger_endpoint, None);
    arguments.push(alloc::format!("--portal-application={application}"));
    arguments.push(alloc::format!("--portal-path={path}"));
    arguments.push(alloc::format!(
        "--portal-access={}",
        if writable { "read-write" } else { "read" }
    ));
    spawn(fixed_service_spec(FixedService::SecureUi), &arguments)
}

pub(crate) fn spawn_network_prompt(
    logger_endpoint: u64,
    application: &str,
) -> Result<u64, mochi_user_syscall::SysError> {
    let mut arguments = fixed_service_arguments(FixedService::SecureUi, logger_endpoint, None);
    arguments.push(alloc::format!("--network-application={application}"));
    spawn(fixed_service_spec(FixedService::SecureUi), &arguments)
}

pub(crate) fn spawn_iommu_warning(
    logger_endpoint: u64,
    vendor: &str,
) -> Result<u64, mochi_user_syscall::SysError> {
    let mut arguments = fixed_service_arguments(FixedService::SecureUi, logger_endpoint, None);
    arguments.push(alloc::format!("--iommu-warning={vendor}"));
    spawn(fixed_service_spec(FixedService::SecureUi), &arguments)
}

pub(crate) fn spawn_permission_prompt_server(
    logger_endpoint: u64,
    token: u64,
) -> Result<u64, mochi_user_syscall::SysError> {
    let mut arguments = fixed_service_arguments(FixedService::SecureUi, logger_endpoint, None);
    arguments.push("--permission-prompt-server".to_owned());
    arguments.push(alloc::format!("--permission-prompt-token={token}"));
    spawn(fixed_service_spec(FixedService::SecureUi), &arguments)
}

fn session_user(uid: u32) -> Option<mochios_user_database::UserRecord> {
    use mochios_user_database::{DATABASE_PATH, UserDatabase};

    let bytes = std::fs::read(DATABASE_PATH).ok()?;
    let database = UserDatabase::parse(&bytes).ok()?;
    database.find_uid(uid).cloned()
}
