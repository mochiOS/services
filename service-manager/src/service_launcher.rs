use mochi_user_platform as platform;

use crate::launch_arguments::encode_native_launch;
use crate::native_process::NativeProcess;
use crate::service_config::{
    DRIVERS, FixedService, ReadyTarget, ServiceSpec, driver_arguments, fixed_service_arguments,
    fixed_service_spec, mboot_agent_arguments,
};
use crate::spawn_support::{prepare_execution_image, resolve_execution_security, sys_error};

use crate::launch_rollback::retain_failed_launch;
pub(crate) use crate::launch_rollback::{has_failed_launch_cleanup, retry_failed_launch_cleanup};

const SESSION_USER_ARG_PREFIX: &str = "--session-user=";
const LOCK_USER_ARG_PREFIX: &str = "--lock-user=";
use mochios_posix_client::launch_arguments::{ENVIRONMENT_PREFIX, INHERITED_HANDLE_PREFIX};

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
    let mut random = [0; 16];
    platform::random::fill(&mut random)?;
    let label = spec
        .path
        .rsplit('/')
        .next()
        .ok_or_else(|| sys_error(mochi_user_syscall::EINVAL))?;
    let metadata = encode_native_launch(spec.path, label, arguments, random)
        .map_err(|_| sys_error(mochi_user_syscall::EINVAL))?;
    let image = prepare_execution_image(spec.path, spec.execution_class)?;
    let process = NativeProcess::create_with_rollback(
        image.handle(),
        &metadata,
        |_| Ok(()),
        reap_namespace_launch,
    )?;
    Ok(process.process_id())
}

fn reap_namespace_launch(process: NativeProcess) {
    let _ = platform::write_fmt(
        platform::io::STDERR,
        format_args!("service-manager.service: retaining failed namespace launch until exit\n",),
    );
    // No POSIX service/session exists for these initial children. Retain the
    // exact native owner until termination is confirmed; never look up a PID.
    while process.retry_rollback(|_| Ok(())).is_err() {
        let _ = platform::thread::sleep_milliseconds(1);
    }
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
    // Only namespace bootstrap can run before executable Handles are available.
    // Unknown or newly added kinds must not regain legacy pathname creation.
    if !service.is_namespace_bootstrap() {
        return Err(sys_error(mochi_user_syscall::EINVAL));
    }
    let ready_target = ready_target.map(|target| ReadyTarget {
        endpoint: target.endpoint,
        token: target.token,
    });
    let mut arguments = fixed_service_arguments(service, logger_endpoint, ready_target);
    if service == FixedService::Posix {
        append_filesystem_handle(&mut arguments, filesystem_endpoint);
        let own_endpoint = platform::ipc::create()?;
        let rights = platform::handle::HANDLE_RIGHT_WAIT | platform::handle::HANDLE_RIGHT_SIGNAL;
        let bootstrap = platform::process::open_handle_for_endpoint(
            own_endpoint,
            rights | platform::handle::HANDLE_RIGHT_TRANSFER,
        )?;
        arguments.push(alloc::format!(
            "{INHERITED_HANDLE_PREFIX}{}:{bootstrap}:{rights}",
            mochios_posix_protocol::BOOTSTRAP_PROCESS_HANDLE_KEY,
        ));
        let result = spawn(fixed_service_spec(service), &arguments);
        let _ = platform::handle::close(bootstrap);
        return result;
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

pub(crate) fn spawn_network_service(
    logger_endpoint: u64,
    ready_target: platform::service_ready::Target,
    posix_endpoint: platform::handle::Handle,
) -> Result<NativeProcess, mochi_user_syscall::SysError> {
    spawn_native_fixed(
        FixedService::Network,
        "network.service",
        logger_endpoint,
        ready_target,
        posix_endpoint,
    )
}

pub(crate) fn spawn_keychain_service(
    logger_endpoint: u64,
    ready_target: platform::service_ready::Target,
    posix_endpoint: platform::handle::Handle,
) -> Result<NativeProcess, mochi_user_syscall::SysError> {
    spawn_native_fixed(
        FixedService::Keychain,
        "keychain.service",
        logger_endpoint,
        ready_target,
        posix_endpoint,
    )
}

pub(crate) fn spawn_user_service(
    logger_endpoint: u64,
    ready_target: platform::service_ready::Target,
    posix_endpoint: platform::handle::Handle,
) -> Result<NativeProcess, mochi_user_syscall::SysError> {
    spawn_native_fixed(
        FixedService::User,
        "user.service",
        logger_endpoint,
        ready_target,
        posix_endpoint,
    )
}

pub(crate) fn spawn_update_service(
    logger_endpoint: u64,
    posix_endpoint: platform::handle::Handle,
) -> Result<NativeProcess, mochi_user_syscall::SysError> {
    let mut arguments = fixed_service_arguments(FixedService::Update, logger_endpoint, None);
    append_posix_handle(&mut arguments, Some(posix_endpoint));
    spawn_native(
        fixed_service_spec(FixedService::Update),
        "update.service",
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
    if has_failed_launch_cleanup() {
        return Err(sys_error(mochi_user_syscall::EAGAIN));
    }
    use mochios_posix_client::{
        Client, ClientError, ObjectHandleAttachment, OpenAtBase, SyscallEndpointTransport,
    };
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
    client
        .register_session()
        .inspect_err(|error| {
            eprintln!("service-manager.service: {label} session registration failed: {error:?}");
        })
        .map_err(client_error)?;
    let image = client
        .open_at(
            OpenAtBase::ProcessRoot,
            mochios_posix_protocol::OPEN_READ,
            0,
            spec.path,
        )
        .inspect_err(|error| {
            eprintln!("service-manager.service: {label} image open failed: {error:?}");
        })
        .map_err(client_error)?;
    // The source reference comes only from this IPC attachment, not a PID/FD
    // capture API. Always release it, including authorization/create failure.
    let result = (|| {
        resolve_execution_security(spec.path, spec.execution_class).inspect_err(|error| {
            eprintln!(
                "service-manager.service: {label} execution authorization failed status={}",
                error.raw()
            );
        })?;
        // Fixed system services run as POSIX root by userspace policy. Register
        // their environment and parent before execution; never derive it from
        // the new native task's default kernel credentials. Native capability
        // authorization above remains independent of these POSIX IDs.
        NativeProcess::create_with_rollback(
            image.handle,
            &metadata,
            |handle| {
                client
                    .register_spawned_child(
                        ObjectHandleAttachment {
                            handle,
                            rights: mnu_abi::HANDLE_RIGHT_WAIT | mnu_abi::HANDLE_RIGHT_SIGNAL,
                        },
                        0,
                        0,
                        &[],
                    )
                    .map_err(client_error)
            },
            |process| retain_failed_launch(process, posix_endpoint),
        )
    })();
    let _ = platform::handle::close(image.handle);
    result
}

pub(crate) fn spawn_mboot_agent(
    logger_endpoint: u64,
    stage_token: u64,
    posix_endpoint: platform::handle::Handle,
) -> Result<NativeProcess, mochi_user_syscall::SysError> {
    let mut arguments = mboot_agent_arguments(logger_endpoint, stage_token);
    append_posix_handle(&mut arguments, Some(posix_endpoint));
    spawn_native(
        fixed_service_spec(FixedService::MbootAgent),
        "mboot-agent.service",
        &arguments,
        posix_endpoint,
    )
}

pub(crate) fn spawn_user_session(
    service: FixedService,
    logger_endpoint: u64,
    identity: platform::service_ready::SessionIdentity,
    session_id: u64,
    ready_target: Option<platform::service_ready::Target>,
    posix_endpoint: Option<platform::handle::Handle>,
) -> Result<NativeProcess, mochi_user_syscall::SysError> {
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
    let endpoint = posix_endpoint
        .filter(|endpoint| *endpoint != 0)
        .ok_or_else(|| sys_error(mochi_user_syscall::EINVAL))?;
    spawn_native_session(fixed_service_spec(service), &arguments, identity, endpoint)
}

fn spawn_native_session(
    spec: ServiceSpec,
    arguments: &[String],
    identity: platform::service_ready::SessionIdentity,
    endpoint: platform::handle::Handle,
) -> Result<NativeProcess, mochi_user_syscall::SysError> {
    if has_failed_launch_cleanup() {
        return Err(sys_error(mochi_user_syscall::EAGAIN));
    }
    use mochios_posix_client::{
        Client, ClientError, ObjectHandleAttachment, OpenAtBase, SyscallEndpointTransport,
    };
    let client = Client::new(SyscallEndpointTransport::new(endpoint));
    let convert = |error| match error {
        ClientError::Transport(error) => error,
        ClientError::Remote(errno) => sys_error(errno.unsigned_abs() as u64),
        _ => sys_error(mochi_user_syscall::EIO),
    };
    client.register_session().map_err(convert)?;
    let mut random = [0; 16];
    platform::random::fill(&mut random)?;
    let label = spec
        .path
        .rsplit('/')
        .find(|part| part.ends_with(".app"))
        .or_else(|| spec.path.rsplit('/').next())
        .unwrap_or("session");
    let metadata = encode_native_launch(spec.path, label, arguments, random)
        .map_err(|_| sys_error(mochi_user_syscall::EINVAL))?;
    let image = client
        .open_at(
            OpenAtBase::ProcessRoot,
            mochios_posix_protocol::OPEN_READ,
            0,
            spec.path,
        )
        .map_err(convert)?;
    let result = (|| {
        resolve_execution_security(spec.path, spec.execution_class)?;
        NativeProcess::create_with_rollback(
            image.handle,
            &metadata,
            |handle| {
                client
                    .register_spawned_child(
                        ObjectHandleAttachment {
                            handle,
                            rights: mnu_abi::HANDLE_RIGHT_WAIT | mnu_abi::HANDLE_RIGHT_SIGNAL,
                        },
                        identity.uid,
                        identity.gid,
                        &[],
                    )
                    .map_err(convert)
            },
            |process| retain_failed_launch(process, endpoint),
        )
    })();
    let _ = platform::handle::close(image.handle);
    result
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
    posix_endpoint: platform::handle::Handle,
) -> Result<NativeProcess, mochi_user_syscall::SysError> {
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
    append_posix_handle(&mut arguments, Some(posix_endpoint));
    spawn_native(
        fixed_service_spec(FixedService::SecureUi),
        "secure-ui.service",
        &arguments,
        posix_endpoint,
    )
}

pub(crate) fn spawn_iommu_warning(
    logger_endpoint: u64,
    vendor: &str,
    posix_endpoint: platform::handle::Handle,
) -> Result<NativeProcess, mochi_user_syscall::SysError> {
    let mut arguments = fixed_service_arguments(FixedService::SecureUi, logger_endpoint, None);
    arguments.push(alloc::format!("--iommu-warning={vendor}"));
    append_posix_handle(&mut arguments, Some(posix_endpoint));
    spawn_native(
        fixed_service_spec(FixedService::SecureUi),
        "secure-ui.service",
        &arguments,
        posix_endpoint,
    )
}

pub(crate) fn spawn_permission_prompt_server(
    logger_endpoint: u64,
    token: u64,
    target: platform::service_ready::Target,
) -> Result<NativeProcess, mochi_user_syscall::SysError> {
    let posix_endpoint = platform::handle::inherited(mochios_posix_protocol::CONTROL_HANDLE_KEY)?;
    let mut arguments = fixed_service_arguments(
        FixedService::SecureUi,
        logger_endpoint,
        Some(ReadyTarget {
            endpoint: target.endpoint,
            token: target.token,
        }),
    );
    arguments.push("--permission-prompt-server".to_owned());
    arguments.push(alloc::format!("--permission-prompt-token={token}"));
    append_posix_handle(&mut arguments, Some(posix_endpoint));
    spawn_native(
        fixed_service_spec(FixedService::SecureUi),
        "secure-ui.service",
        &arguments,
        posix_endpoint,
    )
}

#[cfg(mochios_presentation_probe_307)]
pub(crate) fn spawn_presentation_probe(
    logger_endpoint: u64,
    target: platform::service_ready::Target,
) -> Result<NativeProcess, mochi_user_syscall::SysError> {
    let posix_endpoint = platform::handle::inherited(mochios_posix_protocol::CONTROL_HANDLE_KEY)?;
    let mut arguments = fixed_service_arguments(
        FixedService::SecureUi,
        logger_endpoint,
        Some(ReadyTarget {
            endpoint: target.endpoint,
            token: target.token,
        }),
    );
    arguments.push("--presentation-probe-server".to_owned());
    append_posix_handle(&mut arguments, Some(posix_endpoint));
    spawn_native(
        fixed_service_spec(FixedService::SecureUi),
        "secure-ui.service",
        &arguments,
        posix_endpoint,
    )
}

fn session_user(uid: u32) -> Option<mochios_user_database::UserRecord> {
    use mochios_user_database::{DATABASE_PATH, UserDatabase};

    let bytes = std::fs::read(DATABASE_PATH).ok()?;
    let database = UserDatabase::parse(&bytes).ok()?;
    database.find_uid(uid).cloned()
}
