use mochi_user_platform as platform;

use crate::service_config::{
    DRIVERS, FixedService, ReadyTarget, ServiceSpec, driver_arguments, fixed_service_arguments,
    fixed_service_spec, mboot_agent_arguments,
};
use crate::spawn_support::{encode_spawn_args, resolve_capabilities, sys_error};

const SESSION_USER_ARG_PREFIX: &str = "--session-user=";
const LOCK_USER_ARG_PREFIX: &str = "--lock-user=";
const EXEC_MANIFEST_ENV_PREFIX: &str = "__MOCHI_EXEC_ENV=";
const EXEC_MANIFEST_APP_ID_PREFIX: &str = "__MOCHI_EXEC_APP_ID=";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct DriverManagerTarget {
    pub(crate) endpoint: u64,
    pub(crate) token: u64,
}

fn spawn(
    spec: ServiceSpec,
    arguments: &[alloc::string::String],
) -> Result<u64, mochi_user_syscall::SysError> {
    let manifest = platform::package::read_manifest(spec.manifest_path)
        .ok_or_else(|| sys_error(mochi_user_syscall::ENOENT))?;
    let mut arguments = arguments.to_vec();
    if spec.role == crate::service_config::ROLE_APPLICATION {
        arguments.insert(
            0,
            alloc::format!("{EXEC_MANIFEST_APP_ID_PREFIX}{}", manifest.package_id),
        );
    }
    let arguments = encode_spawn_args(&arguments);
    let capabilities = resolve_capabilities(spec.path)?;
    platform::service::spawn_manifest(
        spec.path,
        spec.role,
        Some(arguments.as_slice()),
        Some(capabilities.as_slice()),
    )
}

fn spawn_with_credentials(
    spec: ServiceSpec,
    arguments: &[alloc::string::String],
    identity: platform::service_ready::SessionIdentity,
) -> Result<u64, mochi_user_syscall::SysError> {
    let manifest = platform::package::read_manifest(spec.manifest_path)
        .ok_or_else(|| sys_error(mochi_user_syscall::ENOENT))?;
    let mut arguments = arguments.to_vec();
    if spec.role == crate::service_config::ROLE_APPLICATION {
        arguments.insert(
            0,
            alloc::format!("{EXEC_MANIFEST_APP_ID_PREFIX}{}", manifest.package_id),
        );
    }
    let arguments = encode_spawn_args(&arguments);
    let capabilities = resolve_capabilities(spec.path)?;
    platform::service::spawn_manifest_with_credentials(
        spec.path,
        spec.role,
        identity.uid,
        identity.gid,
        Some(arguments.as_slice()),
        Some(capabilities.as_slice()),
    )
}

pub(crate) fn spawn_drivers(
    logger_endpoint: u64,
    manager: DriverManagerTarget,
) -> Result<u64, mochi_user_syscall::SysError> {
    spawn(
        DRIVERS,
        &driver_arguments(logger_endpoint, manager.endpoint, manager.token),
    )
}

pub(crate) fn spawn_fixed_service(
    service: FixedService,
    logger_endpoint: u64,
    ready_target: Option<platform::service_ready::Target>,
) -> Result<u64, mochi_user_syscall::SysError> {
    let ready_target = ready_target.map(|target| ReadyTarget {
        endpoint: target.endpoint,
        token: target.token,
    });
    let arguments = fixed_service_arguments(service, logger_endpoint, ready_target);
    spawn(fixed_service_spec(service), &arguments)
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
) -> Result<u64, mochi_user_syscall::SysError> {
    let mut arguments = fixed_service_arguments(service, logger_endpoint, None);
    if let Some(user) = session_user(identity.uid) {
        arguments.push(alloc::format!("{SESSION_USER_ARG_PREFIX}{}", user.name));
        for (name, value) in [
            ("HOME", user.home.as_str()),
            ("USER", user.name.as_str()),
            ("LOGNAME", user.name.as_str()),
            ("SHELL", "/bin/msh"),
        ] {
            arguments.push(alloc::format!("{EXEC_MANIFEST_ENV_PREFIX}{name}={value}"));
        }
        arguments.push(alloc::format!(
            "{EXEC_MANIFEST_ENV_PREFIX}MOCHI_SESSION_ID={session_id}"
        ));
    }
    spawn_with_credentials(fixed_service_spec(service), &arguments, identity)
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
    target: platform::service_ready::Target,
    application: &str,
    path: &str,
    writable: bool,
) -> Result<u64, mochi_user_syscall::SysError> {
    let mut arguments = fixed_service_arguments(FixedService::SecureUi, logger_endpoint, None);
    arguments.push(alloc::format!(
        "--portal-target={}:{}",
        target.endpoint,
        target.token
    ));
    arguments.push(alloc::format!("--portal-application={application}"));
    arguments.push(alloc::format!("--portal-path={path}"));
    arguments.push(alloc::format!(
        "--portal-access={}",
        if writable { "read-write" } else { "read" }
    ));
    spawn(fixed_service_spec(FixedService::SecureUi), &arguments)
}

fn session_user(uid: u32) -> Option<mochios_user_database::UserRecord> {
    use mochios_user_database::{DATABASE_PATH, UserDatabase};

    let bytes = std::fs::read(DATABASE_PATH).ok()?;
    let database = UserDatabase::parse(&bytes).ok()?;
    database.find_uid(uid).cloned()
}
