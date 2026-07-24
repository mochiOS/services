use mochi_user_platform as platform;

use crate::service_config::{
    DRIVERS, FixedService, ReadyTarget, ServiceSpec, driver_arguments, fixed_service_arguments,
    fixed_service_spec,
};
use crate::spawn_support::{encode_spawn_args, resolve_capabilities, sys_error};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct DriverManagerTarget {
    pub(crate) endpoint: u64,
    pub(crate) token: u64,
}

fn spawn(
    spec: ServiceSpec,
    arguments: &[alloc::string::String],
) -> Result<u64, mochi_user_syscall::SysError> {
    let _manifest = platform::package::read_manifest(spec.manifest_path)
        .ok_or_else(|| sys_error(mochi_user_syscall::ENOENT))?;
    let arguments = encode_spawn_args(arguments);
    let capabilities = resolve_capabilities(spec.path)?;
    platform::service::spawn_manifest(
        spec.path,
        spec.role,
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
    spawn(
        fixed_service_spec(service),
        &fixed_service_arguments(logger_endpoint, ready_target),
    )
}
