use alloc::string::ToString;
use alloc::vec;

use mochi_user_platform as platform;

use crate::spawn_support::{encode_spawn_args, resolve_capabilities, sys_error};

const INPUT_SERVICE_PATH: &str = "/system/services/input.service";
const INPUT_PACKAGE_MANIFEST_PATH: &str = "/system/packages/input/manifest.toml";
const DISPLAY_SERVICE_PATH: &str = "/system/services/display.driver";
const DISPLAY_PACKAGE_MANIFEST_PATH: &str = "/system/packages/display/manifest.toml";
const COMPOSITOR_SERVICE_PATH: &str = "/system/services/compositor.service";
const COMPOSITOR_PACKAGE_MANIFEST_PATH: &str = "/system/packages/compositor/manifest.toml";
const TTY_SERVICE_PATH: &str = "/system/services/tty.service";
const TTY_PACKAGE_MANIFEST_PATH: &str = "/system/packages/tty/manifest.toml";

fn spawn_input_service(logger_endpoint: u64) -> Result<u64, mochi_user_syscall::SysError> {
    let _manifest = platform::package::read_manifest(INPUT_PACKAGE_MANIFEST_PATH)
        .ok_or_else(|| sys_error(mochi_user_syscall::ENOENT))?;
    let args = vec![logger_endpoint.to_string()];
    let args_nul = encode_spawn_args(&args);
    let caps_nul = resolve_capabilities(INPUT_SERVICE_PATH)?;
    platform::service::spawn_manifest(
        INPUT_SERVICE_PATH,
        platform::service::ROLE_SERVICE,
        Some(args_nul.as_slice()),
        Some(caps_nul.as_slice()),
    )
}

fn spawn_named_service(
    service_path: &str,
    manifest_path: &str,
    logger_endpoint: u64,
) -> Result<u64, mochi_user_syscall::SysError> {
    let _manifest = platform::package::read_manifest(manifest_path)
        .ok_or_else(|| sys_error(mochi_user_syscall::ENOENT))?;
    let args = vec![logger_endpoint.to_string()];
    let args_nul = encode_spawn_args(&args);
    let caps_nul = resolve_capabilities(service_path)?;
    platform::service::spawn_manifest(
        service_path,
        platform::service::ROLE_SERVICE,
        Some(args_nul.as_slice()),
        Some(caps_nul.as_slice()),
    )
}

fn spawn_display_service(logger_endpoint: u64) -> Result<u64, mochi_user_syscall::SysError> {
    spawn_named_service(
        DISPLAY_SERVICE_PATH,
        DISPLAY_PACKAGE_MANIFEST_PATH,
        logger_endpoint,
    )
}

fn spawn_compositor_service(logger_endpoint: u64) -> Result<u64, mochi_user_syscall::SysError> {
    spawn_named_service(
        COMPOSITOR_SERVICE_PATH,
        COMPOSITOR_PACKAGE_MANIFEST_PATH,
        logger_endpoint,
    )
}

fn spawn_tty_service(logger_endpoint: u64) -> Result<u64, mochi_user_syscall::SysError> {
    let _manifest = platform::package::read_manifest(TTY_PACKAGE_MANIFEST_PATH)
        .ok_or_else(|| sys_error(mochi_user_syscall::ENOENT))?;
    let args = vec![logger_endpoint.to_string()];
    let args_nul = encode_spawn_args(&args);
    let caps_nul = resolve_capabilities(TTY_SERVICE_PATH)?;
    platform::service::spawn_manifest(
        TTY_SERVICE_PATH,
        platform::service::ROLE_SERVICE,
        Some(args_nul.as_slice()),
        Some(caps_nul.as_slice()),
    )
}

pub(crate) fn launch_input_service(logger_endpoint: u64) -> Option<u64> {
    match spawn_input_service(logger_endpoint) {
        Ok(pid) => {
            platform::println!("drivers.service: input.service spawned pid={}", pid);
            Some(pid)
        }
        Err(err) => {
            platform::println!(
                "drivers.service: input.service spawn failed errno={}",
                err.errno().unwrap_or(0)
            );
            None
        }
    }
}

pub(crate) fn launch_display_service(logger_endpoint: u64) -> Option<u64> {
    match spawn_display_service(logger_endpoint) {
        Ok(pid) => {
            platform::println!("drivers.service: display.driver spawned pid={}", pid);
            Some(pid)
        }
        Err(err) => {
            platform::println!(
                "drivers.service: display.driver spawn failed errno={}",
                err.errno().unwrap_or(0)
            );
            None
        }
    }
}

pub(crate) fn launch_compositor_service(logger_endpoint: u64) {
    match spawn_compositor_service(logger_endpoint) {
        Ok(pid) => platform::println!("drivers.service: compositor.service spawned pid={}", pid),
        Err(err) => platform::println!(
            "drivers.service: compositor.service spawn failed errno={}",
            err.errno().unwrap_or(0)
        ),
    }
}

pub(crate) fn launch_tty_service(logger_endpoint: u64) {
    match spawn_tty_service(logger_endpoint) {
        Ok(pid) => platform::println!("drivers.service: tty.service spawned pid={}", pid),
        Err(err) => platform::println!(
            "drivers.service: tty.service spawn failed errno={}",
            err.errno().unwrap_or(0)
        ),
    }
}
