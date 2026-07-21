#![no_std]

extern crate alloc;

mod driver_discovery;
mod driver_manifest;
mod driver_matcher;
mod readiness;
mod service_launcher;
mod spawn_support;

use alloc::string::ToString;

use mochi_user_platform as platform;

use spawn_support::sys_error;

fn spawn_bundle(
    entry_path: &str,
    args: Option<&[u8]>,
    logger_endpoint: u64,
) -> Result<u64, mochi_user_syscall::SysError> {
    let caps_nul = spawn_support::resolve_capabilities(entry_path)?;
    let mut spawn_args = alloc::vec::Vec::new();
    if let Some(args) = args {
        let text = core::str::from_utf8(args).map_err(|_| sys_error(mochi_user_syscall::EINVAL))?;
        for part in text.split('\0') {
            if !part.is_empty() {
                spawn_args.push(part.to_string());
            }
        }
    }
    if logger_endpoint != 0 {
        spawn_args.push(logger_endpoint.to_string());
    }
    let args_nul = spawn_support::encode_spawn_args(&spawn_args);
    platform::service::spawn_manifest(
        entry_path,
        platform::service::ROLE_DRIVER,
        Some(args_nul.as_slice()),
        Some(caps_nul.as_slice()),
    )
}

fn maybe_spawn_bundle(bundle_root: &str, logger_endpoint: u64) {
    let Some(bundle) = driver_manifest::load(bundle_root) else {
        return;
    };
    let manifest = &bundle.manifest;
    let entry_path = &bundle.entry_path;
    let Some(binary) = manifest.binary(entry_path) else {
        return;
    };

    let _ = driver_matcher::matches(manifest, binary);
    match spawn_bundle(entry_path, None, logger_endpoint) {
        Ok(pid) => {
            platform::println!("drivers.service: spawned driver pid={}", pid);
        }
        Err(err) => {
            platform::println!(
                "drivers.service: spawn failed {} errno={}",
                entry_path,
                err.errno().unwrap_or(0)
            );
        }
    }
}

pub fn run(sp: *const usize) -> ! {
    unsafe {
        let _ = platform::logger::init_from_initial_stack(sp);
    }
    platform::println!("drivers.service: start");
    let logger_endpoint = platform::logger::endpoint().unwrap_or(0);
    match service_launcher::spawn_input_service(logger_endpoint) {
        Ok(pid) => platform::println!("drivers.service: input.service spawned pid={}", pid),
        Err(err) => platform::println!(
            "drivers.service: input.service spawn failed errno={}",
            err.errno().unwrap_or(0)
        ),
    }
    match service_launcher::spawn_display_service(logger_endpoint) {
        Ok(pid) => platform::println!("drivers.service: display.driver spawned pid={}", pid),
        Err(err) => platform::println!(
            "drivers.service: display.driver spawn failed errno={}",
            err.errno().unwrap_or(0)
        ),
    }
    if !readiness::wait_for_process(service_launcher::DISPLAY_SERVICE_NAME) {
        platform::println!(
            "drivers.service: {} not registered before compositor spawn",
            service_launcher::DISPLAY_SERVICE_NAME
        );
    }
    if !readiness::wait_for_process(service_launcher::INPUT_SERVICE_NAME) {
        platform::println!(
            "drivers.service: {} not registered before compositor spawn",
            service_launcher::INPUT_SERVICE_NAME
        );
    }
    match service_launcher::spawn_compositor_service(logger_endpoint) {
        Ok(pid) => platform::println!("drivers.service: compositor.service spawned pid={}", pid),
        Err(err) => platform::println!(
            "drivers.service: compositor.service spawn failed errno={}",
            err.errno().unwrap_or(0)
        ),
    }
    for bundle_root_path in driver_discovery::roots() {
        driver_discovery::visit_bundles(bundle_root_path, |bundle_root| {
            maybe_spawn_bundle(bundle_root, logger_endpoint);
        });
    }
    match service_launcher::spawn_tty_service(logger_endpoint) {
        Ok(pid) => platform::println!("drivers.service: tty.service spawned pid={}", pid),
        Err(err) => platform::println!(
            "drivers.service: tty.service spawn failed errno={}",
            err.errno().unwrap_or(0)
        ),
    }

    readiness::idle()
}
