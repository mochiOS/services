#![no_std]

extern crate alloc;

mod driver_discovery;
mod driver_manifest;
mod driver_matcher;
mod driver_spawn;
mod readiness;
mod service_launcher;
mod spawn_support;

use mochi_user_platform as platform;

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
    driver_spawn::spawn(entry_path, None, logger_endpoint);
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
