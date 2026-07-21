use mochi_user_platform as platform;

use crate::{
    driver_discovery, driver_manifest, driver_matcher, driver_spawn, readiness, service_launcher,
};

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

pub(crate) fn run() -> ! {
    platform::println!("drivers.service: start");
    let logger_endpoint = platform::logger::endpoint().unwrap_or(0);
    service_launcher::launch_input_service(logger_endpoint);
    service_launcher::launch_display_service(logger_endpoint);
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
    service_launcher::launch_compositor_service(logger_endpoint);
    for bundle_root_path in driver_discovery::roots() {
        driver_discovery::visit_bundles(bundle_root_path, |bundle_root| {
            maybe_spawn_bundle(bundle_root, logger_endpoint);
        });
    }
    service_launcher::launch_tty_service(logger_endpoint);

    readiness::idle()
}
