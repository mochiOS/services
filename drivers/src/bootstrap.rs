use mochi_user_platform as platform;

use crate::{
    driver_discovery, driver_manifest, driver_matcher, driver_registry, driver_spawn, readiness,
    service_launcher,
};

fn maybe_spawn_bundle(
    root: driver_matcher::DriverSearchRoot,
    bundle_root: &str,
    logger_endpoint: u64,
    started_drivers: &mut driver_registry::StartedDrivers,
) {
    let Some(bundle) = driver_manifest::load(bundle_root) else {
        return;
    };
    let manifest = &bundle.manifest;
    let entry_path = &bundle.entry_path;
    let Some(binary) = manifest.binary(entry_path) else {
        return;
    };

    platform::println!(
        "drivers.service: bundle {} {} api={} class={} match={}/{}",
        manifest.package_id,
        manifest.package_name,
        binary.api_version.unwrap_or(0),
        binary.driver_class.as_deref().unwrap_or(""),
        binary.match_bus.as_deref().unwrap_or(""),
        binary.match_class.as_deref().unwrap_or("")
    );
    let match_result = driver_matcher::matches(
        root,
        &manifest.package_id,
        binary.driver_class.as_deref(),
        binary.match_bus.as_deref(),
        binary.match_class.as_deref(),
    );
    if match_result != driver_matcher::MatchResult::Matched {
        platform::println!(
            "drivers.service: rejected bundle={} package={} root={} reason={}",
            bundle_root,
            manifest.package_id,
            root.path(),
            match_result.reason()
        );
        return;
    }
    platform::println!(
        "drivers.service: matched bundle={} package={} root={}",
        bundle_root,
        manifest.package_id,
        root.path()
    );
    if started_drivers.contains(&manifest.package_id) {
        platform::println!(
            "drivers.service: skipped duplicate bundle={} package={}",
            bundle_root,
            manifest.package_id
        );
        return;
    }
    if driver_spawn::spawn(entry_path, None, logger_endpoint) {
        started_drivers.record(manifest.package_id.clone());
    }
}

fn wait_for_ready(service: readiness::ServiceKind, process_id: u64) -> bool {
    platform::println!("drivers.service: waiting for {} ready", service.name());
    match readiness::wait_for_service_ready(service, process_id) {
        Ok(()) => {
            platform::println!("drivers.service: {} ready", service.name());
            true
        }
        Err(readiness::ReadyError::InvalidMessage) => {
            platform::println!(
                "drivers.service: invalid ready message from {}",
                service.name()
            );
            false
        }
        Err(readiness::ReadyError::Failed(status)) => {
            platform::println!(
                "drivers.service: {} ready failed status={}",
                service.name(),
                status
            );
            false
        }
        Err(readiness::ReadyError::TimedOut) => {
            platform::println!("drivers.service: {} ready timeout", service.name());
            false
        }
        Err(readiness::ReadyError::ProcessExited(status)) => {
            platform::println!(
                "drivers.service: {} exited before ready status={}",
                service.name(),
                status
            );
            false
        }
        Err(readiness::ReadyError::Ipc(errno)) => {
            platform::println!(
                "drivers.service: {} ready IPC failed errno={}",
                service.name(),
                errno
            );
            false
        }
        Err(readiness::ReadyError::Clock(errno)) => {
            platform::println!(
                "drivers.service: {} ready clock failed errno={}",
                service.name(),
                errno
            );
            false
        }
        Err(readiness::ReadyError::ProcessWait(errno)) => {
            platform::println!(
                "drivers.service: {} ready process wait failed errno={}",
                service.name(),
                errno
            );
            false
        }
    }
}

pub(crate) fn run() -> ! {
    platform::println!("drivers.service: start");
    let logger_endpoint = platform::logger::endpoint().unwrap_or(0);
    let Some(input_process) = service_launcher::launch_input_service(logger_endpoint) else {
        readiness::idle();
    };
    let Some(display_process) = service_launcher::launch_display_service(logger_endpoint) else {
        readiness::idle();
    };
    if !wait_for_ready(readiness::ServiceKind::Display, display_process) {
        readiness::idle();
    }
    if !wait_for_ready(readiness::ServiceKind::Input, input_process) {
        readiness::idle();
    }
    service_launcher::launch_compositor_service(logger_endpoint);
    let mut started_drivers = driver_registry::StartedDrivers::new();
    for &root in driver_discovery::roots() {
        driver_discovery::visit_bundles(root, |bundle_root| {
            maybe_spawn_bundle(root, bundle_root, logger_endpoint, &mut started_drivers);
        });
    }
    service_launcher::launch_tty_service(logger_endpoint);

    readiness::idle()
}
