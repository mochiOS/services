use mochi_user_platform as platform;
use mochios_driver_control_protocol::DiscoveryResult;

use crate::{driver_discovery, driver_manifest, driver_matcher, driver_registry, driver_spawn};

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

pub(crate) fn run(logger_endpoint: u64, mut progress: impl FnMut()) -> DiscoveryResult {
    let mut started_drivers = driver_registry::StartedDrivers::new();
    for &root in driver_discovery::roots() {
        driver_discovery::visit_bundles(root, |bundle_root| {
            maybe_spawn_bundle(root, bundle_root, logger_endpoint, &mut started_drivers);
            progress();
        });
        progress();
    }
    DiscoveryResult { status: 0 }
}
