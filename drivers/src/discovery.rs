use mochi_user_platform as platform;
use mochios_driver_control_protocol::DiscoveryResult;

use crate::{driver_discovery, driver_manifest, driver_matcher, driver_registry, driver_spawn};

fn maybe_spawn_bundle(
    root: driver_matcher::DriverSearchRoot,
    bundle_root: &str,
    logger_endpoint: u64,
    posix_endpoint: platform::handle::Handle,
    raw_input: platform::handle::Handle,
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

    platform::logln!(
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
        platform::logln!(
            "drivers.service: rejected bundle={} package={} root={} reason={}",
            bundle_root,
            manifest.package_id,
            root.path(),
            match_result.reason()
        );
        return;
    }
    platform::logln!(
        "drivers.service: matched bundle={} package={} root={}",
        bundle_root,
        manifest.package_id,
        root.path()
    );
    if started_drivers.contains(&manifest.package_id) {
        platform::logln!(
            "drivers.service: skipped duplicate bundle={} package={}",
            bundle_root,
            manifest.package_id
        );
        return;
    }
    if started_drivers.has_failed_cleanup() {
        return;
    }
    match driver_spawn::spawn(
        entry_path,
        None,
        logger_endpoint,
        posix_endpoint,
        raw_input,
        |process| started_drivers.retain_failed(process),
    ) {
        Ok(process) => {
            platform::logln!("drivers.service: active bundle={}", bundle_root);
            started_drivers.record(manifest.package_id.clone(), process);
        }
        Err(error) => eprintln!(
            "drivers.service: native driver creation failed path={entry_path} errno={}",
            error.errno().unwrap_or(0)
        ),
    }
}

pub(crate) fn run(
    logger_endpoint: u64,
    posix_endpoint: platform::handle::Handle,
    raw_input: platform::handle::Handle,
    started_drivers: &mut driver_registry::StartedDrivers,
    mut progress: impl FnMut(),
) -> DiscoveryResult {
    for &root in driver_discovery::roots() {
        driver_discovery::visit_bundles(root, |bundle_root| {
            started_drivers.retry_failed(posix_endpoint);
            maybe_spawn_bundle(
                root,
                bundle_root,
                logger_endpoint,
                posix_endpoint,
                raw_input,
                started_drivers,
            );
            progress();
        });
        progress();
    }
    DiscoveryResult { status: 0 }
}
