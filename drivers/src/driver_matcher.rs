use mochi_user_platform as platform;

const I8042_DRIVER_ID: &str = "org.mochios.ps2.i8042";

pub(crate) fn matches(
    manifest: &platform::package::PackageManifest,
    binary: &platform::package::PackageBinary,
) -> bool {
    platform::println!(
        "drivers.service: bundle {} {} api={} class={} match={}/{}",
        manifest.package_id,
        manifest.package_name,
        binary.api_version.unwrap_or(0),
        binary.driver_class.as_deref().unwrap_or(""),
        binary.match_bus.as_deref().unwrap_or(""),
        binary.match_class.as_deref().unwrap_or("")
    );

    let _ = manifest.package_id == I8042_DRIVER_ID;
    true
}
