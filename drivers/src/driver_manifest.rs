use alloc::string::String;

use mochi_user_platform as platform;

pub(crate) struct DriverManifest {
    pub(crate) manifest: platform::package::PackageManifest,
    pub(crate) entry_path: String,
}

fn bundle_manifest_path(bundle_root: &str) -> String {
    alloc::format!(
        "/system/packages{}/manifest.toml",
        bundle_root.trim_start_matches("/bin")
    )
}

pub(crate) fn load(bundle_root: &str) -> Option<DriverManifest> {
    let package_manifest_path = bundle_manifest_path(bundle_root);
    let Some(manifest) = platform::package::read_manifest(&package_manifest_path) else {
        platform::println!("drivers.service: missing {}", package_manifest_path);
        return None;
    };
    let entry_path = alloc::format!("{}/entry.elf", bundle_root);
    if manifest.binary(&entry_path).is_none() {
        platform::println!(
            "drivers.service: missing binary entry {} in {}",
            entry_path,
            package_manifest_path
        );
        return None;
    }
    Some(DriverManifest {
        manifest,
        entry_path,
    })
}
