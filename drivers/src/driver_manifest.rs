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
    let bytes = match platform::file::read_to_end_path(&package_manifest_path) {
        Ok(bytes) => bytes,
        Err(err) => {
            platform::println!(
                "drivers.service: rejected bundle={} reason=manifest-read path={} errno={}",
                bundle_root,
                package_manifest_path,
                err.errno().unwrap_or(0)
            );
            return None;
        }
    };
    let text = match core::str::from_utf8(&bytes) {
        Ok(text) => text,
        Err(_) => {
            platform::println!(
                "drivers.service: rejected bundle={} reason=manifest-encoding path={}",
                bundle_root,
                package_manifest_path
            );
            return None;
        }
    };
    let Some(manifest) = platform::package::parse_manifest(text) else {
        platform::println!(
            "drivers.service: rejected bundle={} reason=manifest-invalid path={}",
            bundle_root,
            package_manifest_path
        );
        return None;
    };
    let entry_path = alloc::format!("{}/entry.elf", bundle_root);
    if manifest.binary(&entry_path).is_none() {
        platform::println!(
            "drivers.service: rejected bundle={} reason=missing-entry entry={} manifest={}",
            bundle_root,
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
