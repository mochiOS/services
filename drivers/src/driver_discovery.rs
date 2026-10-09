use alloc::string::String;
use alloc::vec::Vec;

use mochi_user_platform as platform;

use crate::driver_matcher::DriverSearchRoot;

const DRIVER_BUNDLE_ROOTS: &[DriverSearchRoot] = &[
    DriverSearchRoot::Usb,
    DriverSearchRoot::Ps2,
    DriverSearchRoot::Network,
];

pub(crate) fn roots() -> &'static [DriverSearchRoot] {
    DRIVER_BUNDLE_ROOTS
}

fn read_dir_names(path: &str) -> Vec<String> {
    let names = std::fs::read_dir(path).and_then(|entries| {
        entries
            .map(|entry| {
                entry?.file_name().into_string().map_err(|_| {
                    std::io::Error::new(std::io::ErrorKind::InvalidData, "non-UTF-8 driver name")
                })
            })
            .collect::<std::io::Result<Vec<_>>>()
    });
    match names {
        Ok(names) => {
            let message = alloc::format!(
                "drivers.service: discovery root={} entries={}\n",
                path,
                names.len()
            );
            let _ = platform::io::stderr(message.as_bytes());
            names
        }
        Err(err) => {
            let message = alloc::format!(
                "drivers.service: discovery root={} errno={}\n",
                path,
                err.raw_os_error().unwrap_or(5)
            );
            let _ = platform::io::stderr(message.as_bytes());
            platform::logln!(
                "drivers.service: open dir failed {} errno={}",
                path,
                err.raw_os_error().unwrap_or(5)
            );
            Vec::new()
        }
    }
}

pub(crate) fn visit_bundles(root: DriverSearchRoot, mut visit: impl FnMut(&str)) {
    let bundle_root_path = root.path();
    let bundle_roots = read_dir_names(bundle_root_path);
    for bundle in bundle_roots {
        if !bundle.ends_with(".driver") {
            continue;
        }
        let bundle_root = alloc::format!("{}/{}", bundle_root_path, bundle);
        visit(&bundle_root);
    }
}
