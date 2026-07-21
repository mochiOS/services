use alloc::string::String;
use alloc::vec::Vec;

use mochi_user_platform as platform;

use crate::driver_matcher::DriverSearchRoot;

const DRIVER_BUNDLE_ROOTS: &[DriverSearchRoot] = &[DriverSearchRoot::Usb, DriverSearchRoot::Ps2];

pub(crate) fn roots() -> &'static [DriverSearchRoot] {
    DRIVER_BUNDLE_ROOTS
}

fn read_dir_names(path: &str) -> Vec<String> {
    match platform::file::read_dir_names(path) {
        Ok(names) => names,
        Err(err) => {
            platform::println!(
                "drivers.service: open dir failed {} errno={}",
                path,
                err.errno().unwrap_or(0)
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
