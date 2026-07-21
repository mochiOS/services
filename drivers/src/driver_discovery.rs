use alloc::string::String;
use alloc::vec::Vec;

use mochi_user_platform as platform;

const DRIVER_BUNDLE_ROOTS: &[&str] = &["/bin/drivers/usb", "/bin/drivers/ps2"];

pub(crate) fn roots() -> &'static [&'static str] {
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

pub(crate) fn visit_bundles(bundle_root_path: &str, mut visit: impl FnMut(&str)) {
    let bundle_roots = read_dir_names(bundle_root_path);
    for bundle in bundle_roots {
        if !bundle.ends_with(".driver") {
            continue;
        }
        let bundle_root = alloc::format!("{}/{}", bundle_root_path, bundle);
        visit(&bundle_root);
    }
}
