#[path = "../../service-manager/src/orchestration.rs"]
#[allow(dead_code)]
mod orchestration;
#[path = "../../service-manager/src/service_config.rs"]
#[allow(dead_code)]
mod service_config;

#[test]
fn drivers_inherit_posix_and_do_not_use_legacy_filesystem_syscalls() {
    let launcher = include_str!("../../service-manager/src/service_launcher.rs");
    let start = launcher.find("pub(crate) fn spawn_drivers(").unwrap();
    let end = launcher[start..]
        .find("pub(crate) fn spawn_fixed_service(")
        .unwrap()
        + start;
    assert!(
        launcher[start..end].contains("append_posix_handle(&mut arguments, Some(posix_endpoint))")
    );
    let manifest = include_str!("../../drivers/src/driver_manifest.rs");
    let discovery = include_str!("../../drivers/src/driver_discovery.rs");
    assert!(manifest.contains("std::fs::read(&package_manifest_path)"));
    assert!(discovery.contains("std::fs::read_dir(path)"));
    for source in [manifest, discovery] {
        assert!(!source.contains("platform::file::"));
    }
}
extern crate alloc;

