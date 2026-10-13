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
    assert!(launcher[start..end].contains("spawn_native(DRIVERS, \"drivers.service\""));
    assert!(!launcher[start..end].contains("spawn(DRIVERS,"));
    let bootstrap = include_str!("../../service-manager/src/bootstrap.rs");
    let controller = include_str!("../../service-manager/src/driver_controller.rs");
    assert!(bootstrap.contains("type DriversProcess = NativeProcess;"));
    assert!(bootstrap.contains("wait_for_hello(process.watch_target())"));
    assert!(bootstrap.contains("wait_for_complete(process.watch_target())"));
    assert!(!controller.contains("drivers_process: u64"));
    assert!(controller.contains("ProcessWatch::open(target)"));
    let manifest = include_str!("../../drivers/src/driver_manifest.rs");
    let discovery = include_str!("../../drivers/src/driver_discovery.rs");
    assert!(manifest.contains("std::fs::read(&package_manifest_path)"));
    assert!(discovery.contains("std::fs::read_dir(path)"));
    for source in [manifest, discovery] {
        assert!(!source.contains("platform::file::"));
    }
}
extern crate alloc;

#[test]
fn only_namespace_bootstrap_can_use_the_legacy_fixed_launcher() {
    use service_config::FixedService;
    assert!(FixedService::Filesystem.is_namespace_bootstrap());
    assert!(FixedService::Posix.is_namespace_bootstrap());
    for service in [
        FixedService::MbootAgent,
        FixedService::Input,
        FixedService::Display,
        FixedService::Compositor,
        FixedService::Network,
        FixedService::User,
        FixedService::SecureUi,
        FixedService::Linux,
        FixedService::Binder,
        FixedService::Installer,
        FixedService::Update,
        FixedService::Workspace,
    ] {
        assert!(!service.is_namespace_bootstrap(), "{service:?}");
    }
}
