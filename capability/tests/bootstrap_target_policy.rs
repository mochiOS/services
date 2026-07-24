const BOOTSTRAP_SOURCE: &str = include_str!("../src/service_bootstrap.rs");

fn main() {
    assert!(
        BOOTSTRAP_SOURCE
            .contains("const SERVICE_MANAGER_PACKAGE_ID: &str = \"org.mochios.service-manager\";")
    );
    assert_eq!(
        BOOTSTRAP_SOURCE
            .matches("spawn_service_by_package(package_index, SERVICE_MANAGER_PACKAGE_ID)")
            .count(),
        1
    );
    assert!(!BOOTSTRAP_SOURCE.contains("org.mochios.drivers"));
    assert!(!BOOTSTRAP_SOURCE.contains("register_delegate"));
}
