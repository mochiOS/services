use alloc::string::{String, ToString};
use alloc::vec::Vec;

pub(crate) const ROLE_SERVICE: u64 = 2;
pub(crate) const ROLE_APPLICATION: u64 = 3;
pub(crate) const SERVICE_READY_TIMEOUT_TICKS: u64 = 5_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FixedService {
    Input,
    Display,
    Compositor,
    Network,
    User,
    SecureUi,
    Binder,
    Update,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ServiceSpec {
    pub(crate) path: &'static str,
    pub(crate) manifest_path: &'static str,
    pub(crate) role: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ReadyTarget {
    pub(crate) endpoint: u64,
    pub(crate) token: u64,
}

pub(crate) const DRIVERS: ServiceSpec = ServiceSpec {
    path: "/system/services/drivers.service",
    manifest_path: "/system/packages/drivers/manifest.toml",
    role: ROLE_SERVICE,
};

pub(crate) const fn fixed_service_spec(service: FixedService) -> ServiceSpec {
    match service {
        FixedService::Input => ServiceSpec {
            path: "/system/services/input.service",
            manifest_path: "/system/packages/input/manifest.toml",
            role: ROLE_SERVICE,
        },
        FixedService::Display => ServiceSpec {
            path: "/system/services/display.driver",
            manifest_path: "/system/packages/display/manifest.toml",
            role: ROLE_SERVICE,
        },
        FixedService::Compositor => ServiceSpec {
            path: "/system/services/compositor.service",
            manifest_path: "/system/packages/compositor/manifest.toml",
            role: ROLE_SERVICE,
        },
        FixedService::Network => ServiceSpec {
            path: "/system/services/network.service",
            manifest_path: "/system/packages/network/manifest.toml",
            role: ROLE_SERVICE,
        },
        FixedService::User => ServiceSpec {
            path: "/system/services/user.service",
            manifest_path: "/system/packages/user/manifest.toml",
            role: ROLE_SERVICE,
        },
        FixedService::SecureUi => ServiceSpec {
            path: "/system/services/secure-ui.service",
            manifest_path: "/system/packages/secure-ui/manifest.toml",
            role: ROLE_SERVICE,
        },
        FixedService::Binder => ServiceSpec {
            path: "/applications/Binder.app/entry.elf",
            manifest_path: "/system/packages/binder/manifest.toml",
            role: ROLE_APPLICATION,
        },
        FixedService::Update => ServiceSpec {
            path: "/system/services/update.service",
            manifest_path: "/system/packages/update/manifest.toml",
            role: ROLE_SERVICE,
        },
    }
}

pub(crate) fn driver_arguments(
    logger_endpoint: u64,
    manager_endpoint: u64,
    token: u64,
) -> Vec<String> {
    let mut arguments = Vec::with_capacity(2);
    arguments.push(logger_endpoint.to_string());
    arguments.push(alloc::format!(
        "--driver-manager={}:{}",
        manager_endpoint,
        token
    ));
    arguments
}

pub(crate) fn fixed_service_arguments(
    service: FixedService,
    logger_endpoint: u64,
    ready_target: Option<ReadyTarget>,
) -> Vec<String> {
    if service == FixedService::Binder {
        return Vec::new();
    }
    let mut arguments = Vec::with_capacity(2);
    arguments.push(logger_endpoint.to_string());
    if let Some(target) = ready_target {
        arguments.push(alloc::format!(
            "--service-ready={}:{}",
            target.endpoint,
            target.token
        ));
    }
    arguments
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_roles_and_manifest_paths_match_fixed_service_policy() {
        assert_eq!(DRIVERS.path, "/system/services/drivers.service");
        assert_eq!(
            DRIVERS.manifest_path,
            "/system/packages/drivers/manifest.toml"
        );
        assert_eq!(DRIVERS.role, ROLE_SERVICE);
        let expected = [
            (
                FixedService::Input,
                "/system/services/input.service",
                "/system/packages/input/manifest.toml",
                ROLE_SERVICE,
            ),
            (
                FixedService::Display,
                "/system/services/display.driver",
                "/system/packages/display/manifest.toml",
                ROLE_SERVICE,
            ),
            (
                FixedService::Compositor,
                "/system/services/compositor.service",
                "/system/packages/compositor/manifest.toml",
                ROLE_SERVICE,
            ),
            (
                FixedService::Binder,
                "/applications/Binder.app/entry.elf",
                "/system/packages/binder/manifest.toml",
                ROLE_APPLICATION,
            ),
            (
                FixedService::Network,
                "/system/services/network.service",
                "/system/packages/network/manifest.toml",
                ROLE_SERVICE,
            ),
            (
                FixedService::User,
                "/system/services/user.service",
                "/system/packages/user/manifest.toml",
                ROLE_SERVICE,
            ),
            (
                FixedService::SecureUi,
                "/system/services/secure-ui.service",
                "/system/packages/secure-ui/manifest.toml",
                ROLE_SERVICE,
            ),
            (
                FixedService::Update,
                "/system/services/update.service",
                "/system/packages/update/manifest.toml",
                ROLE_SERVICE,
            ),
        ];
        for (service, path, manifest_path, role) in expected {
            let spec = fixed_service_spec(service);
            assert_eq!(spec.path, path);
            assert_eq!(spec.manifest_path, manifest_path);
            assert_eq!(spec.role, role);
        }
    }

    #[test]
    fn arguments_preserve_logger_and_add_only_required_control_target() {
        assert_eq!(
            driver_arguments(7, 8, 9),
            alloc::vec!["7".to_string(), "--driver-manager=8:9".to_string(),]
        );
        assert_eq!(
            fixed_service_arguments(
                FixedService::Input,
                7,
                Some(ReadyTarget {
                    endpoint: 8,
                    token: 9,
                }),
            ),
            alloc::vec!["7".to_string(), "--service-ready=8:9".to_string()]
        );
        assert_eq!(
            fixed_service_arguments(FixedService::Compositor, 7, None),
            alloc::vec!["7".to_string()]
        );
        assert_eq!(
            fixed_service_arguments(
                FixedService::SecureUi,
                7,
                Some(ReadyTarget {
                    endpoint: 8,
                    token: 9,
                }),
            ),
            alloc::vec!["7".to_string(), "--service-ready=8:9".to_string()]
        );
        assert!(fixed_service_arguments(FixedService::Binder, 7, None).is_empty());
    }

    #[test]
    fn ready_timeout_matches_fixed_service_policy() {
        assert_eq!(SERVICE_READY_TIMEOUT_TICKS, 5_000);
    }
}
