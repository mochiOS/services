use alloc::string::{String, ToString};
use alloc::vec::Vec;

pub(crate) const ROLE_SERVICE: u64 = 2;
pub(crate) const SERVICE_READY_TIMEOUT_TICKS: u64 = 5_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FixedService {
    Input,
    Display,
    Compositor,
    Tty,
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
        FixedService::Tty => ServiceSpec {
            path: "/system/services/tty.service",
            manifest_path: "/system/packages/tty/manifest.toml",
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
    logger_endpoint: u64,
    ready_target: Option<ReadyTarget>,
) -> Vec<String> {
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
            ),
            (
                FixedService::Display,
                "/system/services/display.driver",
                "/system/packages/display/manifest.toml",
            ),
            (
                FixedService::Compositor,
                "/system/services/compositor.service",
                "/system/packages/compositor/manifest.toml",
            ),
            (
                FixedService::Tty,
                "/system/services/tty.service",
                "/system/packages/tty/manifest.toml",
            ),
        ];
        for (service, path, manifest_path) in expected {
            let spec = fixed_service_spec(service);
            assert_eq!(spec.path, path);
            assert_eq!(spec.manifest_path, manifest_path);
            assert_eq!(spec.role, ROLE_SERVICE);
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
                7,
                Some(ReadyTarget {
                    endpoint: 8,
                    token: 9,
                }),
            ),
            alloc::vec!["7".to_string(), "--service-ready=8:9".to_string()]
        );
        assert_eq!(
            fixed_service_arguments(7, None),
            alloc::vec!["7".to_string()]
        );
    }

    #[test]
    fn ready_timeout_matches_fixed_service_policy() {
        assert_eq!(SERVICE_READY_TIMEOUT_TICKS, 5_000);
    }
}
