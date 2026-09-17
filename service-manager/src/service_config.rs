use alloc::string::{String, ToString};
use alloc::vec::Vec;
use mochi_user_platform::service::ExecutionClass;

pub(crate) const SERVICE_READY_TIMEOUT_TICKS: u64 = 5_000;
pub(crate) const NETWORK_READY_TIMEOUT_TICKS: u64 = 30_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FixedService {
    MbootAgent,
    Input,
    Display,
    Compositor,
    Network,
    User,
    SecureUi,
    Linux,
    Binder,
    Installer,
    Update,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ServiceSpec {
    pub(crate) path: &'static str,
    pub(crate) manifest_path: &'static str,
    pub(crate) execution_class: ExecutionClass,
    pub(crate) security_identity: bool,
}

impl ServiceSpec {
    const fn privileged(path: &'static str, manifest_path: &'static str) -> Self {
        Self {
            path,
            manifest_path,
            execution_class: ExecutionClass::Privileged,
            security_identity: true,
        }
    }

    const fn isolated(path: &'static str, manifest_path: &'static str) -> Self {
        Self {
            path,
            manifest_path,
            execution_class: ExecutionClass::Unprivileged,
            security_identity: true,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ReadyTarget {
    pub(crate) endpoint: u64,
    pub(crate) token: u64,
}

pub(crate) const DRIVERS: ServiceSpec = ServiceSpec::privileged(
    "/system/services/drivers.service",
    "/system/packages/drivers/manifest.toml",
);

pub(crate) const fn fixed_service_spec(service: FixedService) -> ServiceSpec {
    match service {
        FixedService::MbootAgent => ServiceSpec::privileged(
            "/system/services/mboot-agent.service",
            "/system/packages/mboot-agent/manifest.toml",
        ),
        FixedService::Input => ServiceSpec::privileged(
            "/system/services/input.service",
            "/system/packages/input/manifest.toml",
        ),
        FixedService::Display => ServiceSpec::privileged(
            "/system/services/display.driver",
            "/system/packages/display/manifest.toml",
        ),
        FixedService::Compositor => ServiceSpec::privileged(
            "/system/services/compositor.service",
            "/system/packages/compositor/manifest.toml",
        ),
        FixedService::Network => ServiceSpec::privileged(
            "/system/services/network.service",
            "/system/packages/network/manifest.toml",
        ),
        FixedService::User => ServiceSpec::privileged(
            "/system/services/user.service",
            "/system/packages/user/manifest.toml",
        ),
        FixedService::SecureUi => ServiceSpec::privileged(
            "/system/services/secure-ui.service",
            "/system/packages/secure-ui/manifest.toml",
        ),
        FixedService::Linux => ServiceSpec::privileged(
            "/system/services/linux.service",
            "/system/packages/linux/manifest.toml",
        ),
        FixedService::Binder => ServiceSpec::isolated(
            "/applications/Binder.app/entry.elf",
            "/system/packages/binder/manifest.toml",
        ),
        FixedService::Installer => ServiceSpec::isolated(
            "/applications/Installer.app/entry.elf",
            "/system/packages/installer/manifest.toml",
        ),
        FixedService::Update => ServiceSpec::privileged(
            "/system/services/update.service",
            "/system/packages/update/manifest.toml",
        ),
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
    if matches!(service, FixedService::Binder | FixedService::Installer) {
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

pub(crate) fn mboot_agent_arguments(logger_endpoint: u64, stage_token: u64) -> Vec<String> {
    alloc::vec![
        logger_endpoint.to_string(),
        alloc::format!("--mboot-stage-token={stage_token}"),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_classes_and_manifest_paths_match_fixed_service_policy() {
        assert_eq!(DRIVERS.path, "/system/services/drivers.service");
        assert_eq!(
            DRIVERS.manifest_path,
            "/system/packages/drivers/manifest.toml"
        );
        assert_eq!(DRIVERS.execution_class, ExecutionClass::Privileged);
        assert!(DRIVERS.security_identity);
        let expected = [
            (
                FixedService::MbootAgent,
                "/system/services/mboot-agent.service",
                "/system/packages/mboot-agent/manifest.toml",
                ExecutionClass::Privileged,
                true,
            ),
            (
                FixedService::Input,
                "/system/services/input.service",
                "/system/packages/input/manifest.toml",
                ExecutionClass::Privileged,
                true,
            ),
            (
                FixedService::Display,
                "/system/services/display.driver",
                "/system/packages/display/manifest.toml",
                ExecutionClass::Privileged,
                true,
            ),
            (
                FixedService::Compositor,
                "/system/services/compositor.service",
                "/system/packages/compositor/manifest.toml",
                ExecutionClass::Privileged,
                true,
            ),
            (
                FixedService::Linux,
                "/system/services/linux.service",
                "/system/packages/linux/manifest.toml",
                ExecutionClass::Privileged,
                true,
            ),
            (
                FixedService::Binder,
                "/applications/Binder.app/entry.elf",
                "/system/packages/binder/manifest.toml",
                ExecutionClass::Unprivileged,
                true,
            ),
            (
                FixedService::Installer,
                "/applications/Installer.app/entry.elf",
                "/system/packages/installer/manifest.toml",
                ExecutionClass::Unprivileged,
                true,
            ),
            (
                FixedService::Network,
                "/system/services/network.service",
                "/system/packages/network/manifest.toml",
                ExecutionClass::Privileged,
                true,
            ),
            (
                FixedService::User,
                "/system/services/user.service",
                "/system/packages/user/manifest.toml",
                ExecutionClass::Privileged,
                true,
            ),
            (
                FixedService::SecureUi,
                "/system/services/secure-ui.service",
                "/system/packages/secure-ui/manifest.toml",
                ExecutionClass::Privileged,
                true,
            ),
            (
                FixedService::Update,
                "/system/services/update.service",
                "/system/packages/update/manifest.toml",
                ExecutionClass::Privileged,
                true,
            ),
        ];
        for (service, path, manifest_path, execution_class, security_identity) in expected {
            let spec = fixed_service_spec(service);
            assert_eq!(spec.path, path);
            assert_eq!(spec.manifest_path, manifest_path);
            assert_eq!(spec.execution_class, execution_class);
            assert_eq!(spec.security_identity, security_identity);
        }
    }

    #[test]
    fn arguments_preserve_logger_and_add_only_required_control_target() {
        assert_eq!(
            mboot_agent_arguments(7, 9),
            alloc::vec!["7".to_string(), "--mboot-stage-token=9".to_string()]
        );
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
        assert_eq!(NETWORK_READY_TIMEOUT_TICKS, 30_000);
    }
}
