use crate::package_index::{PackageIndex, build_package_index, build_runtime_package_index};
use crate::policy::{AppPromptPolicy, load_app_prompt_policy, load_runtime_app_prompt_policy};
use mochi_user_platform::syscall;

pub(crate) struct CapabilityServiceState {
    pub(crate) package_index: PackageIndex,
    pub(crate) app_prompt_policy: AppPromptPolicy,
    // Owned solely by this broker, never by a renderer. Transport adapters
    // must authenticate fresh observations before entering this controller.
    pub(crate) consent: crate::consent::Controller,
    pub(crate) authorization_generation: u64,
    pub(crate) trusted_images: crate::trusted_images::TrustedImages,
}

impl CapabilityServiceState {
    pub(crate) fn new() -> Result<Self, syscall::SysError> {
        let package_index = build_package_index()?;
        if package_index.duplicate {
            return Err(syscall::SysError::from_raw(
                mochios_posix_protocol::STATUS_EEXIST as i64,
            ));
        }
        let app_prompt_policy = load_app_prompt_policy(&package_index);
        let trusted_images = crate::trusted_images::TrustedImages::bootstrap(
            &package_index,
            crate::bootstrap_file::read_file,
        )?;
        Ok(Self {
            package_index,
            app_prompt_policy,
            consent: crate::consent::Controller::new(),
            authorization_generation: 1,
            trusted_images,
        })
    }

    pub(crate) fn refresh_package_index(&mut self) -> Result<(), syscall::SysError> {
        let package_index = build_runtime_package_index()?;
        if package_index.duplicate {
            return Err(syscall::SysError::from_raw(
                mochios_posix_protocol::STATUS_EEXIST as i64,
            ));
        }
        let app_prompt_policy = load_runtime_app_prompt_policy(&package_index)?;
        let next_generation = self
            .authorization_generation
            .checked_add(1)
            .ok_or_else(|| {
                syscall::SysError::from_raw(syscall::NativeError::LimitExceeded.into_raw() as i64)
            })?;
        self.package_index = package_index;
        self.app_prompt_policy = app_prompt_policy;
        self.authorization_generation = next_generation;
        Ok(())
    }
}
