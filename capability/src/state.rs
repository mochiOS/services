use crate::package_index::{PackageIndex, build_package_index};
use crate::policy::{AppPromptPolicy, load_app_prompt_policy};

pub(crate) struct CapabilityServiceState {
    pub(crate) package_index: PackageIndex,
    pub(crate) app_prompt_policy: AppPromptPolicy,
}

impl CapabilityServiceState {
    pub(crate) fn new() -> Self {
        let package_index = build_package_index();
        let app_prompt_policy = load_app_prompt_policy(&package_index);
        Self {
            package_index,
            app_prompt_policy,
        }
    }

    pub(crate) fn refresh_package_index(
        &mut self,
    ) -> Result<(), mochi_user_syscall::SysError> {
        let package_index = build_package_index();
        if package_index.duplicate {
            return Err(mochi_user_syscall::SysError::from_raw(
                mochi_user_syscall::EEXIST as i64,
            ));
        }
        let app_prompt_policy = load_app_prompt_policy(&package_index);
        self.package_index = package_index;
        self.app_prompt_policy = app_prompt_policy;
        Ok(())
    }
}
