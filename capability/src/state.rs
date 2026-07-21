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
}
