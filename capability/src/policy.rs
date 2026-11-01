use alloc::collections::BTreeSet;
use alloc::string::String;

use mochi_user_platform as platform;

use crate::package_index::PackageIndex;

const CAPABILITY_PACKAGE_ID: &str = "org.mochios.capability";

#[derive(Default)]
pub(crate) struct AppPromptPolicy {
    interactive: BTreeSet<String>,
}

pub(crate) fn load_app_prompt_policy(
    index: &PackageIndex,
) -> Result<AppPromptPolicy, mochi_user_syscall::SysError> {
    parse_app_prompt_policy(index, crate::bootstrap_file::read_file)
}

pub(crate) fn load_runtime_app_prompt_policy(
    index: &PackageIndex,
) -> Result<AppPromptPolicy, mochi_user_syscall::SysError> {
    parse_app_prompt_policy(index, crate::persistent_grant::read_file)
}

fn parse_app_prompt_policy(
    index: &PackageIndex,
    read: crate::resolver::FileReader,
) -> Result<AppPromptPolicy, mochi_user_syscall::SysError> {
    use mochi_user_syscall::{EACCES, EINVAL, ENOENT, SysError};
    use mochios_signature_protocol::InstallProvenance;
    let record = index
        .by_package
        .get(CAPABILITY_PACKAGE_ID)
        .ok_or_else(|| SysError::from_raw(ENOENT as i64))?;
    let verified = crate::resolver::verified_manifest(&record.manifest_path, read)?;
    let identity = verified.identity;
    if identity.package_id != CAPABILITY_PACKAGE_ID
        || identity.developer_id != "org.mochios.system"
        || identity.provenance != InstallProvenance::BuiltIn
        || identity.subject_key_id != [0; 32]
    {
        return Err(SysError::from_raw(EACCES as i64));
    }
    let mut policy = AppPromptPolicy::default();
    for capability in verified.manifest.interactive_capabilities {
        if platform::capability::capability_from_string(&capability)
            != platform::capability::CapabilityClass::UserGrantable
        {
            return Err(SysError::from_raw(EINVAL as i64));
        }
        policy.interactive.insert(capability);
    }
    Ok(policy)
}

pub(crate) fn needs_app_prompt(policy: &AppPromptPolicy, capability: &str) -> bool {
    policy.interactive.contains(capability)
}

pub(crate) fn is_known_capability(name: &str) -> bool {
    mnu_abi::capability::metadata(name).is_some()
}

pub(crate) fn validate_capabilities(
    binary_path: &str,
    caps: &[String],
) -> Result<(), mochi_user_syscall::SysError> {
    for cap in caps {
        if !is_known_capability(cap.as_str()) {
            platform::logln!(
                "capability.service: unknown capability {} requested by {}",
                cap,
                binary_path
            );
            return Err(mochi_user_syscall::SysError::from_raw(
                mochi_user_syscall::EINVAL as i64,
            ));
        }
    }
    Ok(())
}
