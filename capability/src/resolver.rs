use alloc::string::String;
use alloc::vec::Vec;

use mochi_user_platform as platform;

use crate::package_index::build_package_index;
use crate::policy::validate_capabilities;

pub(crate) fn encode_nul_list(items: &[String]) -> Vec<u8> {
    let mut out = Vec::new();
    for item in items {
        out.extend_from_slice(item.as_bytes());
        out.push(0);
    }
    out
}

pub(crate) fn binary_caps<'a>(
    manifest: &'a platform::package::PackageManifest,
    binary_path: &str,
) -> Result<&'a [String], mochi_user_syscall::SysError> {
    let caps = manifest
        .binary_requires(binary_path)
        .ok_or_else(|| mochi_user_syscall::SysError::from_raw(mochi_user_syscall::EINVAL as i64))?;
    validate_capabilities(binary_path, caps)?;
    Ok(caps)
}

pub(crate) fn resolve_capabilities_for_path(
    binary_path: &str,
) -> Result<Vec<String>, mochi_user_syscall::SysError> {
    let index = build_package_index();
    if index.duplicate {
        return Err(mochi_user_syscall::SysError::from_raw(
            mochi_user_syscall::EINVAL as i64,
        ));
    }
    let manifest_path = index
        .by_binary
        .get(binary_path)
        .ok_or_else(|| mochi_user_syscall::SysError::from_raw(mochi_user_syscall::ENOENT as i64))?;
    let manifest = platform::package::read_manifest(&manifest_path.manifest_path)
        .ok_or_else(|| mochi_user_syscall::SysError::from_raw(mochi_user_syscall::EINVAL as i64))?;
    let caps = binary_caps(&manifest, binary_path)?;
    Ok(caps.to_vec())
}
