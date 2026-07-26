use alloc::string::String;
use alloc::vec::Vec;

use mochi_user_platform as platform;
use mochios_signature_protocol::VerifiedView;
use sha2::{Digest, Sha256};

use crate::package_index::PackageIndex;
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
    validate_certificate_capabilities(manifest, caps)?;
    Ok(caps)
}

fn validate_certificate_capabilities(
    manifest: &platform::package::PackageManifest,
    requested: &[String],
) -> Result<(), mochi_user_syscall::SysError> {
    let package_root = alloc::format!("/system/packages/{}", manifest.package_id);
    let verification_path = alloc::format!("{package_root}/verification.bin");
    let verification_bytes = match platform::file::read_to_end_path(&verification_path) {
        Ok(bytes) => bytes,
        Err(error) if error.errno() == Some(mochi_user_syscall::ENOENT.wrapping_neg()) => {
            return Ok(());
        }
        Err(error) => return Err(error),
    };
    let verified = VerifiedView::decode(&verification_bytes)
        .map_err(|_| mochi_user_syscall::SysError::from_raw(mochi_user_syscall::EACCES as i64))?;
    if verified.request_id != 0 || verified.verified_package_id != manifest.package_id {
        return Err(mochi_user_syscall::SysError::from_raw(
            mochi_user_syscall::EACCES as i64,
        ));
    }
    let manifest_path = alloc::format!("{package_root}/manifest.toml");
    let manifest_bytes = platform::file::read_to_end_path(&manifest_path)?;
    if Sha256::digest(&manifest_bytes).as_slice() != verified.manifest_digest {
        return Err(mochi_user_syscall::SysError::from_raw(
            mochi_user_syscall::EACCES as i64,
        ));
    }
    for capability in requested {
        let mut allowed = false;
        for certificate_capability in verified.allowed_capabilities() {
            let certificate_capability = certificate_capability.map_err(|_| {
                mochi_user_syscall::SysError::from_raw(mochi_user_syscall::EACCES as i64)
            })?;
            if certificate_capability == capability {
                allowed = true;
                break;
            }
        }
        if !allowed {
            platform::println!(
                "capability.service: certificate denies required capability {} for {}",
                capability,
                manifest.package_id
            );
            return Err(mochi_user_syscall::SysError::from_raw(
                mochi_user_syscall::EACCES as i64,
            ));
        }
    }
    Ok(())
}

pub(crate) fn resolve_capabilities_for_path(
    index: &PackageIndex,
    binary_path: &str,
) -> Result<Vec<String>, mochi_user_syscall::SysError> {
    if index.duplicate {
        return Err(mochi_user_syscall::SysError::from_raw(
            mochi_user_syscall::EINVAL as i64,
        ));
    }
    let manifest_path = index
        .by_binary
        .get(binary_path)
        .ok_or_else(|| mochi_user_syscall::SysError::from_raw(mochi_user_syscall::ENOENT as i64))?;
    let caps = binary_caps(&manifest_path.manifest, binary_path)?;
    Ok(caps.to_vec())
}
