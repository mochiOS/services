use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use mochi_user_platform as platform;
use sha2::{Digest, Sha256};

#[derive(Default)]
pub(crate) struct PackageIndex {
    pub(crate) by_binary: BTreeMap<String, PackageRecord>,
    pub(crate) by_package: BTreeMap<String, PackageRecord>,
    pub(crate) duplicate: bool,
}

#[derive(Clone)]
pub(crate) struct PackageRecord {
    pub(crate) manifest_path: String,
    manifest_hash: [u8; 32],
}

fn manifest_hash(path: &str) -> Result<[u8; 32], mochi_user_syscall::SysError> {
    let bytes = platform::file::read_to_end_path(path)?;
    let digest = Sha256::digest(&bytes);
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&digest);
    Ok(hash)
}

fn walk_package_tree(path: &str, out: &mut Vec<String>) {
    let Ok(entries) = platform::file::read_dir_names(path) else {
        return;
    };
    for name in entries {
        let child = format!("{}/{}", path.trim_end_matches('/'), name);
        if name == "manifest.toml" {
            out.push(child);
            continue;
        }
        walk_package_tree(&child, out);
    }
}

pub(crate) fn build_package_index() -> PackageIndex {
    let mut manifest_paths = Vec::new();
    walk_package_tree("/system/packages", &mut manifest_paths);
    let mut index = PackageIndex::default();
    for manifest_path in manifest_paths {
        let Some(manifest) = platform::package::read_manifest(&manifest_path) else {
            platform::println!(
                "capability.service: invalid package manifest {}",
                manifest_path
            );
            continue;
        };
        let Ok(hash) = manifest_hash(&manifest_path) else {
            platform::println!(
                "capability.service: failed to hash manifest {}",
                manifest_path
            );
            index.duplicate = true;
            continue;
        };
        let record = PackageRecord {
            manifest_path: manifest_path.clone(),
            manifest_hash: hash,
        };
        if let Some(previous) = index.by_package.get(&manifest.package_id) {
            if previous.manifest_hash != record.manifest_hash {
                platform::println!(
                    "capability.service: duplicate package {} in {} and {}",
                    manifest.package_id,
                    previous.manifest_path,
                    manifest_path
                );
                index.duplicate = true;
                continue;
            }
        } else {
            index
                .by_package
                .insert(manifest.package_id.clone(), record.clone());
        }
        for binary in manifest.binaries {
            if let Some(previous) = index.by_binary.get(&binary.path) {
                if previous.manifest_hash != record.manifest_hash {
                    platform::println!(
                        "capability.service: duplicate binary {} in {} and {}",
                        binary.path,
                        previous.manifest_path,
                        manifest_path
                    );
                    index.duplicate = true;
                }
            } else {
                index.by_binary.insert(binary.path.clone(), record.clone());
            }
        }
    }
    index
}

pub(crate) fn service_binary_path(manifest: &platform::package::PackageManifest) -> Option<&str> {
    manifest
        .binaries
        .iter()
        .find(|binary| binary.kind.as_deref() == Some("service"))
        .map(|binary| binary.path.as_str())
}

pub(crate) fn package_manifest_by_id(
    index: &PackageIndex,
    package_id: &str,
) -> Result<platform::package::PackageManifest, mochi_user_syscall::SysError> {
    if let Some(manifest_path) = index.by_package.get(package_id) {
        return platform::package::read_manifest(&manifest_path.manifest_path).ok_or_else(|| {
            mochi_user_syscall::SysError::from_raw(mochi_user_syscall::EINVAL as i64)
        });
    }

    if let Some(package_dir) = package_id.rsplit('.').next() {
        let fallback_path = format!("/system/packages/{}/manifest.toml", package_dir);
        if let Some(manifest) = platform::package::read_manifest(&fallback_path) {
            if manifest.package_id == package_id {
                return Ok(manifest);
            }
            return Err(mochi_user_syscall::SysError::from_raw(
                mochi_user_syscall::EINVAL as i64,
            ));
        }
    }

    Err(mochi_user_syscall::SysError::from_raw(
        mochi_user_syscall::ENOENT as i64,
    ))
}
