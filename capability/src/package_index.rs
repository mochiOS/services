use alloc::collections::BTreeMap;
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
    pub(crate) manifest: platform::package::PackageManifest,
    manifest_hash: [u8; 32],
}

pub(crate) fn build_package_index() -> Result<PackageIndex, platform::syscall::SysError> {
    let manifest_paths = crate::package_walk::manifest_paths(platform::file::read_dir_names)?;
    let mut manifests = Vec::new();
    for manifest_path in manifest_paths {
        let bytes = platform::file::read_to_end_path(&manifest_path)?;
        manifests.push((manifest_path, bytes));
    }
    Ok(index_manifests(manifests))
}

pub(crate) fn build_runtime_package_index() -> Result<PackageIndex, platform::syscall::SysError> {
    let paths = crate::package_walk::manifest_paths(crate::persistent_grant::read_dir_names)?;
    let mut manifests = Vec::new();
    for path in paths {
        let bytes = crate::persistent_grant::read_file(&path)?;
        manifests.push((path, bytes));
    }
    Ok(index_manifests(manifests))
}

fn index_manifests(manifests: Vec<(String, Vec<u8>)>) -> PackageIndex {
    let mut index = PackageIndex::default();
    for (manifest_path, bytes) in manifests {
        let Ok(text) = core::str::from_utf8(&bytes) else {
            platform::logln!(
                "capability.service: invalid package manifest {}",
                manifest_path
            );
            continue;
        };
        let Some(manifest) = platform::package::parse_manifest(text) else {
            platform::logln!(
                "capability.service: invalid package manifest {}",
                manifest_path
            );
            continue;
        };
        let digest = Sha256::digest(&bytes);
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&digest);
        let record = PackageRecord {
            manifest_path: manifest_path.clone(),
            manifest: manifest.clone(),
            manifest_hash: hash,
        };
        if let Some(previous) = index.by_package.get(&manifest.package_id) {
            if previous.manifest_hash != record.manifest_hash {
                platform::logln!(
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
                    platform::logln!(
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
) -> Result<(platform::package::PackageManifest, String), platform::syscall::SysError> {
    if index.duplicate {
        return Err(platform::syscall::SysError::from_raw(
            platform::syscall::EEXIST as i64,
        ));
    }
    if let Some(record) = index.by_package.get(package_id) {
        return Ok((record.manifest.clone(), record.manifest_path.clone()));
    }

    Err(platform::syscall::SysError::from_raw(
        platform::syscall::ENOENT as i64,
    ))
}
