extern crate alloc;

use mochi_user_platform::{package, syscall};
use mochios_signature_protocol::{InstallProvenance, InstallRecord, VerifiedResponse};
use sha2::{Digest, Sha256};
use std::cell::RefCell;
use std::collections::BTreeMap;

mod package_index {
    use super::*;
    pub(crate) struct PackageRecord {
        pub(crate) manifest: package::PackageManifest,
        pub(crate) manifest_path: String,
    }
    pub(crate) struct PackageIndex {
        pub(crate) duplicate: bool,
        pub(crate) by_binary: BTreeMap<String, PackageRecord>,
    }
}
mod policy {
    pub(crate) fn is_known_capability(name: &str) -> bool {
        mnu_abi::capability::metadata(name).is_some()
    }
}
#[allow(dead_code)]
#[path = "../../capability/src/image_catalog.rs"]
mod image_catalog;
#[path = "support/package_image_catalog.rs"]
mod package_image_catalog;
#[allow(dead_code)]
#[path = "../../capability/src/resolver.rs"]
mod resolver;

const MANIFEST: &str = "/system/packages/capability/manifest.toml";
const RECORD: &str = "/system/packages/capability/verification.bin";
const BINARY: &str = "/system/services/capability.service";

#[test]
#[ignore = "requires MOCHIOS_TEST_BOUND_PACKAGES and MOCHIOS_TEST_BOUND_ROOTFS"]
fn generated_builtin_records_authenticate_every_installed_code_binding() {
    use mochios_posix_client::image_preparation::Source;
    use std::path::{Path, PathBuf};
    fn collect(directory: &Path, out: &mut Vec<PathBuf>) {
        for entry in std::fs::read_dir(directory).unwrap() {
            let entry = entry.unwrap();
            if entry.file_type().unwrap().is_dir() {
                collect(&entry.path(), out);
            } else if entry.file_name() == "manifest.toml" {
                out.push(entry.path());
            }
        }
    }
    let packages = PathBuf::from(std::env::var_os("MOCHIOS_TEST_BOUND_PACKAGES").unwrap());
    let rootfs = PathBuf::from(std::env::var_os("MOCHIOS_TEST_BOUND_ROOTFS").unwrap());
    let mut manifests = Vec::new();
    collect(&packages, &mut manifests);
    manifests.sort();
    assert!(!manifests.is_empty());
    let mut paths = std::collections::BTreeSet::new();
    let mut binaries = 0;
    for source in &manifests {
        let declaration = std::fs::read(source).unwrap();
        let manifest_path = format!(
            "/system/packages/{}",
            source.strip_prefix(&packages).unwrap().display()
        );
        let record_path = manifest_path
            .strip_suffix("manifest.toml")
            .unwrap()
            .to_owned()
            + "verification.bin";
        let record = std::fs::read(source.with_file_name("verification.bin")).unwrap();
        let manifest = package::parse_manifest(std::str::from_utf8(&declaration).unwrap()).unwrap();
        FILES.with_borrow_mut(|files| {
            *files = Files::default();
            files
                .bytes
                .insert(manifest_path.clone(), declaration.clone());
            files.bytes.insert(record_path, record);
        });
        for binary in &manifest.binaries {
            assert!(
                paths.insert(binary.path.clone()),
                "duplicate code path {}",
                binary.path
            );
            assert!(binary.file.is_some(), "unbound code {}", binary.path);
            // Explicit host build mapping, not a runtime pathname fallback.
            let path = binary
                .path
                .strip_prefix("/bin/")
                .map(|tail| format!("system/bin/{tail}"))
                .unwrap_or_else(|| binary.path.strip_prefix('/').unwrap().into());
            let mut bytes = std::fs::read(rootfs.join(path)).unwrap();
            assert!(!bytes.is_empty());
            let verified = resolver::verified_manifest(&manifest_path, read_file).unwrap();
            let decision = verified.decide_capabilities(&binary.path).unwrap();
            assert!(decision.is_allowed(), "{}", binary.path);
            assert!(
                decision
                    .requested
                    .iter()
                    .all(|name| mnu_abi::capability::metadata(name).is_some())
            );
            let catalog = if binary.kind.as_deref() == Some("application") {
                Some(image_catalog::Catalog::new(verified, &binary.path).unwrap())
            } else {
                None
            };
            let validate = |bytes: &[u8]| {
                if let Some(catalog) = &catalog {
                    catalog.validate(Source::Root, bytes)
                } else {
                    image_catalog::validate_declared_root(&manifest, &binary.path, bytes)
                }
            };
            assert_eq!(validate(&bytes), Ok(()), "{}", binary.path);
            let last = bytes.len() - 1;
            bytes[last] ^= 1;
            assert!(validate(&bytes).is_err(), "modified code {}", binary.path);
            bytes[last] ^= 1;
            assert!(
                validate(&bytes[..last]).is_err(),
                "truncated code {}",
                binary.path
            );
            bytes.push(0);
            assert!(validate(&bytes).is_err(), "extended code {}", binary.path);
            binaries += 1;
        }
        FILES.with_borrow_mut(|files| {
            files
                .bytes
                .get_mut(&manifest_path)
                .unwrap()
                .extend_from_slice(b"\n# changed manifest\n")
        });
        assert!(resolver::verified_manifest(&manifest_path, read_file).is_err());
    }
    eprintln!(
        "Authenticated {} packages and {binaries} code bindings through the production resolver and catalog",
        manifests.len()
    );
}

#[test]
#[ignore = "requires MOCHIOS_TEST_DEVELOPMENT_PACKAGE and MOCHIOS_TEST_DEVELOPMENT_PREFIX"]
fn generated_tool_catalog_authenticates_exact_real_code_without_shell_identity() {
    use mochios_posix_client::image_preparation::Source;
    use std::path::PathBuf;
    let package_root = PathBuf::from(std::env::var_os("MOCHIOS_TEST_DEVELOPMENT_PACKAGE").unwrap());
    let prefix = PathBuf::from(std::env::var_os("MOCHIOS_TEST_DEVELOPMENT_PREFIX").unwrap());
    let declaration = std::fs::read(package_root.join("manifest.toml")).unwrap();
    let record = std::fs::read(package_root.join("verification.bin")).unwrap();
    let manifest_path = "/system/packages/development-tools/manifest.toml";
    let record_path = "/system/packages/development-tools/verification.bin";
    let manifest = package::parse_manifest(std::str::from_utf8(&declaration).unwrap()).unwrap();
    assert_eq!(manifest.package_id, "org.mochios.development-tools");
    assert_eq!(manifest.binaries.len(), 4);
    for name in ["clang", "ld.lld", "ld", "msign"] {
        FILES.with_borrow_mut(|files| {
            *files = Files::default();
            files
                .bytes
                .insert(manifest_path.into(), declaration.clone());
            files.bytes.insert(record_path.into(), record.clone());
        });
        let path = format!("/system/developer/bin/{name}");
        let verified = resolver::verified_manifest(manifest_path, read_file).unwrap();
        let decision = verified.decide_capabilities(&path).unwrap();
        assert!(decision.is_allowed());
        assert_eq!(decision.requested.len(), 7);
        for capability in &decision.requested {
            assert!(mnu_abi::capability::metadata(capability).is_some());
        }
        let catalog = image_catalog::Catalog::new(verified, &path).unwrap();
        assert_eq!(catalog.identity().package_id, manifest.package_id);
        assert_ne!(catalog.identity().package_id, "org.mochios.msh");
        assert_eq!(catalog.identity().provenance, InstallProvenance::BuiltIn);
        let bytes = std::fs::read(prefix.join("bin").join(name)).unwrap();
        assert!(!bytes.is_empty());
        assert_eq!(catalog.validate(Source::Root, &bytes), Ok(()));
        let mut changed = bytes.clone();
        changed[0] ^= 1;
        assert!(catalog.validate(Source::Root, &changed).is_err());
        assert!(
            catalog
                .validate(Source::Root, &bytes[..bytes.len() - 1])
                .is_err()
        );
        changed.clone_from(&bytes);
        changed.push(0);
        assert!(catalog.validate(Source::Root, &changed).is_err());
        FILES.with_borrow_mut(|files| {
            files
                .bytes
                .get_mut(manifest_path)
                .unwrap()
                .extend_from_slice(b"\n# replaced declaration\n");
        });
        assert_eq!(catalog.validate(Source::Root, &bytes), Ok(()));
        assert!(resolver::verified_manifest(manifest_path, read_file).is_err());
    }
}

#[derive(Default)]
struct Files {
    bytes: BTreeMap<String, Vec<u8>>,
    reads: Vec<String>,
    error: Option<syscall::SysError>,
}
thread_local! { static FILES: RefCell<Files> = RefCell::new(Files::default()); }

fn read_file(path: &str) -> Result<Vec<u8>, syscall::SysError> {
    FILES.with_borrow_mut(|files| {
        files.reads.push(path.into());
        if let Some(error) = files.error {
            return Err(error);
        }
        files
            .bytes
            .get(path)
            .cloned()
            .ok_or(syscall::SysError::from_raw(syscall::ENOENT as i64))
    })
}

fn fixture() -> package::PackageManifest {
    fixture_text(include_str!("../../capability/manifest.toml"))
}

fn fixture_text(text: &str) -> package::PackageManifest {
    let bytes = text.as_bytes().to_vec();
    let manifest = package::parse_manifest(std::str::from_utf8(&bytes).unwrap()).unwrap();
    let digest: [u8; 32] = Sha256::digest(&bytes).into();
    let caps = manifest
        .binary_requires(BINARY)
        .unwrap()
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>();
    let record = InstallRecord {
        provenance: InstallProvenance::BuiltIn,
        verification: VerifiedResponse {
            request_id: 0,
            provenance: InstallProvenance::BuiltIn,
            certificate_serial: 0,
            subject_key_id: [0; 32],
            manifest_digest: digest,
            package_digest: digest,
            developer_id: "org.mochios.system",
            verified_package_id: &manifest.package_id,
            allowed_capabilities: &caps,
        },
    };
    let mut encoded = vec![0; record.encoded_len()];
    record.encode(&mut encoded).unwrap();
    FILES.with_borrow_mut(|files| {
        *files = Files::default();
        files.bytes.insert(MANIFEST.into(), bytes);
        files.bytes.insert(RECORD.into(), encoded);
    });
    manifest
}

#[test]
fn certificate_and_identity_use_only_the_selected_reader() {
    let manifest = fixture();
    let decision =
        resolver::decide_binary_capabilities(&manifest, MANIFEST, BINARY, read_file).unwrap();
    assert!(decision.is_allowed());
    let identity = resolver::application_identity(&manifest, MANIFEST, read_file).unwrap();
    assert_eq!(identity.package_id, manifest.package_id);
    assert_eq!(identity.developer_id, "org.mochios.system");
    assert_eq!(
        FILES.with_borrow(|files| files.reads.clone()),
        [RECORD, MANIFEST, RECORD, MANIFEST]
    );
}

#[test]
fn selected_reader_failures_are_not_retried_through_another_backend() {
    for status in [syscall::EAGAIN, syscall::EIO, syscall::EACCES] {
        let manifest = fixture();
        let error = syscall::SysError::from_raw(status as i64);
        FILES.with_borrow_mut(|files| files.error = Some(error));
        assert_eq!(
            resolver::application_identity(&manifest, MANIFEST, read_file).err(),
            Some(error)
        );
        assert_eq!(
            resolver::decide_binary_capabilities(&manifest, MANIFEST, BINARY, read_file).err(),
            Some(error)
        );
        let identity = resolver::ApplicationIdentity {
            package_id: manifest.package_id.clone(),
            developer_id: "org.mochios.system".into(),
            subject_key_id: [0; 32],
            provenance: InstallProvenance::BuiltIn,
        };
        assert_eq!(
            resolver::authorize_spawn(
                0,
                BINARY,
                &identity,
                &[],
                mochi_user_platform::service::ExecutionClass::Unprivileged,
                read_file
            ),
            Err(error)
        );
        assert_eq!(
            FILES.with_borrow(|files| files.reads.clone()),
            [RECORD, RECORD, BINARY]
        );
    }
}

#[test]
fn modified_manifest_and_missing_provenance_still_deny_authorization() {
    let manifest = fixture();
    FILES.with_borrow_mut(|files| {
        files
            .bytes
            .get_mut(MANIFEST)
            .unwrap()
            .extend_from_slice(b"\n# modified\n")
    });
    assert_eq!(
        resolver::application_identity(&manifest, MANIFEST, read_file)
            .err()
            .unwrap()
            .raw(),
        syscall::EACCES as i64
    );
    let decision =
        resolver::decide_binary_capabilities(&manifest, MANIFEST, BINARY, read_file).unwrap();
    assert_eq!(
        decision.deny_reason,
        Some(resolver::CapabilityDenyReason::ManifestMismatch)
    );
    assert!(!decision.is_allowed());
    FILES.with_borrow_mut(|files| {
        files.bytes.remove(RECORD);
    });
    let decision =
        resolver::decide_binary_capabilities(&manifest, MANIFEST, BINARY, read_file).unwrap();
    assert_eq!(
        decision.deny_reason,
        Some(resolver::CapabilityDenyReason::MissingProvenance)
    );
    assert!(!decision.is_allowed());
    assert_eq!(
        decision.into_allowed().err().unwrap().raw(),
        syscall::EACCES as i64
    );
}

#[test]
fn capability_allowance_and_manifest_policy_are_one_authenticated_snapshot() {
    let original = fixture();
    let snapshot = resolver::verified_manifest(MANIFEST, read_file).unwrap();
    FILES.with_borrow_mut(|files| {
        files.error = Some(syscall::SysError::from_raw(syscall::EIO as i64))
    });
    let decision = snapshot.decide_capabilities(BINARY).unwrap();
    assert!(decision.is_allowed());
    assert_eq!(
        decision.requested,
        original.binary_requires(BINARY).unwrap()
    );
    assert_eq!(
        decision.into_allowed().unwrap(),
        original.binary_requires(BINARY).unwrap()
    );
    FILES.with_borrow(|files| assert_eq!(files.reads, [RECORD, MANIFEST]));
}

#[test]
fn authenticated_unknown_capabilities_cannot_be_published_to_native_authorization() {
    let text = include_str!("../../capability/manifest.toml").replacen(
        "requires = [",
        "requires = [\n\"unknown.capability\",",
        1,
    );
    fixture_text(&text);
    let snapshot = resolver::verified_manifest(MANIFEST, read_file).unwrap();
    let decision = snapshot.decide_capabilities(BINARY).unwrap();
    assert_eq!(
        decision.deny_reason,
        Some(resolver::CapabilityDenyReason::UnknownCapability)
    );
    assert_eq!(
        decision.into_allowed().err().unwrap().raw(),
        syscall::EINVAL as i64
    );
    FILES.with_borrow(|files| assert_eq!(files.reads, [RECORD, MANIFEST]));
}
