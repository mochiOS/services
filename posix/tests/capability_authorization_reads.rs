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
    pub(crate) fn is_known_capability(_: &str) -> bool {
        true
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
    let bytes = include_bytes!("../../capability/manifest.toml").to_vec();
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
    FILES.with_borrow(|files| assert_eq!(files.reads, [RECORD, MANIFEST]));
}
