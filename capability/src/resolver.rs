use alloc::string::String;
use alloc::vec::Vec;

use mochi_user_platform as platform;
use mochios_signature_protocol::{InstallProvenance, InstallRecordView};
use sha2::{Digest, Sha256};

use crate::package_index::PackageIndex;
use crate::policy::validate_capabilities;

const BUILT_IN_DEVELOPER_ID: &str = "org.mochios.system";

fn install_record_matches_manifest(
    manifest: &platform::package::PackageManifest,
    record: &InstallRecordView<'_>,
) -> bool {
    let verified = record.verification;
    if verified.request_id != 0
        || verified.verified_package_id != manifest.package_id
        || verified.provenance != record.provenance
    {
        return false;
    }
    match record.provenance {
        InstallProvenance::BuiltIn => {
            manifest.install_provenance.as_deref() == Some("built-in")
                && verified.developer_id == BUILT_IN_DEVELOPER_ID
                && verified.certificate_serial == 0
                && verified.subject_key_id == [0; 32]
                && verified.package_digest == verified.manifest_digest
        }
        InstallProvenance::VerifiedPackage | InstallProvenance::Development => {
            manifest.install_provenance.as_deref() != Some("built-in")
        }
    }
}

fn package_root_from_manifest_path(
    manifest_path: &str,
) -> Result<&str, mochi_user_syscall::SysError> {
    manifest_path
        .strip_suffix("/manifest.toml")
        .filter(|root| root.starts_with("/system/packages/") && root.len() > 17)
        .ok_or_else(|| mochi_user_syscall::SysError::from_raw(mochi_user_syscall::EINVAL as i64))
}

#[derive(Clone)]
pub(crate) struct ApplicationIdentity {
    pub(crate) package_id: String,
    pub(crate) developer_id: String,
    pub(crate) subject_key_id: [u8; 32],
    pub(crate) provenance: InstallProvenance,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CapabilityDenyReason {
    UnknownCapability,
    MissingProvenance,
    InvalidInstallRecord,
    ManifestMismatch,
    CertificateAllowance,
    UserGrant,
    CallerCeiling,
}

#[derive(Clone, Debug)]
pub(crate) struct EffectiveCapabilityDecision {
    pub(crate) requested: Vec<String>,
    pub(crate) certificate_allowed: Vec<String>,
    pub(crate) system_allowed: Vec<String>,
    pub(crate) user_allowed: Vec<String>,
    pub(crate) caller_allowed: Vec<String>,
    pub(crate) effective: Vec<String>,
    pub(crate) denied: Vec<String>,
    pub(crate) deny_reason: Option<CapabilityDenyReason>,
}

impl EffectiveCapabilityDecision {
    pub(crate) fn is_allowed(&self) -> bool {
        self.deny_reason.is_none() && self.denied.is_empty()
    }

    pub(crate) fn apply_runtime_constraints(
        mut self,
        user_allowed: &[String],
        caller_allowed: &[String],
    ) -> Self {
        self.user_allowed = self
            .requested
            .iter()
            .filter(|requested| user_allowed.iter().any(|allowed| allowed == *requested))
            .cloned()
            .collect();
        self.caller_allowed = self
            .requested
            .iter()
            .filter(|requested| caller_allowed.iter().any(|allowed| allowed == *requested))
            .cloned()
            .collect();
        self.effective = self
            .requested
            .iter()
            .filter(|requested| {
                self.certificate_allowed
                    .iter()
                    .any(|allowed| allowed == *requested)
                    && self
                        .system_allowed
                        .iter()
                        .any(|allowed| allowed == *requested)
                    && self
                        .user_allowed
                        .iter()
                        .any(|allowed| allowed == *requested)
                    && self
                        .caller_allowed
                        .iter()
                        .any(|allowed| allowed == *requested)
            })
            .cloned()
            .collect();
        self.denied = self
            .requested
            .iter()
            .filter(|requested| !self.effective.iter().any(|allowed| allowed == *requested))
            .cloned()
            .collect();
        if self.deny_reason.is_none() && self.user_allowed.len() != self.requested.len() {
            self.deny_reason = Some(CapabilityDenyReason::UserGrant);
        }
        if self.deny_reason.is_none() && self.caller_allowed.len() != self.requested.len() {
            self.deny_reason = Some(CapabilityDenyReason::CallerCeiling);
        }
        self
    }
}

pub(crate) fn decide_binary_capabilities(
    manifest: &platform::package::PackageManifest,
    manifest_path: &str,
    binary_path: &str,
) -> Result<EffectiveCapabilityDecision, mochi_user_syscall::SysError> {
    let requested = manifest
        .binary_requires(binary_path)
        .ok_or_else(|| {
            mochi_user_syscall::SysError::from_raw(mochi_user_syscall::EINVAL as i64)
        })?
        .to_vec();
    let system_allowed = requested
        .iter()
        .filter(|capability| crate::policy::is_known_capability(capability.as_str()))
        .cloned()
        .collect::<Vec<_>>();
    let mut deny_reason = (system_allowed.len() != requested.len())
        .then_some(CapabilityDenyReason::UnknownCapability);

    let package_root = package_root_from_manifest_path(manifest_path)?;
    let verification_path = alloc::format!("{package_root}/verification.bin");
    let mut certificate_allowed = Vec::new();
    match platform::file::read_to_end_path(&verification_path) {
        Ok(bytes) => match InstallRecordView::decode(&bytes) {
            Ok(record) => {
                let verified = record.verification;
                if !install_record_matches_manifest(manifest, &record) {
                    deny_reason.get_or_insert(CapabilityDenyReason::InvalidInstallRecord);
                } else {
                    let manifest_bytes = platform::file::read_to_end_path(manifest_path)?;
                    if Sha256::digest(&manifest_bytes).as_slice() != verified.manifest_digest {
                        deny_reason.get_or_insert(CapabilityDenyReason::ManifestMismatch);
                    }
                    for capability in verified.allowed_capabilities() {
                        match capability {
                            Ok(capability) => certificate_allowed.push(capability.into()),
                            Err(_) => {
                                deny_reason
                                    .get_or_insert(CapabilityDenyReason::InvalidInstallRecord);
                                break;
                            }
                        }
                    }
                }
            }
            Err(_) => {
                deny_reason.get_or_insert(CapabilityDenyReason::InvalidInstallRecord);
            }
        },
        Err(error) if error.errno() == Some(mochi_user_syscall::ENOENT.wrapping_neg()) => {
            deny_reason.get_or_insert(CapabilityDenyReason::MissingProvenance);
        }
        Err(error) => return Err(error),
    }
    if requested.iter().any(|requested| {
        !certificate_allowed
            .iter()
            .any(|allowed| allowed == requested)
    }) {
        deny_reason.get_or_insert(CapabilityDenyReason::CertificateAllowance);
    }

    let decision = EffectiveCapabilityDecision {
        requested,
        certificate_allowed,
        system_allowed,
        user_allowed: Vec::new(),
        caller_allowed: Vec::new(),
        effective: Vec::new(),
        denied: Vec::new(),
        deny_reason,
    };
    let permissive_ceiling = decision.requested.clone();
    Ok(decision.apply_runtime_constraints(&permissive_ceiling, &permissive_ceiling))
}

pub(crate) fn application_identity(
    manifest: &platform::package::PackageManifest,
    manifest_path: &str,
) -> Result<ApplicationIdentity, mochi_user_syscall::SysError> {
    let package_root = package_root_from_manifest_path(manifest_path)?;
    let verification_path = alloc::format!("{package_root}/verification.bin");
    let verification_bytes = platform::file::read_to_end_path(&verification_path)?;
    let record = InstallRecordView::decode(&verification_bytes)
        .map_err(|_| mochi_user_syscall::SysError::from_raw(mochi_user_syscall::EACCES as i64))?;
    if !install_record_matches_manifest(manifest, &record) {
        return Err(mochi_user_syscall::SysError::from_raw(
            mochi_user_syscall::EACCES as i64,
        ));
    }
    let manifest_bytes = platform::file::read_to_end_path(manifest_path)?;
    if Sha256::digest(&manifest_bytes).as_slice() != record.verification.manifest_digest {
        return Err(mochi_user_syscall::SysError::from_raw(
            mochi_user_syscall::EACCES as i64,
        ));
    }
    let identity = record.application_identity();
    Ok(ApplicationIdentity {
        package_id: identity.package_id.into(),
        developer_id: identity.developer_id.into(),
        subject_key_id: identity.subject_key_id,
        provenance: identity.provenance,
    })
}

pub(crate) fn encode_identity_args(identity: &ApplicationIdentity, out: &mut Vec<String>) {
    use mnu_abi::exec::{
        APPLICATION_DEVELOPER_ID_PREFIX, APPLICATION_PACKAGE_ID_PREFIX,
        APPLICATION_PROVENANCE_PREFIX, APPLICATION_SUBJECT_KEY_ID_PREFIX,
    };
    out.push(alloc::format!(
        "{APPLICATION_PACKAGE_ID_PREFIX}{}",
        identity.package_id
    ));
    out.push(alloc::format!(
        "{APPLICATION_DEVELOPER_ID_PREFIX}{}",
        identity.developer_id
    ));
    let mut key = String::with_capacity(64);
    for byte in identity.subject_key_id {
        use core::fmt::Write;
        let _ = write!(key, "{byte:02x}");
    }
    out.push(alloc::format!("{APPLICATION_SUBJECT_KEY_ID_PREFIX}{key}"));
    let provenance = match identity.provenance {
        InstallProvenance::BuiltIn => "built-in",
        InstallProvenance::VerifiedPackage => "verified-package",
        InstallProvenance::Development => "development",
    };
    out.push(alloc::format!(
        "{APPLICATION_PROVENANCE_PREFIX}{provenance}"
    ));
}

pub(crate) fn encode_nul_list(items: &[String]) -> Vec<u8> {
    let mut out = Vec::new();
    for item in items {
        out.extend_from_slice(item.as_bytes());
        out.push(0);
    }
    out
}

fn encode_authorization_args(
    items: &[String],
) -> Result<Vec<u8>, mochi_user_syscall::SysError> {
    let mut output = Vec::new();
    output.resize(1024, 0);
    let mut cursor = 0usize;
    for item in items {
        let bytes = item.as_bytes();
        if cursor + bytes.len() + 2 > output.len() {
            return Err(mochi_user_syscall::SysError::from_raw(
                mochi_user_syscall::EINVAL as i64,
            ));
        }
        output[cursor..cursor + bytes.len()].copy_from_slice(bytes);
        cursor += bytes.len() + 1;
    }
    Ok(output)
}

pub(crate) fn authorize_spawn(
    requester: u64,
    path: &str,
    identity: &ApplicationIdentity,
    capabilities: &[String],
    execution_class: platform::service::ExecutionClass,
) -> Result<(), mochi_user_syscall::SysError> {
    use mnu_abi::exec::{
        EXECUTABLE_DIGEST_PREFIX, EXEC_AUTHORIZATION_CLASS_PREFIX,
        EXEC_AUTHORIZATION_KIND_PREFIX, EXEC_AUTHORIZATION_KIND_SPAWN,
    };

    let executable = platform::file::read_to_end_path(path)?;
    let digest = Sha256::digest(&executable);
    let mut digest_hex = String::with_capacity(64);
    for byte in digest {
        use core::fmt::Write;
        let _ = write!(digest_hex, "{byte:02x}");
    }
    let mut authorization = Vec::new();
    encode_identity_args(identity, &mut authorization);
    authorization.push(alloc::format!("{EXECUTABLE_DIGEST_PREFIX}{digest_hex}"));
    authorization.push(alloc::format!(
        "{EXEC_AUTHORIZATION_KIND_PREFIX}{EXEC_AUTHORIZATION_KIND_SPAWN}"
    ));
    authorization.push(alloc::format!(
        "{EXEC_AUTHORIZATION_CLASS_PREFIX}{}",
        match execution_class {
            platform::service::ExecutionClass::Privileged => "privileged",
            platform::service::ExecutionClass::Unprivileged => "unprivileged",
        }
    ));
    let identity_nul = encode_authorization_args(&authorization)?;
    platform::service::authorize_exec_for_requester(
        requester,
        path,
        &identity_nul,
        &encode_nul_list(capabilities),
    )
    .map(|_| ())
}

pub(crate) fn encode_exec_authorization_args(
    items: &[String],
) -> Result<Vec<u8>, mochi_user_syscall::SysError> {
    encode_authorization_args(items)
}

pub(crate) fn binary_caps<'a>(
    manifest: &'a platform::package::PackageManifest,
    manifest_path: &str,
    binary_path: &str,
) -> Result<&'a [String], mochi_user_syscall::SysError> {
    let caps = manifest.binary_requires(binary_path).ok_or_else(|| {
        mochi_user_syscall::SysError::from_raw(mochi_user_syscall::EINVAL as i64)
    })?;
    let decision = decide_binary_capabilities(manifest, manifest_path, binary_path)?;
    if !decision.is_allowed() {
        platform::logln!(
            "capability.service: capability decision denied path={} reason={:?}",
            binary_path,
            decision.deny_reason
        );
        let errno = if decision.deny_reason == Some(CapabilityDenyReason::UnknownCapability) {
            mochi_user_syscall::EINVAL
        } else {
            mochi_user_syscall::EACCES
        };
        return Err(mochi_user_syscall::SysError::from_raw(errno as i64));
    }
    Ok(caps)
}

fn validate_certificate_capabilities(
    manifest: &platform::package::PackageManifest,
    manifest_path: &str,
    requested: &[String],
) -> Result<(), mochi_user_syscall::SysError> {
    let package_root = package_root_from_manifest_path(manifest_path)?;
    let verification_path = alloc::format!("{package_root}/verification.bin");
    let verification_bytes = platform::file::read_to_end_path(&verification_path).map_err(|error| {
        if error.errno() == Some(mochi_user_syscall::ENOENT.wrapping_neg()) {
            platform::logln!(
                "capability.service: package {} has no explicit install provenance",
                manifest.package_id
            );
        }
        error
    })?;
    let install_record = InstallRecordView::decode(&verification_bytes)
        .map_err(|_| mochi_user_syscall::SysError::from_raw(mochi_user_syscall::EACCES as i64))?;
    if !install_record_matches_manifest(manifest, &install_record) {
        return Err(mochi_user_syscall::SysError::from_raw(
            mochi_user_syscall::EACCES as i64,
        ));
    }
    let verified = install_record.verification;
    let manifest_bytes = platform::file::read_to_end_path(manifest_path)?;
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
            platform::logln!(
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
    let caps = binary_caps(
        &manifest_path.manifest,
        &manifest_path.manifest_path,
        binary_path,
    )?;
    Ok(caps.to_vec())
}
