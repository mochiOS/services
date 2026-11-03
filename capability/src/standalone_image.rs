//! Policy for the exact standalone source whose integrity has been verified.
use alloc::{string::String, vec::Vec};
use mochi_user_platform as p;
use mochi_user_syscall::{EACCES, EINVAL, NativeError, SysError};
use mochios_elf_signature::VerifiedImage;
use mochios_signature_protocol::InstallProvenance;

use crate::resolver::ApplicationIdentity;

/// Retained policy input for execution or a later asynchronous consent request.
/// Caller paths, claimed publisher/provenance and ambient grants are excluded.
pub(crate) struct Selection {
    pub(crate) identity: ApplicationIdentity,
    pub(crate) requested: Vec<String>,
    digest: [u8; 32],
}

pub(crate) fn select(image: &VerifiedImage<'_>) -> Result<Selection, SysError> {
    let requested = if let Some(text) = image.manifest() {
        let mut manifest =
            p::package::parse_manifest(text).ok_or_else(|| SysError::from_raw(EINVAL as i64))?;
        // A standalone file has no authenticated package catalog selecting a
        // binary. Never guess among entries or use a caller-provided path.
        if manifest.binaries.len() != 1 || manifest.linux.is_some() {
            return Err(SysError::from_raw(EINVAL as i64));
        }
        let binary = manifest.binaries.pop().unwrap();
        if binary
            .kind
            .as_deref()
            .is_some_and(|kind| kind != "application")
            || binary.capability_profile.is_some()
        {
            return Err(SysError::from_raw(EACCES as i64));
        }
        for name in &binary.requires {
            let metadata = mnu_abi::capability::metadata(name)
                .ok_or_else(|| SysError::from_raw(EINVAL as i64))?;
            if metadata.classification
                != mnu_abi::capability::CapabilityClassification::UserGrantable
                || !metadata.user_grantable
                || !metadata.delegable
            {
                return Err(SysError::from_raw(EACCES as i64));
            }
        }
        binary.requires
    } else {
        Vec::new()
    };
    let mut package_id = String::from("local.elf.");
    for byte in image.source_digest() {
        use core::fmt::Write;
        let _ = write!(package_id, "{byte:02x}");
    }
    Ok(Selection {
        identity: ApplicationIdentity {
            package_id,
            developer_id: String::from("org.mochios.local"),
            subject_key_id: image.signature().key_id.unwrap_or([0; 32]),
            provenance: InstallProvenance::Development,
        },
        requested,
        digest: *image.source_digest(),
    })
}

impl Selection {
    pub(crate) fn authority(&self) -> (&ApplicationIdentity, &[String], &[u8; 32]) {
        (&self.identity, &self.requested, &self.digest)
    }

    pub(crate) fn authorize(&self, sender: u64, key: &str) -> Result<(), SysError> {
        // Requested grants remain pending until the shared consent controller
        // owns this exact selection. A caller's existing grants are no consent.
        if !self.requested.is_empty() {
            return Err(SysError::from(NativeError::Unsupported.into_raw()));
        }
        crate::resolver::authorize_image_digest(
            sender,
            key,
            &self.identity,
            &[],
            p::service::ExecutionClass::Unprivileged,
            &self.digest,
            mnu_abi::exec::EXEC_AUTHORIZATION_KIND_IMAGE_REPLACE,
        )
    }
}
