//! Path-independent selection of installed code. Index entries are hints;
//! identity, grants and the final digest come from one authenticated snapshot.
use alloc::{string::String, vec::Vec};
use mochi_user_platform as p;
use mochi_user_syscall::{EACCES, EINVAL, NativeError, SysError};

use crate::{
    image_catalog,
    package_index::PackageIndex,
    policy::AppPromptPolicy,
    resolver::{FileReader, VerifiedManifest},
};

pub(crate) struct Selection {
    verified: VerifiedManifest,
    requested: Vec<String>,
    digest: [u8; 32],
}

pub(crate) fn select(
    index: &PackageIndex,
    digest: &[u8; 32],
    length: u64,
    read: FileReader,
) -> Result<Option<Selection>, SysError> {
    if index.duplicate {
        return Err(SysError::from_raw(EACCES as i64));
    }
    let mut selected = None;
    for (path, hint) in &index.by_binary {
        if !image_catalog::declared_root_binding(&hint.manifest, path)
            .is_ok_and(|binding| binding.digest == *digest)
        {
            continue;
        }
        let verified = crate::resolver::verified_manifest(&hint.manifest_path, read)?;
        let binary = verified
            .manifest
            .binary(path)
            .ok_or_else(|| SysError::from_raw(EACCES as i64))?;
        let binding = image_catalog::declared_root_binding(&verified.manifest, path)?;
        if binary.kind.as_deref() != Some("application")
            || binary.capability_profile.is_some()
            || verified.manifest.linux.is_some()
            || !matches!(
                verified.manifest.package_kind.as_deref(),
                None | Some("application" | "binary")
            )
            || binding.digest != *digest
            || binding.size != length
        {
            return Err(SysError::from_raw(EACCES as i64));
        }
        let requested = verified.decide_capabilities(path)?.into_allowed()?;
        if requested
            .iter()
            .any(|name| !crate::policy::is_known_capability(name))
        {
            return Err(SysError::from_raw(EINVAL as i64));
        }
        // Equal bytes with different declarations must not choose an identity
        // or permission set by iteration order. An explicit selector can be
        // added to the common execution request when this case is supported.
        if selected.is_some() {
            return Err(SysError::from_raw(EACCES as i64));
        }
        selected = Some(Selection {
            verified,
            requested,
            digest: *digest,
        });
    }
    Ok(selected)
}

impl Selection {
    pub(crate) fn authority(
        &self,
    ) -> (&crate::resolver::ApplicationIdentity, &[String], &[u8; 32]) {
        (&self.verified.identity, &self.requested, &self.digest)
    }

    pub(crate) fn authorize(
        &self,
        policy: &AppPromptPolicy,
        sender: u64,
        key: &str,
    ) -> Result<(), SysError> {
        if self
            .requested
            .iter()
            .any(|name| crate::policy::needs_app_prompt(policy, name))
        {
            // The shared consent controller must own this continuation. Do not
            // treat either the caller's grants or a claimed Boolean as consent.
            return Err(SysError::from(NativeError::Unsupported.into_raw()));
        }
        crate::resolver::authorize_image_digest(
            sender,
            key,
            &self.verified.identity,
            &self.requested,
            p::service::ExecutionClass::Unprivileged,
            &self.digest,
            mnu_abi::exec::EXEC_AUTHORIZATION_KIND_IMAGE_REPLACE,
        )
    }
}
