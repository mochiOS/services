//! Code authentication for the requester's existing address space. This gate
//! neither creates a process nor changes identity, capabilities or consent.
use alloc::{string::String, vec::Vec};
use mochi_user_platform as p;
use mochi_user_syscall::{EACCES, EINVAL, SysError};
use sha2::{Digest, Sha256};

fn denied() -> SysError {
    SysError::from_raw(EACCES as i64)
}

pub(crate) fn verify(
    state: &crate::state::CapabilityServiceState,
    sender: u64,
    bytes: &[u8],
    attached: &p::ipc::IpcObjectHandles,
) -> Result<[u8; 32], SysError> {
    let length = p::capability::library_image::decode(bytes)
        .map_err(|_| SysError::from_raw(EINVAL as i64))?;
    if !attached.is_user_delivery() || attached.count != 1 {
        return Err(SysError::from_raw(EINVAL as i64));
    }
    let object = attached.handles[0];
    if object.handle == 0 || object.reserved != 0 {
        return Err(SysError::from_raw(EINVAL as i64));
    }
    if object.rights != p::memory_object::READONLY_BUFFER_RIGHTS {
        return Err(denied());
    }
    // The endpoint and process measurement must remain the same across capture,
    // package verification and every capability query. Never trust a supplied
    // PID, path, digest or identity. The Process handle pins this observation.
    let before = p::execution_peer::capture(sender)?;
    let source = crate::signed_image::capture(object.handle, length)?;
    let digest = authorize_snapshot(state, sender, &source)?;
    let after = p::execution_peer::capture(sender)?;
    if before.image != after.image || before.context != after.context {
        return Err(denied());
    }
    Ok(digest)
}

pub(crate) fn authorize_snapshot(
    state: &crate::state::CapabilityServiceState,
    sender: u64,
    source: &[u8],
) -> Result<[u8; 32], SysError> {
    let digest = Sha256::digest(source).into();
    let installed = crate::installed_image::select_library(
        &state.package_index,
        &digest,
        source.len() as u64,
        crate::persistent_grant::read_file,
    )?;
    let requested = if let Some(selection) = &installed {
        selection.authority().1
    } else {
        // Ad-hoc integrity is sufficient for same-domain code without claims
        // of signer identity. Keyed standalone files require an authenticated
        // installed record; accepting an arbitrary caller key is unnecessary.
        let evidence = crate::signed_image::verify_snapshot(None, source)?;
        return check(sender, &standalone_requirements(&evidence)?).map(|()| digest);
    };
    check(sender, requested)?;
    Ok(digest)
}

fn check(sender: u64, requested: &[String]) -> Result<(), SysError> {
    for name in requested {
        mnu_abi::capability::metadata(name).ok_or_else(denied)?;
        if p::capability::check_thread(sender, name)? != 1 {
            return Err(denied());
        }
    }
    Ok(())
}

fn standalone_requirements(
    image: &mochios_elf_signature::VerifiedImage<'_>,
) -> Result<Vec<String>, SysError> {
    let Some(text) = image.manifest() else {
        return Ok(Vec::new());
    };
    let mut manifest = p::package::parse_manifest(text).ok_or_else(denied)?;
    if manifest.binaries.len() != 1
        || manifest.linux.is_some()
        || !matches!(
            manifest.package_kind.as_deref(),
            None | Some("library" | "binary")
        )
    {
        return Err(denied());
    }
    let binary = manifest.binaries.pop().unwrap();
    if binary.kind.as_deref() != Some("library") || binary.capability_profile.is_some() {
        return Err(denied());
    }
    // A development signature must not declare privileged/internal authority,
    // even when the calling service happens to hold it.
    for name in &binary.requires {
        if !mnu_abi::capability::metadata(name).is_some_and(|m| m.user_grantable && m.delegable) {
            return Err(denied());
        }
    }
    Ok(binary.requires)
}
