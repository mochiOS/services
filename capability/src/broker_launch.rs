//! The pathname spawn interface is reserved for measured system launchers.
//! Applications use the captured-image and common consent interfaces instead.
use alloc::{string::String, vec::Vec};
use mochi_user_platform as p;
use p::syscall::{EACCES, EINVAL, ENOENT, SysError};

use crate::{
    consent_peer,
    package_index::PackageIndex,
    resolver::{self, FileReader},
    trusted_images::{Role, TrustedImages},
};

fn denied() -> SysError {
    SysError::from_raw(EACCES as i64)
}

fn require_capabilities(sender: u64) -> Result<(), SysError> {
    for capability in ["process.spawn", "fs.read.all"] {
        if p::capability::check_thread(sender, capability)? != 1 {
            return Err(denied());
        }
    }
    Ok(())
}

pub(crate) fn resolve(
    index: &PackageIndex,
    trusted: &TrustedImages,
    sender: u64,
    class: u64,
    path: &str,
    read: FileReader,
) -> Result<(Vec<String>, Vec<String>), SysError> {
    require_capabilities(sender)?;
    let peer = consent_peer::capture(sender)?;
    let role = trusted.role(&peer)?.ok_or_else(denied)?;
    if !matches!(role, Role::SessionOwner | Role::DriverLauncher) || index.duplicate {
        return Err(denied());
    }
    let class = p::service::ExecutionClass::from_raw(class)
        .ok_or_else(|| SysError::from_raw(EINVAL as i64))?;
    let record = index
        .by_binary
        .get(path)
        .ok_or_else(|| SysError::from_raw(ENOENT as i64))?;
    let kind = record
        .manifest
        .binary(path)
        .and_then(|binary| binary.kind.as_deref());
    use p::service::ExecutionClass::{Privileged, Unprivileged};
    if !matches!(
        (role, kind, class),
        (
            Role::SessionOwner,
            Some("service"),
            Privileged | Unprivileged
        ) | (Role::SessionOwner, Some("application"), Unprivileged)
            | (Role::DriverLauncher, Some("driver"), Unprivileged)
    ) {
        return Err(denied());
    }
    let caps = resolver::binary_caps(&record.manifest, &record.manifest_path, path, read)?.to_vec();
    let identity = resolver::application_identity(&record.manifest, &record.manifest_path, read)?;
    let mut fields = Vec::new();
    resolver::encode_identity_args(&identity, &mut fields);
    let image = read(path)?;
    // Retain the Process reference while I/O runs, then reject an image or
    // authority change before publishing a one-shot permit for this sender.
    let current = consent_peer::capture(sender)?;
    if current.instance != peer.instance
        || current.context != peer.context
        || !p::handle::same_object(current.process.0, peer.process.0)?
        || trusted.role(&current)? != Some(role)
    {
        return Err(denied());
    }
    require_capabilities(sender)?;
    resolver::authorize_spawn_image(sender, path, &identity, &caps, class, &image)?;
    Ok((fields, caps))
}
