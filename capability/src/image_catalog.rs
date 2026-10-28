//! Inputs approved by the launching application's authenticated manifest.
//! This policy grants nothing: native creation still authorizes the prepared
//! output separately, after every captured input has passed this check.
use alloc::{string::String, vec::Vec};
use mochi_user_platform::{package, syscall};
use mochios_posix_client::image_preparation::Source;
use sha2::{Digest, Sha256};

use crate::resolver::{ApplicationIdentity, VerifiedManifest};

struct Image {
    path: String,
    size: u64,
    digest: [u8; 32],
}

/// Each library must be an explicit `kind = "library"` binary with a `file`
/// binding in this manifest. Merely being installed or signed by another
/// package does not authorize code to receive this application's capabilities.
pub(crate) struct Catalog {
    root: Image,
    libraries: Vec<Image>,
    identity: ApplicationIdentity,
}

fn denied() -> syscall::SysError {
    syscall::SysError::from_raw(syscall::EACCES as i64)
}

fn absolute(path: &str) -> bool {
    path.starts_with('/')
        && !path.contains(['\0', '\\'])
        && path[1..]
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != "..")
}

fn target(manifest: &package::PackageManifest, path: &str) -> Option<String> {
    let result = if path.starts_with('/') {
        String::from(path)
    } else {
        let relative = path.strip_prefix("$/")?;
        // These are the package installer's bundle target rules. The final
        // canonical-path check also rejects traversal through the package name.
        alloc::format!("/applications/{}.app/{relative}", manifest.package_name)
    };
    absolute(&result).then_some(result)
}

fn image(
    manifest: &package::PackageManifest,
    binary: &package::PackageBinary,
) -> Result<Image, syscall::SysError> {
    let file_id = binary.file.as_ref().ok_or_else(denied)?;
    let file = manifest
        .files
        .iter()
        .find(|file| &file.id == file_id)
        .ok_or_else(denied)?;
    if !absolute(&binary.path) || target(manifest, &file.path).as_deref() != Some(&binary.path) {
        return Err(denied());
    }
    let hash = file.digest.strip_prefix("sha256:").ok_or_else(denied)?;
    if hash.len() != 64 {
        return Err(denied());
    }
    let mut digest = [0; 32];
    for (out, pair) in digest.iter_mut().zip(hash.as_bytes().chunks_exact(2)) {
        let nibble = |byte: u8| match byte {
            b'0'..=b'9' => Some(byte - b'0'),
            b'a'..=b'f' => Some(byte - b'a' + 10),
            b'A'..=b'F' => Some(byte - b'A' + 10),
            _ => None,
        };
        *out = nibble(pair[0]).ok_or_else(denied)? * 16 + nibble(pair[1]).ok_or_else(denied)?;
    }
    Ok(Image {
        path: binary.path.clone(),
        size: file.size,
        digest,
    })
}

impl Catalog {
    pub(crate) fn new(
        verified: VerifiedManifest,
        root_path: &str,
    ) -> Result<Self, syscall::SysError> {
        let manifest = &verified.manifest;
        if manifest.package_kind.as_deref() != Some("application") {
            return Err(denied());
        }
        let binary = manifest.binary(root_path).ok_or_else(denied)?;
        if binary.kind.as_deref() != Some("application") {
            return Err(denied());
        }
        let root = image(manifest, binary)?;
        let mut libraries = Vec::new();
        for binary in &manifest.binaries {
            if binary.kind.as_deref() == Some("library") {
                libraries.push(image(manifest, binary)?);
            }
        }
        Ok(Self {
            root,
            libraries,
            identity: verified.identity,
        })
    }

    pub(crate) fn identity(&self) -> &ApplicationIdentity {
        &self.identity
    }

    /// Select a signed record using the actual open candidate, then verify the
    /// captured bytes. No reopening, basename fallback or broker-root lookup.
    pub(crate) fn validate(
        &self,
        source: Source<'_>,
        bytes: &[u8],
    ) -> Result<(), syscall::SysError> {
        let selected = match source {
            Source::Root => &self.root,
            Source::Dependency { path, .. } => self
                .libraries
                .iter()
                .find(|image| image.path.as_bytes() == path)
                .ok_or_else(denied)?,
        };
        if bytes.len() as u64 != selected.size
            || Sha256::digest(bytes).as_slice() != selected.digest
        {
            return Err(denied());
        }
        Ok(())
    }
}
