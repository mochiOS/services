//! Inputs approved by the launching application's authenticated manifest.
//! This policy grants nothing: native creation still authorizes the prepared
//! output separately, after every captured input has passed this check.
use alloc::{string::String, vec::Vec};
use mochi_user_platform::{package, syscall};
use mochios_posix_client::image_preparation::Source;
use sha2::{Digest, Sha256};

use crate::resolver::{ApplicationIdentity, VerifiedManifest};
use mochios_signature_protocol::InstallProvenance;

const MAX_PACKAGES: usize = 256;
const MAX_LIBRARIES: usize = 8192;

struct Image {
    path: String,
    size: u64,
    digest: [u8; 32],
}

/// Each library must be an explicit `kind = "library"` binary with a `file`
/// binding. External publishers must be explicitly approved by authenticated
/// dependency edges; installation alone never approves their code.
pub(crate) struct Catalog {
    root: Image,
    libraries: Vec<Image>,
    identity: ApplicationIdentity,
    manifest_digest: [u8; 32],
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
        match manifest.package_kind.as_deref() {
            Some("application") => {
                alloc::format!("/applications/{}.app/{relative}", manifest.package_name)
            }
            None | Some("binary") => alloc::format!("/bin/{relative}"),
            _ => return None,
        }
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
    let digest = decode_key(hash)?;
    Ok(Image {
        path: binary.path.clone(),
        size: file.size,
        digest,
    })
}

fn decode_key(hash: &str) -> Result<[u8; 32], syscall::SysError> {
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
    Ok(digest)
}

/// Immutable bootstrap readers may select a legacy root without a file table.
/// Once a manifest declares file bindings, even a service root must obey them.
pub(crate) fn validate_declared_root(
    manifest: &package::PackageManifest,
    path: &str,
    bytes: &[u8],
) -> Result<(), syscall::SysError> {
    let binary = manifest.binary(path).ok_or_else(denied)?;
    if binary.file.is_none() && manifest.files.is_empty() {
        return Ok(());
    }
    let expected = image(manifest, binary)?;
    if expected.size != bytes.len() as u64 || expected.digest != <[u8; 32]>::from(Sha256::digest(bytes))
    {
        return Err(denied());
    }
    Ok(())
}

fn matches_dependency(
    required: &package::LibraryDependency,
    actual: &VerifiedManifest,
    architecture: Option<&str>,
) -> Result<(), syscall::SysError> {
    let provenance = match actual.identity.provenance {
        InstallProvenance::BuiltIn => "built-in",
        InstallProvenance::VerifiedPackage => "verified-package",
        InstallProvenance::Development => "development",
    };
    if actual.manifest.package_id != required.package
        || actual.identity.package_id != required.package
        || actual.identity.developer_id != required.developer
        || actual.identity.subject_key_id != decode_key(&required.subject_key_id)?
        || provenance != required.provenance
        || actual.manifest.package_abi.as_deref() != Some(required.abi.as_str())
        || architecture
            .is_some_and(|arch| actual.manifest.package_architecture.as_deref() != Some(arch))
    {
        return Err(denied());
    }
    Ok(())
}

impl Catalog {
    /// Existing static packages have no per-file table. Preserve their trusted
    /// installed-path policy by pinning the broker's captured bytes. Never use
    /// this rule for a dynamic root or for libraries chosen by the requester.
    pub(crate) fn for_static(
        verified: VerifiedManifest,
        root_path: &str,
        trusted: &[u8],
    ) -> Result<Self, syscall::SysError> {
        let manifest = &verified.manifest;
        let binary = manifest.binary(root_path).ok_or_else(denied)?;
        if binary.file.is_some() || !manifest.files.is_empty() {
            return Self::new(verified, root_path);
        }
        if manifest.package_kind.as_deref() != Some("application")
            || binary.kind.as_deref() != Some("application")
            || !absolute(root_path)
            || !manifest.library_dependencies.is_empty()
            || trusted.get(..7) != Some(&[0x7f, b'E', b'L', b'F', 2, 1, 1])
            || trusted.get(16..18) != Some(&2u16.to_le_bytes())
            || mochios_posix_client::image_preparation::needs_preparation_bytes(trusted)
                .map_err(|_| denied())?
        {
            return Err(denied());
        }
        Ok(Self {
            root: Image {
                path: root_path.into(),
                size: trusted.len() as u64,
                digest: Sha256::digest(trusted).into(),
            },
            libraries: Vec::new(),
            identity: verified.identity,
            manifest_digest: verified.manifest_digest,
        })
    }

    pub(crate) fn new(
        verified: VerifiedManifest,
        root_path: &str,
    ) -> Result<Self, syscall::SysError> {
        Self::resolve(verified, root_path, |_| Err(denied()))
    }

    /// Each package is authenticated once per launch. Repeated edges and cycles
    /// reuse that snapshot but must still match every publisher/ABI constraint.
    /// Dependency capabilities and executable identities are never inherited.
    pub(crate) fn resolve(
        verified: VerifiedManifest,
        root_path: &str,
        mut load: impl FnMut(&str) -> Result<VerifiedManifest, syscall::SysError>,
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
        let architecture = manifest.package_architecture.clone();
        let identity = verified.identity.clone();
        let manifest_digest = verified.manifest_digest;
        let mut packages = alloc::vec![verified];
        let mut libraries = Vec::new();
        let mut cursor = 0;
        while cursor < packages.len() {
            let manifest = &packages[cursor].manifest;
            for binary in &manifest.binaries {
                if binary.kind.as_deref() != Some("library") {
                    continue;
                }
                let library = image(manifest, binary)?;
                if libraries
                    .iter()
                    .any(|other: &Image| other.path == library.path)
                    || library.path == root.path
                {
                    return Err(syscall::SysError::from_raw(
                        mochios_posix_protocol::STATUS_EEXIST as i64,
                    ));
                }
                if libraries.len() == MAX_LIBRARIES {
                    return Err(syscall::SysError::from_raw(-7));
                }
                libraries.push(library);
            }
            let dependencies = manifest.library_dependencies.clone();
            for dependency in dependencies {
                if let Some(existing) = packages
                    .iter()
                    .find(|package| package.manifest.package_id == dependency.package)
                {
                    matches_dependency(&dependency, existing, architecture.as_deref())?;
                } else {
                    if packages.len() == MAX_PACKAGES {
                        return Err(syscall::SysError::from_raw(-7));
                    }
                    let loaded = load(&dependency.package)?;
                    matches_dependency(&dependency, &loaded, architecture.as_deref())?;
                    packages.push(loaded);
                }
            }
            cursor += 1;
        }
        Ok(Self {
            root,
            libraries,
            identity,
            manifest_digest,
        })
    }

    pub(crate) fn identity(&self) -> &ApplicationIdentity {
        &self.identity
    }

    pub(crate) fn manifest_digest(&self) -> [u8; 32] {
        self.manifest_digest
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
            Source::Dependency { path, .. } | Source::Interpreter { path } => self
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
