//! Inputs approved by the launching application's authenticated manifest.
//! This policy grants nothing: native creation still authorizes the prepared
//! output separately, after every captured input has passed this check.
use alloc::{string::String, vec::Vec};
use core::cell::RefCell;
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
    diagnostic_inputs: RefCell<Vec<(Vec<u8>, String, [u8; 32])>>,
    diagnostic_version: String,
    diagnostic_name: String,
    resources: Vec<ResourceSet>,
}

fn denied() -> syscall::SysError {
    syscall::SysError::from_raw(syscall::EACCES as i64)
}

fn executable_package(manifest: &package::PackageManifest) -> bool {
    // Standalone commands use binary packages (historically without a kind).
    // The selected binary must still explicitly declare application below.
    matches!(
        manifest.package_kind.as_deref(),
        None | Some("binary" | "application")
    )
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

pub(crate) struct CodeBinding {
    pub(crate) digest: [u8; 32],
    pub(crate) size: u64,
}

pub(crate) fn declared_root_binding(
    manifest: &package::PackageManifest,
    path: &str,
) -> Result<CodeBinding, syscall::SysError> {
    let binary = manifest.binary(path).ok_or_else(denied)?;
    let image = image(manifest, binary)?;
    Ok(CodeBinding {
        digest: image.digest,
        size: image.size,
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

/// Bootstrap and application roots require an explicit authenticated code binding.
pub(crate) fn validate_declared_root(
    manifest: &package::PackageManifest,
    path: &str,
    bytes: &[u8],
) -> Result<(), syscall::SysError> {
    let binary = manifest.binary(path).ok_or_else(denied)?;
    let expected = image(manifest, binary)?;
    if expected.size != bytes.len() as u64
        || expected.digest != <[u8; 32]>::from(Sha256::digest(bytes))
    {
        return Err(denied());
    }
    Ok(())
}

/// Inert startup authority plan, derived only from an installed authenticated
/// manifest. File bytes are separately captured and checked before publication.
pub(crate) struct ResourceSet {
    pub(crate) alias: String,
    pub(crate) identity: ApplicationIdentity,
    pub(crate) manifest_digest: [u8; 32],
    pub(crate) files: Vec<package::resources::SelectedResource>,
}

struct PackageInput {
    manifest: package::PackageManifest,
    identity: ApplicationIdentity,
    manifest_digest: [u8; 32],
}
impl From<VerifiedManifest> for PackageInput {
    fn from(verified: VerifiedManifest) -> Self {
        Self {
            manifest: verified.manifest,
            identity: verified.identity,
            manifest_digest: verified.manifest_digest,
        }
    }
}

fn matches_dependency(
    required: &package::LibraryDependency,
    actual: &PackageInput,
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
    /// The signed standalone root is bound directly to its captured bytes.
    /// Libraries still require explicit dependency edges and authenticated
    /// installed manifests; no library-search path gains implicit trust.
    pub(crate) fn standalone(
        path: &str,
        bytes: &[u8],
        identity: ApplicationIdentity,
        embedded: Option<&str>,
        load: impl FnMut(&str) -> Result<VerifiedManifest, syscall::SysError>,
    ) -> Result<Self, syscall::SysError> {
        let mut manifest = match embedded {
            Some(text) => package::parse_manifest(text).ok_or_else(denied)?,
            None => package::PackageManifest::default(),
        };
        manifest.package_id = identity.package_id.clone();
        let digest = Sha256::digest(bytes).into();
        Self::collect(
            Image {
                path: path.into(),
                size: bytes.len() as u64,
                digest,
            },
            identity,
            manifest,
            digest,
            false,
            load,
        )
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
        load: impl FnMut(&str) -> Result<VerifiedManifest, syscall::SysError>,
    ) -> Result<Self, syscall::SysError> {
        let manifest = &verified.manifest;
        if !executable_package(manifest) {
            return Err(denied());
        }
        let binary = manifest.binary(root_path).ok_or_else(denied)?;
        if binary.kind.as_deref() != Some("application") {
            return Err(denied());
        }
        let root = image(manifest, binary)?;
        Self::collect(
            root,
            verified.identity,
            verified.manifest,
            verified.manifest_digest,
            true,
            load,
        )
    }
    fn collect(
        root: Image,
        identity: ApplicationIdentity,
        manifest: package::PackageManifest,
        manifest_digest: [u8; 32],
        installed: bool,
        mut load: impl FnMut(&str) -> Result<VerifiedManifest, syscall::SysError>,
    ) -> Result<Self, syscall::SysError> {
        let architecture = manifest.package_architecture.clone();
        let diagnostic_version = manifest.package_version.clone();
        let diagnostic_name = manifest.package_name.clone();
        let mut packages = alloc::vec![PackageInput {
            manifest,
            identity: identity.clone(),
            manifest_digest,
        }];
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
                    let loaded = PackageInput::from(load(&dependency.package)?);
                    matches_dependency(&dependency, &loaded, architecture.as_deref())?;
                    packages.push(loaded);
                }
            }
            cursor += 1;
        }
        // Resource-only providers are authenticated with the same resolver, but
        // never enter the code graph. If a code edge already loaded a package,
        // use that exact snapshot; a second index lookup may select a new build.
        let mut resources = Vec::new();
        if installed {
            let main = &packages[0].manifest;
            let own = package::resources::own_resources(main, &root.path).map_err(|_| denied())?;
            resources.push(ResourceSet {
                alias: String::new(),
                identity: identity.clone(),
                manifest_digest,
                files: own,
            });
            let aliases = main
                .binary(&root.path)
                .ok_or_else(denied)?
                .resource_dependencies
                .clone();
            for alias in aliases {
                let dependency = package::resources::resource_dependency(
                    &packages[0].manifest,
                    &root.path,
                    &alias,
                )
                .map_err(|_| denied())?
                .clone();
                let index = match packages
                    .iter()
                    .position(|p| p.manifest.package_id == dependency.provider.package)
                {
                    Some(index) => index,
                    None => {
                        if packages.len() >= MAX_PACKAGES {
                            return Err(syscall::SysError::from_raw(-7));
                        }
                        let provider = PackageInput::from(load(&dependency.provider.package)?);
                        packages.push(provider);
                        packages.len() - 1
                    }
                };
                let provider = &packages[index];
                // Opaque data need not use the consumer CPU architecture.
                matches_dependency(&dependency.provider, provider, None)?;
                let files =
                    package::resources::exported_resources(&provider.manifest, &dependency.export)
                        .map_err(|_| denied())?;
                resources.push(ResourceSet {
                    alias,
                    identity: provider.identity.clone(),
                    manifest_digest: provider.manifest_digest,
                    files,
                });
            }
        }
        Ok(Self {
            root,
            libraries,
            identity,
            manifest_digest,
            diagnostic_inputs: RefCell::new(Vec::new()),
            diagnostic_version,
            diagnostic_name,
            resources,
        })
    }

    /// Aliases are local to the selected executable. An installed package or
    /// code dependency alone is never enough to select an external data set.
    pub(crate) fn resource_set(&self, alias: &str) -> Result<&ResourceSet, syscall::SysError> {
        self.resources
            .iter()
            .find(|set| set.alias == alias)
            .ok_or_else(denied)
    }

    /// Capture only the selected asset and check the exact signed bytes. A
    /// concurrent update cannot silently replace an old startup snapshot.
    /// The reader is privileged broker I/O, never a client-supplied pathname.
    pub(crate) fn read_resource(
        &self,
        alias: &str,
        name: &str,
        mut read: impl FnMut(&str, usize) -> Result<Vec<u8>, syscall::SysError>,
    ) -> Result<Vec<u8>, syscall::SysError> {
        if !package::resources::valid_resource_name(name) {
            return Err(denied());
        }
        let file = self
            .resource_set(alias)?
            .files
            .iter()
            .find(|file| file.name == name)
            .ok_or_else(denied)?;
        let size = usize::try_from(file.size).map_err(|_| denied())?;
        if size > 128 * 1024 * 1024 {
            return Err(syscall::SysError::from_raw(-7));
        }
        let bytes = read(&file.path, size)?;
        let hash = file.digest.strip_prefix("sha256:").ok_or_else(denied)?;
        if bytes.len() != size || <[u8; 32]>::from(Sha256::digest(&bytes)) != decode_key(hash)? {
            return Err(denied());
        }
        Ok(bytes)
    }

    pub(crate) fn identity(&self) -> &ApplicationIdentity {
        &self.identity
    }

    pub(crate) fn manifest_digest(&self) -> [u8; 32] {
        self.manifest_digest
    }

    pub(crate) fn diagnostic_input(&self, name: &[u8]) -> Option<(String, [u8; 32])> {
        if name.is_empty() {
            return Some((self.root.path.clone(), self.root.digest));
        }
        let inputs = self.diagnostic_inputs.try_borrow().ok()?;
        let mut matches = inputs.iter().filter(|(needed, _, _)| needed == name);
        let (_, path, digest) = matches.next()?;
        if matches.next().is_some() {
            return None;
        }
        Some((path.clone(), *digest))
    }

    pub(crate) fn diagnostic_package(&self) -> (&str, &str) {
        (&self.diagnostic_name, &self.diagnostic_version)
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
        if let Source::Dependency { needed, .. } = source
            && let Ok(mut inputs) = self.diagnostic_inputs.try_borrow_mut()
            && inputs.len() < 128
            && !inputs
                .iter()
                .any(|(old, path, _)| old == needed && path == &selected.path)
            && inputs.try_reserve(1).is_ok()
        {
            inputs.push((needed.to_vec(), selected.path.clone(), selected.digest));
        }
        Ok(())
    }
}
