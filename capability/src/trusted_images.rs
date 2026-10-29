//! Role policy belongs to userspace. Roots come only from the immutable boot
//! generation. Runtime path lookups and caller-asserted hashes cannot add code.
use alloc::vec::Vec;
use core::cell::RefCell;
use mochi_user_platform as p;
use p::syscall::{NativeError, SysError};
use sha2::{Digest, Sha256};

use crate::consent_peer::{Peer, ProcessReference};
use crate::package_index::PackageIndex;
use crate::resolver::{ApplicationIdentity, FileReader, verified_manifest};
use mochios_signature_protocol::InstallProvenance;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Role {
    TextPrompt,
    Workspace,
    GraphicalPrompt,
    Input,
    Compositor,
}

const POLICIES: &[(Role, &str, &str)] = &[
    (Role::TextPrompt, "org.mochios.msh", "application"),
    (Role::Workspace, "org.mochios.workspace", "service"),
    (Role::GraphicalPrompt, "org.mochios.secure-ui", "service"),
    (Role::Input, "org.mochios.input", "service"),
    (Role::Compositor, "org.mochios.compositor", "service"),
];
const MAX_DERIVED: usize = 128;

struct Root {
    role: Role,
    identity: ApplicationIdentity,
    source: [u8; 32],
    manifest_digest: [u8; 32],
    raw: bool,
}

struct Derived {
    role: Role,
    process: ProcessReference,
    info: p::syscall::ProcessImageInfo,
}

pub(crate) struct TrustedImages {
    roots: Vec<Root>,
    derived: RefCell<Vec<Derived>>,
}

fn denied() -> SysError {
    SysError::from_raw(NativeError::AccessDenied.into_raw() as i64)
}

fn built_in(identity: &ApplicationIdentity, package: &str) -> bool {
    identity.package_id == package
        && identity.developer_id == "org.mochios.system"
        && identity.provenance == InstallProvenance::BuiltIn
        && identity.subject_key_id == [0; 32]
}

fn same_identity(a: &ApplicationIdentity, b: &ApplicationIdentity) -> bool {
    a.package_id == b.package_id
        && a.developer_id == b.developer_id
        && a.provenance == b.provenance
        && a.subject_key_id == b.subject_key_id
}

impl TrustedImages {
    /// This reader must be the explicitly delegated immutable System reader.
    /// Failures are not retried through the mutable runtime filesystem.
    pub fn bootstrap(index: &PackageIndex, read: FileReader) -> Result<Self, SysError> {
        if index.duplicate {
            return Err(denied());
        }
        let mut roots = Vec::new();
        for &(role, package, kind) in POLICIES {
            let record = index.by_package.get(package).ok_or_else(denied)?;
            let verified = verified_manifest(&record.manifest_path, read)?;
            if !built_in(&verified.identity, package) {
                return Err(denied());
            }
            let mut candidates = verified
                .manifest
                .binaries
                .iter()
                .filter(|b| b.kind.as_deref() == Some(kind));
            let binary = candidates.next().ok_or_else(denied)?;
            if candidates.next().is_some() {
                return Err(denied());
            }
            let bytes = read(&binary.path)?;
            if bytes.len() < 64
                || bytes.len() > mnu_abi::exec::MAX_CAPTURED_IMAGE_BYTES
                || bytes[..7] != [0x7f, b'E', b'L', b'F', 2, 1, 1]
                || !matches!(u16::from_le_bytes([bytes[16], bytes[17]]), 2 | 3)
            {
                return Err(denied());
            }
            crate::image_catalog::validate_declared_root(&verified.manifest, &binary.path, &bytes)?;
            let raw = !mochios_posix_client::image_preparation::needs_preparation_bytes(&bytes)
                .map_err(|_| denied())?;
            roots.push(Root {
                role,
                identity: verified.identity,
                source: Sha256::digest(&bytes).into(),
                manifest_digest: verified.manifest_digest,
                raw,
            });
        }
        Ok(Self {
            roots,
            derived: RefCell::new(Vec::new()),
        })
    }

    /// Called only by the trusted common preparer, after validating the source
    /// and every captured dependency and creating the exact native image. No
    /// IPC request can register an asserted source->output hash relationship.
    pub fn record_created(
        &self,
        identity: &ApplicationIdentity,
        manifest_digest: [u8; 32],
        source: &[u8],
        output: &[u8],
        process: u32,
    ) -> Result<(), SysError> {
        let Some(root) = self
            .roots
            .iter()
            .find(|root| same_identity(&root.identity, identity))
        else {
            return Ok(());
        };
        if root.manifest_digest != manifest_digest
            || root.source != <[u8; 32]>::from(Sha256::digest(source))
        {
            return Err(denied());
        }
        let info = p::process::image_info(Some(process))?;
        if info.digest_kind != p::syscall::PROCESS_IMAGE_DIGEST_SHA256
            || info.digest != <[u8; 32]>::from(Sha256::digest(output))
            || info.image_revision != 0
        {
            return Err(denied());
        }
        let mut derived = self.derived.try_borrow_mut().map_err(|_| denied())?;
        derived.retain(|entry| {
            p::process::image_info(Some(entry.process.0)).is_ok_and(|now| now == entry.info)
        });
        if derived.len() == MAX_DERIVED {
            return Err(SysError::from_raw(
                NativeError::LimitExceeded.into_raw() as i64
            ));
        }
        derived
            .try_reserve(1)
            .map_err(|_| SysError::from_raw(NativeError::ResourceUnavailable.into_raw() as i64))?;
        let process =
            ProcessReference(p::handle::duplicate(process, p::handle::HANDLE_RIGHT_WAIT)?);
        derived.push(Derived {
            role: root.role,
            process,
            info,
        });
        Ok(())
    }

    pub fn role(&self, peer: &Peer) -> Result<Option<Role>, SysError> {
        let context = &peer.context;
        let package = context
            .package_id
            .get(..context.package_id_len as usize)
            .ok_or_else(denied)?;
        let developer = context
            .developer_id
            .get(..context.developer_id_len as usize)
            .ok_or_else(denied)?;
        let Some(root) = self.roots.iter().find(|root| {
            root.identity.package_id.as_bytes() == package
                && root.identity.developer_id.as_bytes() == developer
                && root.identity.subject_key_id == context.subject_key_id
                && root.identity.provenance as u8 == context.provenance
        }) else {
            return Ok(None);
        };
        if root.raw && peer.instance.digest == root.source {
            return Ok(Some(root.role));
        }
        let derived = self.derived.try_borrow().map_err(|_| denied())?;
        for entry in derived.iter().filter(|entry| entry.role == root.role) {
            if entry.info.process_id == peer.instance.process
                && entry.info.image_revision == peer.instance.revision
                && entry.info.digest == peer.instance.digest
                && p::handle::same_object(entry.process.0, peer.process.0)?
            {
                return Ok(Some(root.role));
            }
        }
        Ok(None)
    }
}
