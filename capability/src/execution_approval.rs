//! Own an authenticated launch across consent, then issue its exact native permit.
//! A renderer supplies neither the source, grants nor the execution identity.
use alloc::{string::String, vec::Vec};
use mochi_user_platform as p;
use p::capability::consent::Choice;
use p::syscall::{NativeError, SysError};
use sha2::{Digest, Sha256};

use crate::{
    consent::{Action, Approval, Binding, Session},
    consent_peer::Peer,
    resolver::ApplicationIdentity,
};

/// Variants can only contain selections returned by the authenticated source
/// gate. The original manifest/verification snapshot stays owned here.
pub(crate) enum Selection {
    Installed(crate::installed_image::Selection),
    Standalone(crate::standalone_image::Selection),
}

impl Selection {
    fn authority(&self) -> (&ApplicationIdentity, &[String], &[u8; 32]) {
        match self {
            Self::Installed(source) => source.authority(),
            Self::Standalone(source) => source.authority(),
        }
    }

    pub(crate) fn authorize(
        &self,
        policy: &crate::policy::AppPromptPolicy,
        sender: u64,
        key: &str,
    ) -> Result<(), SysError> {
        match self {
            Self::Installed(source) => source.authorize(policy, sender, key),
            Self::Standalone(source) => source.authorize(sender, key),
        }
    }
}

fn error(error: NativeError) -> SysError {
    SysError::from_raw(error.into_raw() as i64)
}

fn requirements(key: &str, capabilities: &[String]) -> Result<[u8; 32], SysError> {
    let length = capabilities.iter().try_fold(0usize, |length, name| {
        if name.is_empty() || name.as_bytes().contains(&0) {
            return None;
        }
        length.checked_add(name.len())?.checked_add(1)
    });
    if capabilities.len() > 128 || length.is_none_or(|length| length > 1024) {
        return Err(error(NativeError::InvalidArgument));
    }
    let mut ordered = Vec::new();
    ordered
        .try_reserve_exact(capabilities.len())
        .map_err(|_| error(NativeError::ResourceUnavailable))?;
    ordered.extend(capabilities.iter().map(String::as_str));
    ordered.sort_unstable();
    ordered.dedup();
    let mut digest = Sha256::new();
    digest.update(b"mochiOS execution launch requirements v1\0");
    // Equal image/grants under another exec key remain separate requests.
    digest.update((key.len() as u32).to_le_bytes());
    digest.update(key.as_bytes());
    digest.update((ordered.len() as u32).to_le_bytes());
    for name in ordered {
        digest.update((name.len() as u32).to_le_bytes());
        digest.update(name.as_bytes());
    }
    Ok(digest.finalize().into())
}

/// Non-clonable owner of the original bytes, policy selection and Process
/// reference. Consuming or cancelling this request releases all three.
pub(crate) struct Pending {
    source: Vec<u8>,
    selection: Selection,
    requester: Peer,
    key: String,
    binding: Binding,
}

impl Pending {
    pub(crate) fn new(
        selection: Selection,
        source: Vec<u8>,
        requester: Peer,
        key: &str,
        session: Session,
        policy_generation: u64,
    ) -> Result<Self, SysError> {
        if source.is_empty()
            || source.len() > mnu_abi::exec::MAX_CAPTURED_IMAGE_BYTES
            || key.is_empty()
            || key.len() >= 256
            || key.as_bytes().contains(&0)
            || requester.instance.endpoint == 0
            || requester.instance.process == 0
            || requester.instance.thread == 0
            || requester.process.0 == 0
            || session.id == 0
            || session.generation == 0
            || policy_generation == 0
        {
            return Err(error(NativeError::InvalidArgument));
        }
        let (_, capabilities, digest) = selection.authority();
        if Sha256::digest(&source).as_slice() != digest {
            return Err(error(NativeError::AccessDenied));
        }
        let binding = Binding {
            requester: requester.instance,
            session,
            policy_generation,
            source_digest: *digest,
            prepared_digest: *digest,
            requirements_digest: requirements(key, capabilities)?,
            action: Action::Launch,
        };
        let mut retained_key = String::new();
        retained_key
            .try_reserve_exact(key.len())
            .map_err(|_| error(NativeError::ResourceUnavailable))?;
        retained_key.push_str(key);
        Ok(Self {
            source,
            selection,
            requester,
            key: retained_key,
            binding,
        })
    }

    pub(crate) fn binding(&self) -> Binding {
        self.binding
    }
    pub(crate) fn source_len(&self) -> usize {
        self.source.len()
    }
    pub(crate) fn process_handle(&self) -> u32 {
        self.requester.process.0
    }
    pub(crate) fn subject(&self) -> (&ApplicationIdentity, &[String]) {
        let (identity, capabilities, _) = self.selection.authority();
        (identity, capabilities)
    }

    /// Adapters supply fresh authenticated peer/session observations. Approval
    /// is consumed before any native I/O; failures require a new transaction.
    /// Only AllowOnce is implemented here, so persistent/process scopes must
    /// not be offered by this launch continuation yet.
    pub(crate) fn complete(
        self,
        approval: Approval,
        current: &Peer,
        session: Session,
        policy_generation: u64,
    ) -> Result<(), SysError> {
        let (binding, choice) = approval.into_parts();
        if choice != Choice::AllowOnce
            || binding != self.binding
            || current.instance != self.requester.instance
            || session != self.binding.session
            || policy_generation != self.binding.policy_generation
            || !p::handle::same_object(current.process.0, self.requester.process.0)?
        {
            return Err(error(NativeError::AccessDenied));
        }
        let (identity, capabilities, digest) = self.selection.authority();
        crate::resolver::authorize_image_install(
            self.requester.instance.endpoint,
            &self.key,
            identity,
            capabilities,
            digest,
            self.requester.instance.revision,
        )
    }
}
