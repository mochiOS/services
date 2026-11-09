//! Own an authenticated launch across consent, then issue its exact native permit.
//! A renderer supplies neither the source, grants nor the execution identity.
use alloc::{boxed::Box, string::String, vec::Vec};
use mochi_user_platform as p;
use p::capability::consent::{Choice, Choices};
use p::syscall::{NativeError, SysError};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::{
    consent::{Action, Approval, Binding, Session},
    consent_peer::Peer,
    resolver::ApplicationIdentity,
};

/// An owned continuation supplies only authenticated retained content. The
/// shared controller remains the sole producer of a one-shot Approval.
pub(crate) trait Administration {
    fn authority(&self) -> (&ApplicationIdentity, &[String], &[u8; 32]);
    fn requirements(&self) -> [u8; 32];
    fn is_run(&self) -> bool;
    fn question(&self) -> p::capability::consent::question::Administrator<'_>;
    fn complete(
        self: Box<Self>,
        source: &[u8],
        peer: &Peer,
        credentials: p::capability::administrator::Credentials<'_>,
        deadline: u64,
        binding: Binding,
        account: (u32, u64),
    ) -> Result<u64, SysError>;
}

/// Variants can only contain selections returned by the authenticated source
/// gate. The original manifest/verification snapshot stays owned here.
pub(crate) enum Selection {
    Installed(crate::installed_image::Selection),
    Standalone(crate::standalone_image::Selection),
    Administration(Box<dyn Administration>),
}

impl Selection {
    pub(crate) fn needs_consent(&self, policy: &crate::policy::AppPromptPolicy) -> bool {
        let (_, requested, _) = self.authority();
        match self {
            Self::Installed(_) => requested
                .iter()
                .any(|name| crate::policy::needs_app_prompt(policy, name)),
            Self::Standalone(_) => !requested.is_empty(),
            Self::Administration(_) => true,
        }
    }
    fn authority(&self) -> (&ApplicationIdentity, &[String], &[u8; 32]) {
        match self {
            Self::Installed(source) => source.authority(),
            Self::Standalone(source) => source.authority(),
            Self::Administration(source) => source.authority(),
        }
    }

    pub(crate) fn authorize_remembered(
        &self,
        requester: &Peer,
        key: &str,
    ) -> Result<bool, SysError> {
        if matches!(self, Self::Administration(_)) {
            return Ok(false);
        }
        let (uid, generation) = crate::execution_grant::requester_account(requester)?;
        let (identity, capabilities, digest) = self.authority();
        let remembered =
            crate::execution_grant::Key::new(uid, generation, identity, capabilities, *digest)?;
        if !crate::execution_grant::contains(remembered)? {
            return Ok(false);
        }
        if crate::execution_grant::requester_account(requester)? != (uid, generation) {
            return Err(error(NativeError::AccessDenied));
        }
        crate::resolver::authorize_image_install(
            requester.instance.endpoint,
            key,
            identity,
            capabilities,
            digest,
            requester.instance.revision,
        )?;
        Ok(true)
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
            Self::Administration(_) => Err(error(NativeError::AccessDenied)),
        }
    }
}

fn error(error: NativeError) -> SysError {
    SysError::from_raw(error.into_raw() as i64)
}

pub(crate) fn requirements(key: &str, capabilities: &[String]) -> Result<[u8; 32], SysError> {
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
    source: Zeroizing<Vec<u8>>,
    selection: Selection,
    requester: Peer,
    key: String,
    binding: Binding,
    remembered: Option<crate::execution_grant::Key>,
    uid: u32,
    account_generation: u64,
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
        let (identity, _, _) = selection.authority();
        let (uid, account_generation) = crate::execution_grant::requester_account(&requester)?;
        let administrator = matches!(selection, Selection::Administration(_));
        let remembered = if administrator {
            None
        } else {
            Some(crate::execution_grant::Key::new(
                uid,
                account_generation,
                identity,
                capabilities,
                *digest,
            )?)
        };
        let binding = Binding {
            requester: requester.instance,
            session,
            policy_generation,
            source_digest: *digest,
            prepared_digest: *digest,
            requirements_digest: match &selection {
                Selection::Administration(request) => request.requirements(),
                _ => requirements(key, capabilities)?,
            },
            action: if administrator {
                Action::Operation
            } else {
                Action::Launch
            },
        };
        let mut retained_key = String::new();
        retained_key
            .try_reserve_exact(key.len())
            .map_err(|_| error(NativeError::ResourceUnavailable))?;
        retained_key.push_str(key);
        Ok(Self {
            source: Zeroizing::new(source),
            selection,
            requester,
            key: retained_key,
            binding,
            remembered,
            uid,
            account_generation,
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
    pub(crate) fn administrator(&self) -> bool {
        matches!(self.selection, Selection::Administration(_))
    }
    pub(crate) fn spawn_reply(&self) -> bool {
        matches!(&self.selection, Selection::Administration(request) if request.is_run())
    }
    pub(crate) fn choices(&self) -> Choices {
        Choices::new(if self.administrator() {
            Choices::ONCE
        } else {
            Choices::ONCE | Choices::PERSISTENT
        })
        .expect("execution consent choices")
    }

    /// Generate frontend content from the retained authenticated selection,
    /// never from request-supplied labels or a fresh pathname lookup.
    pub(crate) fn write_prompt(
        &self,
        offer: crate::consent::Offer,
        output: &mut [u8],
    ) -> Result<usize, SysError> {
        use p::capability::consent::prompt::{self, Prompt};
        let (identity, capabilities, digest) = self.selection.authority();
        let mut ordered = [""; prompt::MAX_CAPABILITIES];
        let names = ordered
            .get_mut(..capabilities.len())
            .ok_or_else(|| error(NativeError::InvalidArgument))?;
        for (slot, name) in names.iter_mut().zip(capabilities) {
            *slot = name;
        }
        names.sort_unstable();
        let mut encoded = [0; prompt::MAX_REQUIREMENTS_BYTES];
        let mut length = 0;
        let mut previous = None;
        for name in names {
            if previous == Some(*name) {
                continue;
            }
            let end = length + name.len() + 1;
            encoded
                .get_mut(length..end)
                .ok_or_else(|| error(NativeError::InvalidArgument))?[..name.len()]
                .copy_from_slice(name.as_bytes());
            length = end;
            previous = Some(*name);
        }
        let prompt = Prompt {
            correlation: offer.correlation,
            deadline: offer.deadline,
            choices: offer.choices,
            source_digest: *digest,
            package: &identity.package_id,
            requirements: &encoded[..length],
        };
        match &self.selection {
            Selection::Administration(request) => {
                p::capability::consent::question::encode(prompt, request.question(), output)
            }
            _ => prompt::encode(prompt, output),
        }
        .map_err(|_| error(NativeError::InvalidArgument))
    }

    /// Adapters supply fresh authenticated peer/session observations. Approval
    /// is consumed before any native I/O; failures require a new transaction.
    /// Remembered consent is scoped to this user, authenticated image and exact
    /// requirements. A storage failure cannot become a successful Allow Once.
    pub(crate) fn complete(
        self,
        approval: Approval,
        current: &Peer,
        session: Session,
        policy_generation: u64,
    ) -> Result<(), SysError> {
        self.complete_operation(
            approval,
            current,
            session,
            policy_generation,
            None,
            u64::MAX,
        )
        .map(|_| ())
    }
    pub(crate) fn complete_operation(
        self,
        approval: Approval,
        current: &Peer,
        session: Session,
        policy_generation: u64,
        credentials: Option<p::capability::administrator::Credentials<'_>>,
        deadline: u64,
    ) -> Result<u64, SysError> {
        let (binding, choice) = approval.into_parts();
        if !matches!(choice, Choice::AllowOnce | Choice::AllowPersistently)
            || binding != self.binding
            || current.instance != self.requester.instance
            || session != self.binding.session
            || policy_generation != self.binding.policy_generation
            || !p::handle::same_object(current.process.0, self.requester.process.0)?
        {
            return Err(error(NativeError::AccessDenied));
        }
        if crate::execution_grant::requester_account(current)?
            != (self.uid, self.account_generation)
        {
            return Err(error(NativeError::AccessDenied));
        }
        if let Selection::Administration(request) = self.selection {
            if choice != Choice::AllowOnce {
                return Err(error(NativeError::AccessDenied));
            }
            let credentials = credentials.ok_or_else(|| error(NativeError::AccessDenied))?;
            return request.complete(
                &self.source,
                current,
                credentials,
                deadline,
                self.binding,
                (self.uid, self.account_generation),
            );
        }
        if credentials.is_some() {
            return Err(error(NativeError::AccessDenied));
        }
        if choice == Choice::AllowPersistently {
            crate::execution_grant::remember(
                self.remembered
                    .ok_or_else(|| error(NativeError::AccessDenied))?,
            )?;
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
        .map(|()| 0)
    }
}
