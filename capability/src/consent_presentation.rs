//! Measured compositor transport. Session state is supplied only by the
//! measured session owner; renderers never choose it through environment data.
use crate::{
    consent_peer::{self, Peer, ProcessReference},
    trusted_images::{Role, TrustedImages},
};
use mochi_user_platform as p;
use p::capability::{consent::Correlation, presentation as w};
fn denied() -> p::syscall::SysError {
    p::syscall::SysError::from_raw(p::syscall::NativeError::AccessDenied.into_raw() as i64)
}
fn same(current: &Peer, expected: &Peer) -> Result<(), p::syscall::SysError> {
    if current.instance != expected.instance
        || !p::handle::same_object(current.process.0, expected.process.0)?
    {
        return Err(denied());
    }
    Ok(())
}
pub(crate) struct Channel {
    peer: Peer,
    context: Option<w::Context>,
}
impl Channel {
    pub fn connect(trusted: &TrustedImages) -> Result<Self, p::syscall::SysError> {
        let peer = consent_peer::capture(p::process::find_by_name("compositor.service")?)?;
        if trusted.role(&peer)? != Some(Role::Compositor) {
            return Err(denied());
        }
        Ok(Self {
            peer,
            context: None,
        })
    }
    fn destination(&self) -> Result<u32, p::syscall::SysError> {
        same(
            &consent_peer::capture(self.peer.instance.endpoint)?,
            &self.peer,
        )?;
        u32::try_from(self.peer.instance.endpoint).map_err(|_| denied())
    }
    pub fn update(&mut self, context: w::Context) -> Result<(), p::syscall::SysError> {
        // Failed publication leaves no usable local session, even if the
        // remote side received an update whose reply was lost.
        self.context = None;
        p::presentation::session(self.destination()?, context)?;
        self.destination()?;
        self.context = Some(context);
        Ok(())
    }
    pub fn context(&self) -> Option<w::Context> {
        self.context.filter(|c| c.active)
    }
    pub fn register(
        &self,
        trusted: &TrustedImages,
        renderer: &Peer,
        correlation: Correlation,
        kind: w::Kind,
    ) -> Result<w::Receipt, p::syscall::SysError> {
        let role = match kind {
            w::Kind::SecureOverlay => Role::GraphicalPrompt,
            w::Kind::Window => Role::TextDisplay,
        };
        if trusted.role(renderer)? != Some(role) {
            return Err(denied());
        }
        same(
            &consent_peer::capture(renderer.instance.endpoint)?,
            renderer,
        )?;
        let process = ProcessReference(p::process::open_handle_for_endpoint(
            renderer.instance.endpoint,
            p::handle::HANDLE_RIGHT_WAIT | p::handle::HANDLE_RIGHT_TRANSFER,
        )?);
        if !p::handle::same_object(process.0, renderer.process.0)? {
            return Err(denied());
        }
        let context = self.context().ok_or_else(denied)?;
        let reply = p::presentation::command(
            self.destination()?,
            w::Command::Register {
                context,
                correlation,
                kind,
            },
            Some(p::ipc::IpcObjectHandle {
                handle: process.0,
                reserved: 0,
                rights: p::handle::HANDLE_RIGHT_WAIT,
            }),
        )?;
        same(
            &consent_peer::capture(renderer.instance.endpoint)?,
            renderer,
        )?;
        self.destination()?;
        if reply.renderer
            != (w::Image {
                process: renderer.instance.process,
                revision: renderer.instance.revision,
                digest: renderer.instance.digest,
            })
        {
            return Err(denied());
        }
        Ok(reply)
    }
    pub fn status(
        &self,
        correlation: Correlation,
        registration: u64,
    ) -> Result<w::Receipt, p::syscall::SysError> {
        let reply = p::presentation::command(
            self.destination()?,
            w::Command::Status {
                correlation,
                registration,
            },
            None,
        )?;
        self.destination()?;
        if Some(reply.context) != self.context() {
            return Err(denied());
        }
        Ok(reply)
    }
    pub fn cancel(
        &self,
        correlation: Correlation,
        registration: u64,
    ) -> Result<(), p::syscall::SysError> {
        p::presentation::command(
            self.destination()?,
            w::Command::Cancel {
                correlation,
                registration,
            },
            None,
        )
        .map(|_| ())
    }
}
#[derive(Default)]
pub(crate) struct Sessions {
    owner: Option<Peer>,
    last: Option<w::Context>,
    domain: Option<DomainReference>,
}
pub(crate) struct DomainReference(pub u32);
impl Drop for DomainReference {
    fn drop(&mut self) {
        let _ = p::handle::close(self.0);
    }
}
fn member(domain: &DomainReference, peer: &Peer) -> Result<bool, p::syscall::SysError> {
    same(&consent_peer::capture(peer.instance.endpoint)?, peer)?;
    let reference = ProcessReference(p::process::open_handle_for_endpoint(
        peer.instance.endpoint,
        p::handle::HANDLE_RIGHT_WAIT | p::handle::HANDLE_RIGHT_TRANSFER,
    )?);
    if !p::handle::same_object(reference.0, peer.process.0)? {
        return Err(denied());
    }
    let included = crate::persistent_grant::with_client(|client| {
        client.process_domain_contains(
            mochios_posix_client::ObjectHandleAttachment {
                handle: domain.0,
                rights: mochios_posix_protocol::process_domain::ATTACH_RIGHTS,
            },
            mochios_posix_client::ObjectHandleAttachment {
                handle: reference.0,
                rights: p::handle::HANDLE_RIGHT_WAIT,
            },
        )
    })?;
    same(&consent_peer::capture(peer.instance.endpoint)?, peer)?;
    Ok(included)
}
impl Sessions {
    /// Membership comes from the owner's explicit native domain and the
    /// requester's actual Process reference. Environment data is irrelevant.
    pub fn authenticate_member(
        &self,
        channel: &Channel,
        requester: &Peer,
    ) -> Result<w::Context, p::syscall::SysError> {
        let owner = self.owner.as_ref().ok_or_else(denied)?;
        same(&consent_peer::capture(owner.instance.endpoint)?, owner)?;
        let context = self
            .last
            .filter(|context| context.active)
            .ok_or_else(denied)?;
        if channel.context() != Some(context)
            || !member(self.domain.as_ref().ok_or_else(denied)?, requester)?
        {
            return Err(denied());
        }
        Ok(context)
    }
    pub fn publish(
        &mut self,
        sender: u64,
        context: w::Context,
        domain: Option<DomainReference>,
        trusted: &TrustedImages,
        channel: &mut Option<Channel>,
        revoke: impl FnOnce(),
    ) -> Result<(), p::syscall::SysError> {
        let owner = consent_peer::capture(sender)?;
        if trusted.role(&owner)? != Some(Role::SessionOwner) {
            return Err(denied());
        }
        if let Some(previous) = &self.owner {
            same(&owner, previous)?;
        }
        if self.last.is_some_and(|old| {
            context.generation < old.generation
                || (context.generation == old.generation
                    && (context.active || context.session != old.session))
        }) {
            return Err(denied());
        }
        if context.active != domain.is_some() {
            return Err(denied());
        }
        self.last = Some(context);
        self.domain = None;
        if self.owner.is_none() {
            self.owner = Some(owner);
        }
        revoke();
        if let Some(domain) = &domain {
            // The owner need not belong to the domain. A valid false reply
            // authenticates the delegated provider object without a PID query.
            let _ = member(domain, self.owner.as_ref().ok_or_else(denied)?)?;
        }
        if channel.is_none() {
            *channel = Some(Channel::connect(trusted)?);
        }
        channel.as_mut().ok_or_else(denied)?.update(context)?;
        self.domain = domain;
        Ok(())
    }
}
