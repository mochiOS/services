//! Native observations for the shared presenter handoff. Only this adapter
//! captures peers, desktop membership, scanout and the independent input route.
use super::*;
use crate::{
    consent_peer, consent_presentation,
    trusted_images::{Role, TrustedImages},
};
use p::capability::presentation as w;

fn observed<T>(stage: &str, result: Result<T, SysError>) -> Result<T, SysError> {
    result.inspect_err(|reason| {
        p::logln!(
            "capability.service: execution consent {stage} failed raw={}",
            reason.raw()
        );
    })
}

pub(crate) struct Native<'a> {
    pub trusted: &'a TrustedImages,
    pub sessions: &'a consent_presentation::Sessions,
    pub display: Option<&'a consent_presentation::Channel>,
    pub input: Option<&'a mut crate::consent_input::Channel>,
}
impl Native<'_> {
    fn display(&self) -> Result<&consent_presentation::Channel, SysError> {
        self.display.ok_or_else(|| error(NativeError::NotReady))
    }
}
impl Authority for Native<'_> {
    fn presenter(&self, peer: &Peer, kind: Kind) -> Result<(), SysError> {
        let expected = match kind {
            Kind::Text => Role::TextDisplay,
            Kind::Graphical => Role::GraphicalPrompt,
        };
        if self.trusted.role(peer)? == Some(expected) {
            Ok(())
        } else {
            Err(denied())
        }
    }
    fn requester_kind(&self, peer: &Peer) -> Result<Kind, SysError> {
        self.current(peer)?;
        let process = crate::consent_peer::ProcessReference(p::process::open_handle_for_endpoint(
            peer.instance.endpoint,
            p::handle::HANDLE_RIGHT_WAIT | p::handle::HANDLE_RIGHT_TRANSFER,
        )?);
        if !p::handle::same_object(process.0, peer.process.0)? {
            return Err(denied());
        }
        let terminal = crate::persistent_grant::with_client(|client| {
            client.process_has_terminal(mochios_posix_client::ObjectHandleAttachment {
                handle: process.0,
                rights: p::handle::HANDLE_RIGHT_WAIT,
            })
        })?;
        self.current(peer)?;
        Ok(if terminal || self.trusted.role(peer)? == Some(Role::TextPrompt) {
            Kind::Text
        } else {
            Kind::Graphical
        })
    }
    fn text_matches(&self, master: u32, requester: &Peer) -> Result<bool, SysError> {
        self.current(requester)?;
        let process = crate::consent_peer::ProcessReference(p::process::open_handle_for_endpoint(
            requester.instance.endpoint,
            p::handle::HANDLE_RIGHT_WAIT | p::handle::HANDLE_RIGHT_TRANSFER,
        )?);
        if !p::handle::same_object(process.0, requester.process.0)? {
            return Err(denied());
        }
        let included = crate::persistent_grant::with_client(|client| {
            client.terminal_process_foreground(
                mochios_posix_client::ObjectHandleAttachment {
                    handle: master,
                    rights: p::handle::HANDLE_RIGHT_CONTROL | p::handle::HANDLE_RIGHT_TRANSFER,
                },
                mochios_posix_client::ObjectHandleAttachment {
                    handle: process.0,
                    rights: p::handle::HANDLE_RIGHT_WAIT,
                },
            )
        })?;
        self.current(requester)?;
        Ok(included)
    }
    fn same_terminal(&self, left: u32, right: u32) -> Result<bool, SysError> {
        p::handle::same_object(left, right)
    }
    fn current(&self, expected: &Peer) -> Result<(), SysError> {
        let current = consent_peer::capture(expected.instance.endpoint)?;
        if current.instance != expected.instance
            || !p::handle::same_object(current.process.0, expected.process.0)?
        {
            return Err(denied());
        }
        Ok(())
    }
    fn session(&self, peer: &Peer) -> Result<Session, SysError> {
        let context = observed(
            "desktop membership",
            self.sessions.authenticate_member(self.display()?, peer),
        )?;
        Ok(Session {
            id: context.session,
            generation: context.generation,
        })
    }
    fn route(&self) -> Result<InputRoute, SysError> {
        let input = self
            .input
            .as_ref()
            .ok_or_else(|| error(NativeError::NotReady))?;
        input.current()?;
        if !input.idle() {
            return Err(busy());
        }
        Ok(input.route())
    }
    fn challenge(&self) -> Result<[u8; 32], SysError> {
        let mut bytes = [0; 32];
        if p::syscall::call2(
            p::syscall::SyscallNumber::RandomFill,
            bytes.as_mut_ptr() as u64,
            bytes.len() as u64,
        )? != bytes.len() as u64
        {
            return Err(error(NativeError::BackingFailure));
        }
        Ok(bytes)
    }
    fn register(&self, peer: &Peer, correlation: Correlation, kind: Kind) -> Result<u64, SysError> {
        let kind = match kind {
            Kind::Text => w::Kind::Window,
            Kind::Graphical => w::Kind::SecureOverlay,
        };
        Ok(observed(
            "display registration",
            self.display()?
                .register(self.trusted, peer, correlation, kind),
        )?
        .registration)
    }
    fn observe(
        &self,
        requester: Instance,
        peer: &Peer,
        presenter: Presenter,
        route: InputRoute,
        correlation: Correlation,
        policy: u64,
    ) -> Result<Witness, SysError> {
        self.current(peer)?;
        let requester_peer = consent_peer::capture(requester.endpoint)?;
        if requester_peer.instance != requester {
            return Err(denied());
        }
        let session = self.session(&requester_peer)?;
        let input = self.input.as_ref().ok_or_else(denied)?;
        input.current()?;
        if input.route() != route {
            return Err(denied());
        }
        let receipt = observed(
            "display status",
            self.display()?.status(correlation, presenter.registration),
        )?;
        if receipt.renderer
            != (w::Image {
                process: peer.instance.process,
                revision: peer.instance.revision,
                digest: peer.instance.digest,
            })
        {
            return Err(denied());
        }
        match receipt.stage {
            w::Stage::Pending => return Err(error(NativeError::NotReady)),
            w::Stage::Revoked => return Err(denied()),
            w::Stage::Presented => {}
        }
        if receipt.surface == 0
            || receipt.content_generation == 0
            || receipt.focus_generation == 0
            || receipt.context.session != session.id
            || receipt.context.generation != session.generation
        {
            return Err(denied());
        }
        Ok(Witness {
            requester: requester_peer,
            current: Current {
                requester: Some(requester),
                presenter: Some(presenter),
                input: Some(route),
                session: Some(session),
                policy_generation: policy,
                foreground: true,
            },
        })
    }
    fn arm(&mut self, correlation: Correlation) -> Result<(u64, bool), SysError> {
        let reply = self.input.as_mut().ok_or_else(denied)?.arm(correlation)?;
        Ok((reply.serial, reply.all_released))
    }
    fn synchronized(&self) -> Result<(), SysError> {
        self.input.as_ref().ok_or_else(denied)?.synchronized()
    }
    fn dismiss(&mut self, correlation: Correlation, registration: u64) {
        if let Some(input) = self.input.as_mut().filter(|input| !input.idle()) {
            if let Err(reason) = input.cancel() {
                p::logln!(
                    "capability.service: consent input cancellation failed raw={}",
                    reason.raw()
                );
            }
        }
        if let Some(display) = self.display {
            if let Err(reason) = display.cancel(correlation, registration) {
                p::logln!(
                    "capability.service: consent display cancellation failed raw={}",
                    reason.raw()
                );
            }
        }
    }
    fn reply_error(&self, target: u64, reason: SysError) {
        let status = u64::from(
            mochios_posix_protocol::status::normalize_failure(reason.raw()).unsigned_abs(),
        );
        let _ = p::ipc::reply(target, &status.to_le_bytes());
    }
}
