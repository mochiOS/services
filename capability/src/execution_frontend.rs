//! Nonblocking presenter handoff for the shared execution gate. Waiting IPC
//! calls and active requests retain their native owners; no UI Boolean grants.
use crate::{
    consent::{
        self, Controller, Current, InputRoute, Instance, Offer, Outcome, Presenter, Session,
    },
    consent_peer::Peer,
    execution_approval::{Pending, Selection},
    execution_requests::{Registry, Reply, Reservation},
};
use alloc::vec::Vec;
use mochi_user_platform as p;
use p::capability::consent::{
    Choice, Correlation, Feedback,
    frontend::{Action, Kind},
};
use p::syscall::{NativeError, SysError};
#[path = "execution_frontend/native.rs"]
#[cfg(not(test))]
pub(crate) mod native;

fn error(error: NativeError) -> SysError {
    SysError::from(error.into_raw())
}
fn denied() -> SysError {
    error(NativeError::AccessDenied)
}
fn busy() -> SysError {
    // Presenter restart, an occupied seat and input synchronization are
    // temporary readiness states, not failed storage allocations.
    error(NativeError::NotReady)
}

pub(crate) struct Witness {
    pub current: Current,
    pub requester: Peer,
}
/// Every observation is captured by a broker-owned adapter. Frontend messages
/// supply only correlation and choice, never any field of Witness/InputRoute.
pub(crate) trait Authority {
    fn presenter(&self, peer: &Peer, kind: Kind) -> Result<(), SysError>;
    fn requester_kind(&self, peer: &Peer) -> Result<Kind, SysError>;
    fn text_matches(&self, master: u32, requester: &Peer) -> Result<bool, SysError>;
    fn same_terminal(&self, left: u32, right: u32) -> Result<bool, SysError>;
    fn current(&self, peer: &Peer) -> Result<(), SysError>;
    fn session(&self, peer: &Peer) -> Result<Session, SysError>;
    fn route(&self) -> Result<InputRoute, SysError>;
    fn challenge(&self) -> Result<[u8; 32], SysError>;
    fn register(&self, peer: &Peer, correlation: Correlation, kind: Kind) -> Result<u64, SysError>;
    fn observe(
        &self,
        requester: Instance,
        peer: &Peer,
        presenter: Presenter,
        route: InputRoute,
        correlation: Correlation,
        policy: u64,
    ) -> Result<Witness, SysError>;
    fn arm(&mut self, correlation: Correlation) -> Result<(u64, bool), SysError>;
    fn synchronized(&self) -> Result<(), SysError>;
    fn dismiss(&mut self, correlation: Correlation, registration: u64);
    fn reply_error(&self, target: u64, reason: SysError);
}
struct Active {
    peer: Peer,
    requester: Instance,
    presenter: Presenter,
    route: InputRoute,
    offer: Offer,
    armed: bool,
    terminal: Option<crate::consent_peer::ProcessReference>,
    text_input: crate::text_evidence::Evidence,
}
struct TextWaiter {
    peer: Peer,
    master: crate::consent_peer::ProcessReference,
}
pub(crate) struct Frontends {
    idle: [Option<Peer>; 2],
    active: Option<Active>,
    text: Vec<TextWaiter>,
}
impl Frontends {
    pub(crate) fn new() -> Self {
        Self {
            idle: [None, None],
            active: None,
            text: Vec::new(),
        }
    }
    fn index(kind: Kind) -> usize {
        match kind {
            Kind::Text => 0,
            Kind::Graphical => 1,
        }
    }
    pub(crate) fn wait(
        &mut self,
        peer: Peer,
        kind: Kind,
        authority: &impl Authority,
    ) -> Result<(), SysError> {
        authority.presenter(&peer, kind)?;
        authority.current(&peer)?;
        let slot = &mut self.idle[Self::index(kind)];
        if slot.is_some()
            || self
                .active
                .as_ref()
                .is_some_and(|active| active.peer.instance.endpoint == peer.instance.endpoint)
        {
            return Err(busy());
        }
        *slot = Some(peer);
        Ok(())
    }
    pub(crate) fn poll_text(
        &mut self,
        peer: Peer,
        master: crate::consent_peer::ProcessReference,
        authority: &impl Authority,
    ) -> Result<Option<Correlation>, SysError> {
        authority.presenter(&peer, Kind::Text)?;
        authority.current(&peer)?;
        // A valid false query authenticates the provider/controller object;
        // the Terminal UI process need not itself have a controlling terminal.
        let _ = authority.text_matches(master.0, &peer)?;
        if let Some(active) = &self.active {
            if active.peer.instance == peer.instance && active.terminal.is_some() {
                if authority.same_terminal(active.terminal.as_ref().unwrap().0, master.0)? {
                    return Ok(Some(active.offer.correlation));
                }
                return Err(busy());
            }
        }
        for waiter in &self.text {
            if waiter.peer.instance == peer.instance {
                return if authority.same_terminal(waiter.master.0, master.0)? {
                    Ok(None)
                } else {
                    Err(busy())
                };
            }
        }
        if self.text.len() == 16 {
            return Err(busy());
        }
        self.text
            .try_reserve(1)
            .map_err(|_| error(NativeError::ResourceUnavailable))?;
        self.text.push(TextWaiter { peer, master });
        Ok(None)
    }
    pub(crate) fn release_text(
        &mut self,
        registry: &mut Registry,
        controller: &mut Controller,
        peer: &Peer,
        master: u32,
        authority: &mut impl Authority,
        emit: impl FnMut(Reply),
    ) -> Result<(), SysError> {
        authority.presenter(peer, Kind::Text)?;
        if let Some(active) = &self.active {
            if active.peer.instance == peer.instance {
                if let Some(terminal) = &active.terminal {
                    if authority.same_terminal(terminal.0, master)? {
                        self.cancel(
                            registry,
                            controller,
                            NativeError::AccessDenied,
                            authority,
                            emit,
                        );
                        return Ok(());
                    }
                }
            }
        }
        for index in 0..self.text.len() {
            let waiter = &self.text[index];
            if waiter.peer.instance == peer.instance
                && authority.same_terminal(waiter.master.0, master)?
            {
                self.text.remove(index);
                break;
            }
        }
        Ok(())
    }
    pub(crate) fn observe_text_input(&mut self, event: p::capability::input_authority::Event) {
        if let Some(active) = self.active.as_mut() {
            if active.armed
                && active.terminal.is_some()
                && active.offer.correlation == event.correlation
            {
                active.text_input.observe(event.observation);
            }
        }
    }
    pub(crate) fn begin(
        &mut self,
        reservation: Reservation<'_>,
        controller: &mut Controller,
        selection: Selection,
        source: Vec<u8>,
        requester: Peer,
        key: &str,
        generation: u64,
        now: u64,
        authority: &mut impl Authority,
    ) -> Result<(Offer, Option<u64>), SysError> {
        if self.active.is_some() {
            return Err(busy());
        }
        let mut text_index = None;
        for (index, waiter) in self.text.iter().enumerate() {
            if authority.text_matches(waiter.master.0, &requester)? {
                if text_index.replace(index).is_some() {
                    return Err(denied());
                }
            }
        }
        let kind = if text_index.is_some() {
            Kind::Text
        } else {
            authority.requester_kind(&requester)?
        };
        let slot = Self::index(kind);
        let peer = match text_index {
            Some(index) => &self.text[index].peer,
            None => self.idle[slot].as_ref().ok_or_else(busy)?,
        };
        authority.presenter(peer, kind)?;
        authority.current(peer)?;
        let session = authority.session(&requester)?;
        let route = authority.route()?;
        let request = Pending::new(selection, source, requester, key, session, generation)?;
        let requester = request.binding().requester;
        let correlation = controller
            .next_correlation(authority.challenge()?)
            .map_err(|_| denied())?;
        let registration = authority.register(peer, correlation, kind)?;
        let presenter = Presenter {
            instance: peer.instance,
            registration,
        };
        let offer = match reservation.begin(
            controller,
            request,
            correlation,
            presenter,
            route,
            now,
            consent::MAX_TIMEOUT_NS,
        ) {
            Ok(offer) => offer,
            Err(reason) => {
                authority.dismiss(correlation, registration);
                return Err(reason);
            }
        };
        let (peer, terminal) = if let Some(index) = text_index {
            let waiter = self.text.remove(index);
            (waiter.peer, Some(waiter.master))
        } else {
            (self.idle[slot].take().unwrap(), None)
        };
        let destination = terminal.is_none().then_some(peer.instance.endpoint);
        self.active = Some(Active {
            peer,
            requester,
            presenter,
            route,
            offer,
            armed: false,
            terminal,
            text_input: crate::text_evidence::Evidence::default(),
        });
        Ok((offer, destination))
    }
    pub(crate) fn presenter_instance(
        &self,
        correlation: Correlation,
    ) -> Result<Instance, SysError> {
        self.active
            .as_ref()
            .filter(|active| active.offer.correlation == correlation)
            .map(|active| active.peer.instance)
            .ok_or_else(denied)
    }
    pub(crate) fn cancel(
        &mut self,
        registry: &mut Registry,
        controller: &mut Controller,
        reason: NativeError,
        authority: &mut impl Authority,
        mut emit: impl FnMut(Reply),
    ) {
        if let Some(active) = self.active.take() {
            if let Ok(reply) = registry.cancel(controller, active.offer.correlation, reason) {
                emit(reply);
            }
            authority.dismiss(active.offer.correlation, active.presenter.registration);
        }
    }
    /// Called before waiting, and after policy/session expiry. Image changes
    /// and presenter death cannot leave a live grant or an orphaned source.
    pub(crate) fn maintain(
        &mut self,
        registry: &mut Registry,
        controller: &mut Controller,
        authority: &mut impl Authority,
        mut emit: impl FnMut(Reply),
    ) {
        for slot in &mut self.idle {
            if let Some(peer) = slot.as_ref() {
                if let Err(reason) = authority.current(peer) {
                    authority.reply_error(peer.instance.endpoint, reason);
                    *slot = None;
                }
            }
        }
        self.text
            .retain(|waiter| authority.current(&waiter.peer).is_ok());
        if self.active.as_ref().is_some_and(|active| {
            !registry.contains(active.offer.correlation) || authority.current(&active.peer).is_err()
        }) {
            self.cancel(
                registry,
                controller,
                NativeError::PeerClosed,
                authority,
                &mut emit,
            );
        }
    }
    pub(crate) fn process_handles(&self, mut emit: impl FnMut(u32)) {
        for waiter in &self.text {
            emit(waiter.peer.process.0);
        }
        for peer in self.idle.iter().flatten() {
            emit(peer.process.0);
        }
        if let Some(active) = &self.active {
            emit(active.peer.process.0);
        }
    }
    pub(crate) fn command(
        &mut self,
        registry: &mut Registry,
        controller: &mut Controller,
        peer: &Peer,
        correlation: Correlation,
        action: Action,
        generation: u64,
        now: u64,
        authority: &mut impl Authority,
        mut emit: impl FnMut(Reply),
    ) -> Result<(), SysError> {
        let active = self
            .active
            .as_ref()
            .filter(|active| active.offer.correlation == correlation)
            .ok_or_else(denied)?;
        if peer.instance != active.peer.instance {
            return Err(denied());
        }
        authority.current(&active.peer)?;
        if matches!(action, Action::Dismissed | Action::Decide(Choice::Deny)) {
            self.cancel(
                registry,
                controller,
                NativeError::AccessDenied,
                authority,
                emit,
            );
            return Ok(());
        }
        let witness = match authority.observe(
            active.requester,
            &active.peer,
            active.presenter,
            active.route,
            correlation,
            generation,
        ) {
            Ok(witness) => witness,
            Err(reason) if reason.native_error() == Some(NativeError::NotReady) => {
                return Err(busy());
            }
            Err(reason) => {
                self.cancel(
                    registry,
                    controller,
                    NativeError::AccessDenied,
                    authority,
                    emit,
                );
                return Err(reason);
            }
        };
        if let Some(master) = &active.terminal {
            if !authority.text_matches(master.0, &witness.requester)? {
                self.cancel(
                    registry,
                    controller,
                    NativeError::AccessDenied,
                    authority,
                    emit,
                );
                return Err(denied());
            }
        }
        if action == Action::Presented {
            if active.armed {
                authority.synchronized()?;
                return Ok(());
            }
            if controller.feedback(
                peer.instance,
                correlation,
                Feedback::Presented,
                witness.current,
                now,
            ) != Ok(Outcome::Pending)
            {
                self.cancel(
                    registry,
                    controller,
                    NativeError::AccessDenied,
                    authority,
                    emit,
                );
                return Err(denied());
            }
            let (serial, released) = match authority.arm(correlation) {
                Ok(snapshot) => snapshot,
                Err(reason) => {
                    self.cancel(
                        registry,
                        controller,
                        NativeError::AccessDenied,
                        authority,
                        emit,
                    );
                    return Err(reason);
                }
            };
            if controller
                .arm(
                    active.route.source,
                    correlation,
                    active.route,
                    serial,
                    released,
                    now,
                )
                .is_err()
            {
                self.cancel(
                    registry,
                    controller,
                    NativeError::AccessDenied,
                    authority,
                    emit,
                );
                return Err(denied());
            }
            self.active.as_mut().unwrap().armed = true;
            self.active.as_mut().unwrap().text_input.arm(released);
            return Ok(());
        }
        if !active.armed {
            return Err(busy());
        }
        authority.synchronized()?;
        let Action::Decide(choice) = action else {
            unreachable!()
        };
        if active.terminal.is_some() && !active.text_input.accepts(choice) {
            return Err(busy());
        }
        let approval =
            match controller.propose(peer.instance, correlation, choice, witness.current, now) {
                Ok(Outcome::Approved(approval)) => approval,
                Err(consent::Error::MissingPresence) => return Err(busy()),
                _ => {
                    self.cancel(
                        registry,
                        controller,
                        NativeError::AccessDenied,
                        authority,
                        emit,
                    );
                    return Err(denied());
                }
            };
        let active = self.active.take().unwrap();
        let reply = registry.finish(
            controller,
            correlation,
            approval,
            &witness.requester,
            witness.current.session.ok_or_else(denied)?,
            generation,
            now,
        );
        authority.dismiss(correlation, active.presenter.registration);
        let reply = match reply {
            Ok(reply) => reply,
            Err(reason) => {
                if let Ok(reply) =
                    registry.cancel(controller, correlation, NativeError::AccessDenied)
                {
                    emit(reply);
                }
                return Err(reason);
            }
        };
        let result = reply.result;
        emit(reply);
        result
    }
}
