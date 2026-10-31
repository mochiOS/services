//! Service-owned, nonblocking consent transactions shared by every presenter.
//! Adapters authenticate peers and capture image/session/focus observations.
//! Wire-supplied identities, input serials, flags or Boolean trust claims must
//! never be used to construct those observations. No UI or grant runs here.
use mochi_user_platform::capability::consent::{Choice, Choices, Correlation, Feedback, Ticket};

pub(crate) const MAX_PENDING: usize = 32;
pub(crate) const MAX_TIMEOUT_NS: u64 = 120_000_000_000;

/// Kernel-observed endpoint owner plus its committed image measurement.
/// An unmeasured image cannot supply this witness. A SHA256 value of zero is
/// still a measured digest; it is not used as an unmeasured sentinel here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Instance {
    pub endpoint: u64,
    pub process: u64,
    pub thread: u64,
    pub revision: u64,
    pub digest: [u8; 32],
}

impl Instance {
    fn valid(self) -> bool {
        self.endpoint != 0 && self.process != 0 && self.thread != 0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Session {
    pub id: u64,
    pub generation: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Presenter {
    pub instance: Instance,
    pub registration: u64,
}

/// An authority-registered route to this presentation, not a normal stdio/PTY
/// stream. Its generation changes when routing/focus ownership is replaced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct InputRoute {
    pub source: Instance,
    pub seat: u64,
    pub generation: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Action {
    Launch,
    ProcessGrant,
    Operation,
}

/// Only the verified execution/operation gate constructs this binding. The
/// requirements digest binds the canonical capabilities, resources and scope.
/// Feedback cannot substitute any of these fields. Captured object ownership
/// stays with the gate until the final native authorization/commit completes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Binding {
    pub requester: Instance,
    pub session: Session,
    pub policy_generation: u64,
    pub source_digest: [u8; 32],
    pub prepared_digest: [u8; 32],
    pub requirements_digest: [u8; 32],
    pub action: Action,
}

/// Fresh observations made by the service adapter, not by the response sender.
/// Missing processes, failed reads and unavailable session/focus observations
/// stay missing; none may fall back to a cached identity or another process.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Current {
    pub requester: Option<Instance>,
    pub presenter: Option<Presenter>,
    pub input: Option<InputRoute>,
    pub session: Option<Session>,
    pub policy_generation: u64,
    pub foreground: bool,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct Offer {
    pub correlation: Correlation,
    pub deadline: u64,
    pub choices: Choices,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Transition {
    AllReleased,
    PhysicalPress,
    Repeat,
    Synthetic,
    Release,
}

impl From<mochi_user_platform::capability::input_authority::Transition> for Transition {
    fn from(value: mochi_user_platform::capability::input_authority::Transition) -> Self {
        use mochi_user_platform::capability::input_authority::Transition as T;
        match value {
            T::AllReleased => Self::AllReleased,
            T::PhysicalPress => Self::PhysicalPress,
            T::Repeat => Self::Repeat,
            T::Synthetic => Self::Synthetic,
            T::Release => Self::Release,
        }
    }
}

/// A decision at an observed point, not a kernel permit or grant. Native
/// authorization must still bind the same target bytes and execution instance
/// atomically at commit. A check followed by unbound CapTransfer is not safe.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Approval {
    binding: Binding,
    choice: Choice,
}

impl Approval {
    pub fn into_parts(self) -> (Binding, Choice) {
        (self.binding, self.choice)
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Outcome {
    Pending,
    Denied(Binding),
    Approved(Approval),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Error {
    Invalid,
    Full,
    Busy,
    Exhausted,
    ClockWentBack,
    Unknown,
    WrongPeer,
    WrongDisplay,
    InvalidState,
    StaleInput,
    MissingPresence,
    UnofferedChoice,
    Expired,
    Changed,
}

#[derive(Clone, Copy)]
struct Presence {
    serial: u64,
    released: bool,
    gesture: Option<u64>,
}

#[derive(Clone, Copy)]
enum Stage {
    Offered,
    Presented,
    Armed(Presence),
}

#[derive(Clone, Copy)]
struct Pending {
    offer: Offer,
    binding: Binding,
    presenter: Presenter,
    input: InputRoute,
    stage: Stage,
}

impl Pending {
    fn matches(self, current: Current) -> bool {
        current.requester == Some(self.binding.requester)
            && current.presenter == Some(self.presenter)
            && current.input == Some(self.input)
            && current.session == Some(self.binding.session)
            && current.policy_generation == self.binding.policy_generation
            && current.foreground
    }
}

pub(crate) struct Controller {
    pending: [Option<Pending>; MAX_PENDING],
    next_id: Option<u64>,
    last_now: u64,
}

impl Controller {
    pub const fn new() -> Self {
        Self {
            pending: [None; MAX_PENDING],
            next_id: Some(1),
            last_now: 0,
        }
    }

    fn clock(&mut self, now: u64) -> Result<(), Error> {
        if now < self.last_now {
            return Err(Error::ClockWentBack);
        }
        self.last_now = now;
        Ok(())
    }

    pub fn begin(
        &mut self,
        binding: Binding,
        presenter: Presenter,
        input: InputRoute,
        choices: Choices,
        now: u64,
        timeout: u64,
        challenge: [u8; 32],
    ) -> Result<Offer, Error> {
        self.clock(now)?;
        if !binding.requester.valid()
            || !presenter.instance.valid()
            || !input.source.valid()
            || input.source.process == presenter.instance.process
            || presenter.registration == 0
            || input.generation == 0
            || binding.session.id == 0
            || binding.session.generation == 0
            || binding.policy_generation == 0
            || timeout == 0
            || timeout > MAX_TIMEOUT_NS
            || challenge == [0; 32]
            || (binding.action == Action::ProcessGrant && choices.contains(Choice::AllowOnce))
            || (binding.action != Action::ProcessGrant && choices.contains(Choice::AllowForProcess))
        {
            return Err(Error::Invalid);
        }
        let deadline = now.checked_add(timeout).ok_or(Error::Exhausted)?;
        if self.pending.iter().flatten().any(|p| {
            p.presenter.instance.endpoint == presenter.instance.endpoint
                || p.offer.correlation.ticket.challenge == challenge
        }) {
            // A renderer cannot have two overlapping active questions. A new
            // display/re-registration requires cancellation and a fresh ticket.
            return Err(Error::Busy);
        }
        let slot = self
            .pending
            .iter_mut()
            .find(|p| p.is_none())
            .ok_or(Error::Full)?;
        let id = self.next_id.ok_or(Error::Exhausted)?;
        let offer = Offer {
            correlation: Correlation {
                ticket: Ticket { id, challenge },
                display: id,
            },
            deadline,
            choices,
        };
        *slot = Some(Pending {
            offer,
            binding,
            presenter,
            input,
            stage: Stage::Offered,
        });
        self.next_id = id.checked_add(1);
        Ok(offer)
    }

    fn locate(&self, correlation: Correlation) -> Result<usize, Error> {
        let index = self
            .pending
            .iter()
            .position(|p| {
                p.is_some_and(|p| {
                    p.offer.correlation.ticket.id == correlation.ticket.id
                        && p.offer
                            .correlation
                            .ticket
                            .challenge
                            .iter()
                            .zip(correlation.ticket.challenge)
                            .fold(0u8, |diff, (a, b)| diff | (a ^ b))
                            == 0
                })
            })
            .ok_or(Error::Unknown)?;
        if self.pending[index].unwrap().offer.correlation.display != correlation.display {
            return Err(Error::WrongDisplay);
        }
        Ok(index)
    }

    fn live(&mut self, index: usize, now: u64) -> Result<Pending, Error> {
        let pending = self.pending[index].unwrap();
        if now >= pending.offer.deadline {
            self.pending[index] = None;
            return Err(Error::Expired);
        }
        Ok(pending)
    }

    pub fn feedback(
        &mut self,
        peer: Instance,
        correlation: Correlation,
        feedback: Feedback,
        current: Current,
        now: u64,
    ) -> Result<Outcome, Error> {
        self.clock(now)?;
        let index = self.locate(correlation)?;
        let mut pending = self.live(index, now)?;
        if peer != pending.presenter.instance {
            return Err(Error::WrongPeer);
        }
        if !pending.matches(current) {
            self.pending[index] = None;
            return Err(Error::Changed);
        }
        match feedback {
            Feedback::Presented => {
                if !matches!(pending.stage, Stage::Offered) {
                    return Err(Error::InvalidState);
                }
                pending.stage = Stage::Presented;
                self.pending[index] = Some(pending);
                Ok(Outcome::Pending)
            }
            Feedback::Dismissed
            | Feedback::Decision {
                choice: Choice::Deny,
                gesture: 0,
            } => {
                self.pending[index] = None;
                Ok(Outcome::Denied(pending.binding))
            }
            Feedback::Decision { choice, gesture } => {
                if choice == Choice::Deny || !pending.offer.choices.contains(choice) {
                    return Err(Error::UnofferedChoice);
                }
                let Stage::Armed(presence) = pending.stage else {
                    return Err(Error::MissingPresence);
                };
                if gesture == 0 || presence.gesture != Some(gesture) {
                    return Err(Error::MissingPresence);
                }
                // Consume before returning control to any I/O, persistence or
                // native grant. A failed external action cannot replay consent.
                self.pending[index] = None;
                Ok(Outcome::Approved(Approval {
                    binding: pending.binding,
                    choice,
                }))
            }
        }
    }

    /// The registered input authority snapshots its current serial/key state
    /// AFTER the presenter has acknowledged display. Frontend-supplied serials
    /// or an old snapshot cannot substitute for this separate message.
    pub fn arm(
        &mut self,
        peer: Instance,
        correlation: Correlation,
        route: InputRoute,
        serial: u64,
        all_released: bool,
        now: u64,
    ) -> Result<(), Error> {
        self.clock(now)?;
        let index = self.locate(correlation)?;
        let mut pending = self.live(index, now)?;
        if peer != pending.input.source || route != pending.input {
            return Err(Error::WrongPeer);
        }
        if !matches!(pending.stage, Stage::Presented) {
            return Err(Error::InvalidState);
        }
        pending.stage = Stage::Armed(Presence {
            serial,
            released: all_released,
            gesture: None,
        });
        self.pending[index] = Some(pending);
        Ok(())
    }

    pub fn input(
        &mut self,
        peer: Instance,
        correlation: Correlation,
        route: InputRoute,
        serial: u64,
        transition: Transition,
        now: u64,
    ) -> Result<(), Error> {
        self.clock(now)?;
        let index = self.locate(correlation)?;
        let mut pending = self.live(index, now)?;
        if peer != pending.input.source || route != pending.input {
            return Err(Error::WrongPeer);
        }
        let Stage::Armed(mut presence) = pending.stage else {
            return Err(Error::InvalidState);
        };
        if serial <= presence.serial {
            return Err(Error::StaleInput);
        }
        presence.serial = serial;
        match transition {
            Transition::AllReleased => presence.released = true,
            Transition::PhysicalPress => {
                if presence.released {
                    presence.gesture = Some(serial);
                }
                presence.released = false;
            }
            Transition::Repeat | Transition::Synthetic | Transition::Release => {}
        }
        pending.stage = Stage::Armed(presence);
        self.pending[index] = Some(pending);
        Ok(())
    }

    pub fn cancel(&mut self, peer: Instance, correlation: Correlation) -> Result<Binding, Error> {
        let index = self.locate(correlation)?;
        let pending = self.pending[index].unwrap();
        if peer != pending.binding.requester
            && peer != pending.presenter.instance
            && peer != pending.input.source
        {
            return Err(Error::WrongPeer);
        }
        self.pending[index] = None;
        Ok(pending.binding)
    }

    /// The owner replies to expired waiters from this callback. No IPC or
    /// frontend wait is performed by the state machine itself.
    pub fn expire(
        &mut self,
        now: u64,
        mut expired: impl FnMut(Ticket, Binding),
    ) -> Result<(), Error> {
        self.clock(now)?;
        for slot in &mut self.pending {
            if slot.is_some_and(|p| now >= p.offer.deadline) {
                let pending = slot.take().unwrap();
                expired(pending.offer.correlation.ticket, pending.binding);
            }
        }
        Ok(())
    }

    pub fn len(&self) -> usize {
        self.pending.iter().flatten().count()
    }

    /// Poll native execution/session/route observations without waiting for a
    /// renderer response. The owner also dismisses the matching display and
    /// replies to the original waiter from the cancellation callback.
    pub fn observe(
        &mut self,
        mut current: impl FnMut(Binding, Presenter, InputRoute) -> Current,
        mut cancelled: impl FnMut(Ticket, Binding),
    ) {
        for slot in &mut self.pending {
            if let Some(pending) = *slot {
                if !pending.matches(current(pending.binding, pending.presenter, pending.input)) {
                    *slot = None;
                    cancelled(pending.offer.correlation.ticket, pending.binding);
                }
            }
        }
    }

    pub fn next_deadline(&self) -> Option<u64> {
        self.pending
            .iter()
            .flatten()
            .map(|p| p.offer.deadline)
            .min()
    }
}
