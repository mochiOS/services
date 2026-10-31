//! Native transport probe only. Presenter/session observations below are test
//! fixtures; this never grants a capability, persists consent or launches code.
use crate::{consent::*, consent_input::Channel, consent_peer};
use mochi_user_platform as p;
use p::capability::{
    consent::{Choice, Choices, Feedback},
    input_authority as w,
};
pub const START: u32 = u32::from_le_bytes(*b"ID06");
pub(crate) struct Probe {
    binding: Binding,
    presenter: Presenter,
    route: InputRoute,
    offer: Offer,
    synthetic: bool,
    physical: Option<u64>,
}
fn denied() -> p::syscall::SysError {
    p::syscall::SysError::from_raw(p::syscall::NativeError::AccessDenied.into_raw() as i64)
}
impl Probe {
    pub fn start(
        sender: u64,
        controller: &mut Controller,
        channel: &mut Channel,
    ) -> Result<(Self, w::Event), p::syscall::SysError> {
        let peer = consent_peer::capture(sender)?;
        let binding = Binding {
            requester: peer.instance,
            session: Session {
                id: u64::MAX,
                generation: 1,
            },
            policy_generation: 1,
            source_digest: peer.instance.digest,
            prepared_digest: peer.instance.digest,
            requirements_digest: [1; 32],
            action: Action::Operation,
        };
        let presenter = Presenter {
            instance: peer.instance,
            registration: 1,
        };
        let route = channel.route();
        let mut challenge = [0; 32];
        if p::syscall::call2(
            p::syscall::SyscallNumber::RandomFill,
            challenge.as_mut_ptr() as u64,
            32,
        )? != 32
        {
            return Err(denied());
        }
        let now = p::time::monotonic_nanoseconds()?;
        let offer = controller
            .begin(
                binding,
                presenter,
                route,
                Choices::new(Choices::ONCE).unwrap(),
                now,
                MAX_TIMEOUT_NS,
                challenge,
            )
            .map_err(|_| denied())?;
        let probe = Self {
            binding,
            presenter,
            route,
            offer,
            synthetic: false,
            physical: None,
        };
        controller
            .feedback(
                presenter.instance,
                offer.correlation,
                Feedback::Presented,
                probe.current(),
                now,
            )
            .map_err(|_| denied())?;
        let snapshot = channel.arm(offer.correlation)?;
        controller
            .arm(
                route.source,
                offer.correlation,
                route,
                snapshot.serial,
                snapshot.all_released,
                now,
            )
            .map_err(|_| denied())?;
        let forged = w::Event {
            generation: route.generation,
            correlation: offer.correlation,
            observation: w::Observation {
                serial: snapshot.serial.checked_add(1).ok_or_else(denied)?,
                transition: w::Transition::PhysicalPress,
                control: 0x15,
            },
        };
        Ok((probe, forged))
    }
    fn current(&self) -> Current {
        Current {
            requester: Some(self.binding.requester),
            presenter: Some(self.presenter),
            input: Some(self.route),
            session: Some(self.binding.session),
            policy_generation: 1,
            foreground: true,
        }
    }
    pub fn observe(
        &mut self,
        event: w::Event,
        controller: &mut Controller,
        channel: &mut Channel,
    ) -> Result<bool, p::syscall::SysError> {
        let now = p::time::monotonic_nanoseconds()?;
        if event.observation.transition == w::Transition::Synthetic && self.physical.is_none() {
            let decision = Feedback::Decision {
                choice: Choice::AllowOnce,
                gesture: event.observation.serial,
            };
            if controller.feedback(
                self.presenter.instance,
                self.offer.correlation,
                decision,
                self.current(),
                now,
            ) != Err(Error::MissingPresence)
            {
                return Err(denied());
            }
            self.synthetic = true;
        }
        if event.observation.transition == w::Transition::PhysicalPress
            && event.observation.control == 0x15
        {
            self.physical = Some(event.observation.serial);
        }
        if event.observation.transition == w::Transition::AllReleased
            && event.observation.control == 0x15
            && self.synthetic
        {
            if let Some(gesture) = self.physical {
                let snapshot = channel.status()?;
                if snapshot.serial != event.observation.serial || !snapshot.all_released {
                    return Ok(false);
                }
                let decision = Feedback::Decision {
                    choice: Choice::AllowOnce,
                    gesture,
                };
                let Outcome::Approved(approval) = controller
                    .feedback(
                        self.presenter.instance,
                        self.offer.correlation,
                        decision,
                        self.current(),
                        now,
                    )
                    .map_err(|_| denied())?
                else {
                    return Err(denied());
                };
                if approval.into_parts() != (self.binding, Choice::AllowOnce) {
                    return Err(denied());
                }
                channel.cancel()?;
                let text=b"consent-input-306: PASS measured authority, forged sender denied, synthetic denied, fresh physical press and release (no grant)\n";
                let _ = p::syscall::call2(
                    p::syscall::SyscallNumber::DebugWrite,
                    text.as_ptr() as u64,
                    text.len() as u64,
                );
                return Ok(true);
            }
        }
        Ok(false)
    }
}
