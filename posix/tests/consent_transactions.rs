#[path = "../../capability/src/consent.rs"]
mod consent;
use consent::*;
use mochi_user_platform::capability::consent::{Choice, Choices, Correlation, Feedback};

fn instance(id: u64) -> Instance {
    Instance {
        endpoint: id,
        process: id + 100,
        thread: id + 200,
        revision: 0,
        digest: [id as u8; 32],
    }
}
fn binding() -> Binding {
    Binding {
        requester: instance(1),
        session: Session {
            id: 3,
            generation: 4,
        },
        policy_generation: 1,
        source_digest: [0x71; 32],
        prepared_digest: [0x72; 32],
        requirements_digest: [0x73; 32],
        action: Action::Launch,
    }
}
struct Fixture {
    controller: Controller,
    binding: Binding,
    presenter: Presenter,
    input: InputRoute,
    offer: Offer,
}
impl Fixture {
    fn new() -> Self {
        Self::with(Action::Launch, Choices::ONCE | Choices::PERSISTENT)
    }
    fn with(action: Action, choices: u8) -> Self {
        let mut controller = Controller::new();
        let binding = Binding {
            action,
            ..binding()
        };
        let presenter = Presenter {
            instance: instance(2),
            registration: 5,
        };
        let input = InputRoute {
            source: instance(4),
            seat: 0,
            generation: 7,
        };
        let offer = controller
            .begin(
                binding,
                presenter,
                input,
                Choices::new(choices).unwrap(),
                100,
                100,
                [0x98; 32],
            )
            .unwrap();
        Self {
            controller,
            binding,
            presenter,
            input,
            offer,
        }
    }
    fn current(&self) -> Current {
        Current {
            requester: Some(self.binding.requester),
            presenter: Some(self.presenter),
            input: Some(self.input),
            session: Some(self.binding.session),
            policy_generation: 1,
            foreground: true,
        }
    }
    fn feedback(&mut self, feedback: Feedback) -> Result<Outcome, Error> {
        let current = self.current();
        self.controller.feedback(
            self.presenter.instance,
            self.offer.correlation,
            feedback,
            current,
            100,
        )
    }
    fn arm(&mut self, released: bool) -> Result<(), Error> {
        self.controller.arm(
            self.input.source,
            self.offer.correlation,
            self.input,
            20,
            released,
            100,
        )
    }
    fn event(&mut self, serial: u64, transition: Transition) -> Result<(), Error> {
        self.controller.input(
            self.input.source,
            self.offer.correlation,
            self.input,
            serial,
            transition,
            100,
        )
    }
    fn ready(&mut self) {
        assert_eq!(self.feedback(Feedback::Presented), Ok(Outcome::Pending));
        self.arm(true).unwrap();
        self.event(21, Transition::PhysicalPress).unwrap();
    }
    fn allow(&mut self, gesture: u64) -> Result<Outcome, Error> {
        self.feedback(Feedback::Decision {
            choice: Choice::AllowOnce,
            gesture,
        })
    }
}

#[test]
fn consumes_exact_immutable_subject_once_after_display_and_independent_input() {
    let mut f = Fixture::new();
    f.ready();
    let Outcome::Approved(approval) = f.allow(21).unwrap() else {
        panic!("approval required")
    };
    assert_eq!(approval.into_parts(), (f.binding, Choice::AllowOnce));
    assert_eq!(f.controller.len(), 0);
    assert_eq!(f.allow(21), Err(Error::Unknown));
    // Native commit still has to bind these exact source/prepared/requirements hashes.
    assert_ne!(f.binding.source_digest, f.binding.prepared_digest);
}

#[test]
fn guessing_a_serial_or_echoing_y_is_not_evidence() {
    let mut f = Fixture::new();
    assert_eq!(f.allow(21), Err(Error::MissingPresence));
    assert_eq!(f.arm(true), Err(Error::InvalidState));
    f.feedback(Feedback::Presented).unwrap();
    assert_eq!(f.allow(21), Err(Error::MissingPresence));
    f.arm(true).unwrap();
    assert_eq!(f.allow(21), Err(Error::MissingPresence));
    assert_eq!(
        f.event(20, Transition::PhysicalPress),
        Err(Error::StaleInput)
    );
    assert_eq!(
        f.event(19, Transition::PhysicalPress),
        Err(Error::StaleInput)
    );
    f.event(21, Transition::Synthetic).unwrap();
    assert_eq!(f.allow(21), Err(Error::MissingPresence));
    f.event(22, Transition::Repeat).unwrap();
    assert_eq!(f.allow(22), Err(Error::MissingPresence));
    f.event(23, Transition::PhysicalPress).unwrap();
    assert!(matches!(f.allow(23), Ok(Outcome::Approved(_))));
}

#[test]
fn a_key_held_at_display_must_be_released_before_a_new_press() {
    let mut f = Fixture::new();
    f.feedback(Feedback::Presented).unwrap();
    f.arm(false).unwrap();
    for (serial, transition) in [
        (21, Transition::Repeat),
        (22, Transition::PhysicalPress),
        (23, Transition::Synthetic),
    ] {
        f.event(serial, transition).unwrap();
        assert_eq!(f.allow(serial), Err(Error::MissingPresence));
    }
    f.event(24, Transition::AllReleased).unwrap();
    assert_eq!(f.allow(24), Err(Error::MissingPresence));
    f.event(25, Transition::PhysicalPress).unwrap();
    assert!(matches!(f.allow(25), Ok(Outcome::Approved(_))));
}

#[test]
fn release_delivery_before_the_ui_response_does_not_lose_a_real_gesture() {
    let mut f = Fixture::new();
    f.ready();
    f.event(22, Transition::AllReleased).unwrap();
    assert!(matches!(f.allow(21), Ok(Outcome::Approved(_))));
}

#[test]
fn later_gesture_supersedes_old_evidence_without_changing_the_bound_request() {
    let mut f = Fixture::new();
    f.ready();
    f.event(22, Transition::AllReleased).unwrap();
    f.event(23, Transition::PhysicalPress).unwrap();
    assert_eq!(f.allow(21), Err(Error::MissingPresence));
    assert_eq!(f.controller.len(), 1);
    assert!(matches!(f.allow(23), Ok(Outcome::Approved(_))));
}

#[test]
fn frontend_cannot_self_attest_input_or_rearm_its_display() {
    let mut f = Fixture::new();
    f.feedback(Feedback::Presented).unwrap();
    assert_eq!(
        f.controller.arm(
            f.presenter.instance,
            f.offer.correlation,
            f.input,
            20,
            true,
            100
        ),
        Err(Error::WrongPeer)
    );
    f.arm(true).unwrap();
    assert_eq!(f.arm(true), Err(Error::InvalidState));
    assert_eq!(f.feedback(Feedback::Presented), Err(Error::InvalidState));
    assert_eq!(
        f.controller.input(
            f.presenter.instance,
            f.offer.correlation,
            f.input,
            21,
            Transition::PhysicalPress,
            100
        ),
        Err(Error::WrongPeer)
    );
    assert_eq!(f.allow(21), Err(Error::MissingPresence));
    f.event(21, Transition::PhysicalPress).unwrap();
    assert!(matches!(f.allow(21), Ok(Outcome::Approved(_))));
}

#[test]
fn wrong_route_and_foreign_authenticated_sender_cannot_answer_or_cancel() {
    let mut f = Fixture::new();
    f.ready();
    let current = f.current();
    for peer in [
        instance(99),
        Instance {
            process: 999,
            ..f.presenter.instance
        },
        Instance {
            revision: 1,
            ..f.presenter.instance
        },
        Instance {
            digest: [9; 32],
            ..f.presenter.instance
        },
    ] {
        assert_eq!(
            f.controller.feedback(
                peer,
                f.offer.correlation,
                Feedback::Decision {
                    choice: Choice::AllowOnce,
                    gesture: 21
                },
                current,
                100
            ),
            Err(Error::WrongPeer)
        );
        assert_eq!(
            f.controller.cancel(peer, f.offer.correlation),
            Err(Error::WrongPeer)
        );
    }
    let route = InputRoute {
        generation: f.input.generation + 1,
        ..f.input
    };
    assert_eq!(
        f.controller.input(
            f.input.source,
            f.offer.correlation,
            route,
            30,
            Transition::PhysicalPress,
            100
        ),
        Err(Error::WrongPeer)
    );
    assert!(matches!(f.allow(21), Ok(Outcome::Approved(_))));
}

#[test]
fn stale_display_and_wrong_challenge_do_not_consume_the_legitimate_request() {
    let mut f = Fixture::new();
    f.ready();
    let current = f.current();
    let correlation = f.offer.correlation;
    let wrong = Correlation {
        display: correlation.display + 1,
        ..correlation
    };
    assert_eq!(
        f.controller.feedback(
            f.presenter.instance,
            wrong,
            Feedback::Dismissed,
            current,
            100
        ),
        Err(Error::WrongDisplay)
    );
    for index in 0..32 {
        let mut wrong = correlation;
        wrong.ticket.challenge[index] ^= 1;
        assert_eq!(
            f.controller.feedback(
                f.presenter.instance,
                wrong,
                Feedback::Dismissed,
                current,
                100
            ),
            Err(Error::Unknown)
        );
    }
    assert!(matches!(f.allow(21), Ok(Outcome::Approved(_))));
}

#[test]
fn expiry_is_inclusive_and_never_turns_into_an_approval() {
    let mut f = Fixture::new();
    f.ready();
    let current = f.current();
    assert_eq!(
        f.controller.feedback(
            f.presenter.instance,
            f.offer.correlation,
            Feedback::Decision {
                choice: Choice::AllowOnce,
                gesture: 21
            },
            current,
            200
        ),
        Err(Error::Expired)
    );
    assert_eq!(f.controller.len(), 0);
    let mut f = Fixture::new();
    let mut expired = vec![];
    f.controller
        .expire(199, |t, b| expired.push((t, b)))
        .unwrap();
    assert!(expired.is_empty());
    f.controller
        .expire(200, |t, b| expired.push((t, b)))
        .unwrap();
    assert_eq!(expired, [(f.offer.correlation.ticket, f.binding)]);
    assert_eq!(f.controller.len(), 0);
    f.controller
        .expire(201, |_, _| panic!("duplicate expiry"))
        .unwrap();
}

#[test]
fn denial_and_dismissal_require_no_gesture_but_remain_bound_to_the_presenter() {
    for feedback in [
        Feedback::Dismissed,
        Feedback::Decision {
            choice: Choice::Deny,
            gesture: 0,
        },
    ] {
        let mut f = Fixture::new();
        assert_eq!(f.feedback(feedback), Ok(Outcome::Denied(f.binding)));
        assert_eq!(f.feedback(feedback), Err(Error::Unknown));
    }
}

#[test]
fn only_offered_scopes_can_be_approved_and_allow_once_never_becomes_a_process_grant() {
    let mut f = Fixture::with(Action::Launch, Choices::ONCE);
    f.ready();
    for choice in [Choice::AllowForProcess, Choice::AllowPersistently] {
        assert_eq!(
            f.feedback(Feedback::Decision {
                choice,
                gesture: 21
            }),
            Err(Error::UnofferedChoice)
        );
    }
    assert!(matches!(f.allow(21), Ok(Outcome::Approved(_))));
    for (action, bits, choice) in [
        (
            Action::ProcessGrant,
            Choices::PROCESS,
            Choice::AllowForProcess,
        ),
        (Action::Operation, Choices::ONCE, Choice::AllowOnce),
        (
            Action::Launch,
            Choices::PERSISTENT,
            Choice::AllowPersistently,
        ),
    ] {
        let mut f = Fixture::with(action, bits);
        f.ready();
        let Outcome::Approved(approval) = f
            .feedback(Feedback::Decision {
                choice,
                gesture: 21,
            })
            .unwrap()
        else {
            panic!("approval required")
        };
        assert_eq!(approval.into_parts(), (f.binding, choice));
    }
    let mut f = Fixture::new();
    let bad = Binding {
        action: Action::ProcessGrant,
        ..f.binding
    };
    assert!(matches!(
        f.controller.begin(
            bad,
            Presenter {
                registration: 6,
                instance: instance(9)
            },
            f.input,
            Choices::new(Choices::ONCE).unwrap(),
            100,
            50,
            [3; 32]
        ),
        Err(Error::Invalid)
    ));
}

#[test]
fn every_lost_or_changed_execution_route_session_policy_and_focus_revokes_the_question() {
    for mutation in 0..21 {
        let mut f = Fixture::new();
        f.ready();
        let mut current = f.current();
        match mutation {
            0 => current.requester = None,
            1 => current.presenter = None,
            2 => current.input = None,
            3 => current.session = None,
            4 => current.requester.as_mut().unwrap().process += 1,
            5 => current.requester.as_mut().unwrap().thread += 1,
            6 => current.requester.as_mut().unwrap().revision += 1,
            7 => current.requester.as_mut().unwrap().digest[0] ^= 1,
            8 => current.requester.as_mut().unwrap().endpoint += 1,
            9 => current.presenter.as_mut().unwrap().registration += 1,
            10 => current.presenter.as_mut().unwrap().instance.revision += 1,
            11 => current.presenter.as_mut().unwrap().instance.digest[0] ^= 1,
            12 => current.input.as_mut().unwrap().generation += 1,
            13 => current.input.as_mut().unwrap().seat += 1,
            14 => current.input.as_mut().unwrap().source.revision += 1,
            15 => current.input.as_mut().unwrap().source.digest[0] ^= 1,
            16 => current.session.as_mut().unwrap().id += 1,
            17 => current.session.as_mut().unwrap().generation += 1,
            18 => current.foreground = false,
            19 => current.policy_generation += 1,
            20 => current.policy_generation = 0,
            _ => unreachable!(),
        }
        assert_eq!(
            f.controller.feedback(
                f.presenter.instance,
                f.offer.correlation,
                Feedback::Decision {
                    choice: Choice::AllowOnce,
                    gesture: 21
                },
                current,
                100
            ),
            Err(Error::Changed),
            "mutation {mutation}"
        );
        assert_eq!(f.controller.len(), 0);
        assert_eq!(f.allow(21), Err(Error::Unknown));
    }
}

#[test]
fn each_authenticated_participant_can_cancel_without_creating_an_approval() {
    for role in 0..3 {
        let mut f = Fixture::new();
        let peer = match role {
            0 => f.binding.requester,
            1 => f.presenter.instance,
            _ => f.input.source,
        };
        assert_eq!(
            f.controller.cancel(peer, f.offer.correlation),
            Ok(f.binding)
        );
        assert_eq!(f.controller.len(), 0);
        assert_eq!(f.allow(21), Err(Error::Unknown));
    }
}

#[test]
fn pending_questions_are_bounded_and_one_presenter_cannot_overlap_questions() {
    let mut f = Fixture::new();
    assert!(matches!(
        f.controller.begin(
            f.binding,
            f.presenter,
            f.input,
            f.offer.choices,
            100,
            100,
            [5; 32]
        ),
        Err(Error::Busy)
    ));
    for index in 1..MAX_PENDING {
        f.controller
            .begin(
                f.binding,
                Presenter {
                    instance: instance(1000 + index as u64),
                    registration: 1,
                },
                f.input,
                f.offer.choices,
                100,
                100,
                [index as u8; 32],
            )
            .unwrap();
    }
    assert_eq!(f.controller.len(), MAX_PENDING);
    assert!(matches!(
        f.controller.begin(
            f.binding,
            Presenter {
                instance: instance(9999),
                registration: 1
            },
            f.input,
            f.offer.choices,
            100,
            100,
            [0xff; 32]
        ),
        Err(Error::Full)
    ));
    let mut expired = 0;
    f.controller.expire(200, |_, _| expired += 1).unwrap();
    assert_eq!(expired, MAX_PENDING);
    assert_eq!(f.controller.len(), 0);
}

#[test]
fn old_correlations_never_reappear_after_cancellation_or_slot_reuse() {
    let mut f = Fixture::new();
    let old = f.offer.correlation;
    for _ in 0..1000 {
        f.controller
            .cancel(f.binding.requester, f.offer.correlation)
            .unwrap();
        let next = f
            .controller
            .begin(
                f.binding,
                f.presenter,
                f.input,
                f.offer.choices,
                100,
                100,
                [0x98; 32],
            )
            .unwrap();
        assert!(next.correlation.ticket.id > f.offer.correlation.ticket.id);
        f.offer = next;
    }
    assert_eq!(
        f.controller.cancel(f.presenter.instance, old),
        Err(Error::Unknown)
    );
}

#[test]
fn deadline_overflow_zero_entropy_and_clock_rollback_never_relax_a_bound() {
    let mut f = Fixture::new();
    let other = Presenter {
        instance: instance(9),
        registration: 1,
    };
    for timeout in [0, MAX_TIMEOUT_NS + 1] {
        assert!(matches!(
            f.controller.begin(
                f.binding,
                other,
                f.input,
                f.offer.choices,
                100,
                timeout,
                [1; 32]
            ),
            Err(Error::Invalid)
        ));
    }
    assert!(matches!(
        f.controller
            .begin(f.binding, other, f.input, f.offer.choices, 100, 50, [0; 32]),
        Err(Error::Invalid)
    ));
    assert!(matches!(
        f.controller.begin(
            f.binding,
            other,
            f.input,
            f.offer.choices,
            u64::MAX,
            1,
            [1; 32]
        ),
        Err(Error::Exhausted)
    ));
    let mut f = Fixture::new();
    f.ready();
    assert_eq!(
        f.controller
            .expire(99, |_, _| panic!("rollback cannot expire")),
        Err(Error::ClockWentBack)
    );
    assert!(matches!(f.allow(21), Ok(Outcome::Approved(_))));
}

#[test]
fn input_serial_exhaustion_cannot_wrap_to_a_fresh_gesture() {
    let mut f = Fixture::new();
    f.feedback(Feedback::Presented).unwrap();
    f.controller
        .arm(
            f.input.source,
            f.offer.correlation,
            f.input,
            u64::MAX,
            true,
            100,
        )
        .unwrap();
    for serial in [0, 1, u64::MAX] {
        assert_eq!(
            f.event(serial, Transition::PhysicalPress),
            Err(Error::StaleInput)
        );
        assert_eq!(f.allow(serial), Err(Error::MissingPresence));
    }
}

#[test]
fn renderer_and_input_authority_cannot_be_the_same_process() {
    let mut f = Fixture::new();
    for input in [
        InputRoute {
            source: f.presenter.instance,
            ..f.input
        },
        InputRoute {
            source: Instance {
                thread: 999,
                endpoint: 888,
                ..f.presenter.instance
            },
            ..f.input
        },
    ] {
        assert!(matches!(
            f.controller.begin(
                f.binding,
                f.presenter,
                input,
                f.offer.choices,
                100,
                100,
                [0xab; 32]
            ),
            Err(Error::Invalid)
        ));
    }
}

#[test]
fn distinct_presenters_have_independent_requests_and_input_evidence() {
    let mut f = Fixture::new();
    let other = Presenter {
        instance: instance(9),
        registration: 10,
    };
    let other_binding = Binding {
        requester: instance(8),
        requirements_digest: [0xef; 32],
        ..f.binding
    };
    let offer = f
        .controller
        .begin(
            other_binding,
            other,
            f.input,
            f.offer.choices,
            100,
            100,
            [0xab; 32],
        )
        .unwrap();
    f.ready();
    let current = Current {
        requester: Some(other_binding.requester),
        presenter: Some(other),
        ..f.current()
    };
    f.controller
        .feedback(
            other.instance,
            offer.correlation,
            Feedback::Presented,
            current,
            100,
        )
        .unwrap();
    f.controller
        .arm(f.input.source, offer.correlation, f.input, 20, true, 100)
        .unwrap();
    assert_eq!(
        f.controller.feedback(
            other.instance,
            offer.correlation,
            Feedback::Decision {
                choice: Choice::AllowOnce,
                gesture: 21
            },
            current,
            100
        ),
        Err(Error::MissingPresence)
    );
    assert!(matches!(f.allow(21), Ok(Outcome::Approved(_))));
    f.controller
        .input(
            f.input.source,
            offer.correlation,
            f.input,
            22,
            Transition::PhysicalPress,
            100,
        )
        .unwrap();
    let Outcome::Approved(approval) = f
        .controller
        .feedback(
            other.instance,
            offer.correlation,
            Feedback::Decision {
                choice: Choice::AllowOnce,
                gesture: 22,
            },
            current,
            100,
        )
        .unwrap()
    else {
        panic!("approval required")
    };
    assert_eq!(approval.into_parts(), (other_binding, Choice::AllowOnce));
    assert_eq!(f.controller.len(), 0);
}

#[test]
fn owner_can_wait_for_the_earliest_deadline_without_blocking_a_presenter_call() {
    let mut f = Fixture::new();
    assert_eq!(f.controller.next_deadline(), Some(200));
    let early = f
        .controller
        .begin(
            f.binding,
            Presenter {
                instance: instance(99),
                registration: 1,
            },
            f.input,
            f.offer.choices,
            100,
            25,
            [0xee; 32],
        )
        .unwrap();
    assert_eq!(f.controller.next_deadline(), Some(125));
    let mut expired = vec![];
    f.controller
        .expire(125, |ticket, _| expired.push(ticket))
        .unwrap();
    assert_eq!(expired, [early.correlation.ticket]);
    assert_eq!(f.controller.next_deadline(), Some(200));
    f.controller
        .cancel(f.presenter.instance, f.offer.correlation)
        .unwrap();
    assert_eq!(f.controller.next_deadline(), None);
}

#[test]
fn ticket_counter_exhaustion_never_wraps_or_reuses_a_ticket() {
    #[allow(dead_code)]
    #[path = "support/native_error_probe.rs"]
    mod probe;
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap();
    let mut program = format!(
        r#"
extern crate self as mochi_user_platform;
#[path={:?}]pub mod wire;
pub mod capability{{pub use crate::wire as consent;}}
"#,
        root.join("user/crates/capability-protocol/src/consent.rs")
    );
    for line in include_str!("../../capability/src/consent.rs").lines() {
        if !line.starts_with("//!") {
            program.push_str(line);
            program.push('\n');
        }
    }
    program.push_str(r#"
fn main(){
 let instance=Instance{endpoint:1,process:2,thread:3,revision:0,digest:[1;32]};
 let binding=Binding{requester:instance,session:Session{id:1,generation:1},policy_generation:1,source_digest:[2;32],prepared_digest:[3;32],requirements_digest:[4;32],action:Action::Launch};
 let presenter=Presenter{instance,registration:1};let input=InputRoute{source:Instance{endpoint:4,process:5,thread:6,..instance},seat:0,generation:1};
 let choices=Choices::new(Choices::ONCE).unwrap();
 let mut controller=Controller::new();controller.next_id=Some(u64::MAX);
 let last=controller.begin(binding,presenter,input,choices,1,1,[1;32]).unwrap();
 assert_eq!(last.correlation.ticket.id,u64::MAX);assert_eq!(last.correlation.display,u64::MAX);
 controller.cancel(instance,last.correlation).unwrap();
 assert!(matches!(controller.begin(binding,presenter,input,choices,1,1,[2;32]),Err(Error::Exhausted)));
 assert_eq!(controller.len(),0);assert_eq!(controller.cancel(instance,last.correlation),Err(Error::Unknown));
}
"#);
    probe::run(&program);
}

#[test]
fn requester_death_and_policy_changes_cancel_without_waiting_for_a_response() {
    let mut f = Fixture::new();
    let offer = f.offer;
    let current = f.current();
    let mut cancelled = vec![];
    f.controller
        .observe(|_, _, _| current, |_, _| panic!("live context cancelled"));
    assert_eq!(f.controller.len(), 1);
    f.controller.observe(
        |_, _, _| Current {
            requester: None,
            ..current
        },
        |ticket, binding| cancelled.push((ticket, binding)),
    );
    assert_eq!(cancelled, [(offer.correlation.ticket, f.binding)]);
    assert_eq!(f.controller.next_deadline(), None);
    assert_eq!(f.allow(21), Err(Error::Unknown));
    let mut f = Fixture::new();
    let current = f.current();
    let mut cancelled = 0;
    f.controller.observe(
        |_, _, _| Current {
            policy_generation: 2,
            ..current
        },
        |_, _| cancelled += 1,
    );
    assert_eq!(cancelled, 1);
    assert_eq!(f.controller.len(), 0);
    f.controller.observe(
        |_, _, _| panic!("removed context sampled"),
        |_, _| panic!("duplicate cancellation"),
    );
}
