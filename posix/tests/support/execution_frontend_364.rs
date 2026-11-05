//! Production handoff/controller/registry with observable authority transports.
use super::*;
use consent::*;
use execution_frontend::{Authority, Frontends, Witness};
use platform_real::capability::consent::{
    Choice, Correlation,
    frontend::{Action as Command, Kind},
};

fn renderer() -> consent_peer::Peer {
    consent_peer::Peer {
        instance: approvals::instance(2),
        process: consent_peer::ProcessReference(303),
    }
}
fn route() -> InputRoute {
    InputRoute {
        source: approvals::instance(3),
        seat: 0,
        generation: 8,
    }
}
struct NativeObservations {
    trusted: bool,
    alive: bool,
    member: bool,
    displayed: bool,
    synchronized: bool,
    session: Session,
    arm_serial: u64,
    arms: usize,
    dismissals: usize,
}
impl Default for NativeObservations {
    fn default() -> Self {
        Self {
            trusted: true,
            alive: true,
            member: true,
            displayed: true,
            synchronized: true,
            session: approvals::session(),
            arm_serial: 20,
            arms: 0,
            dismissals: 0,
        }
    }
}
fn error(error: NativeError) -> SysError {
    SysError::from(error.into_raw())
}
impl Authority for NativeObservations {
    fn presenter(&self, peer: &consent_peer::Peer, kind: Kind) -> Result<(), SysError> {
        if self.trusted && peer.instance == approvals::instance(2) && kind == Kind::Graphical {
            Ok(())
        } else {
            Err(error(NativeError::AccessDenied))
        }
    }
    fn requester_kind(&self, _: &consent_peer::Peer) -> Result<Kind, SysError> {
        Ok(Kind::Graphical)
    }
    fn current(&self, _: &consent_peer::Peer) -> Result<(), SysError> {
        if self.alive {
            Ok(())
        } else {
            Err(error(NativeError::PeerClosed))
        }
    }
    fn session(&self, _: &consent_peer::Peer) -> Result<Session, SysError> {
        if self.member {
            Ok(self.session)
        } else {
            Err(error(NativeError::AccessDenied))
        }
    }
    fn route(&self) -> Result<InputRoute, SysError> {
        Ok(route())
    }
    fn challenge(&self) -> Result<[u8; 32], SysError> {
        Ok([0x94; 32])
    }
    fn register(&self, _: &consent_peer::Peer, _: Correlation, _: Kind) -> Result<u64, SysError> {
        Ok(4)
    }
    fn observe(
        &self,
        requester: Instance,
        _: &consent_peer::Peer,
        presenter: Presenter,
        route: InputRoute,
        _: Correlation,
        policy: u64,
    ) -> Result<Witness, SysError> {
        if !self.displayed {
            return Err(error(NativeError::NotReady));
        }
        if !self.member {
            return Err(error(NativeError::AccessDenied));
        }
        Ok(Witness {
            requester: approvals::peer(202),
            current: Current {
                requester: Some(requester),
                presenter: Some(presenter),
                input: Some(route),
                session: Some(self.session),
                policy_generation: policy,
                foreground: true,
            },
        })
    }
    fn arm(&mut self, _: Correlation) -> Result<(u64, bool), SysError> {
        self.arms += 1;
        Ok((self.arm_serial, true))
    }
    fn synchronized(&self) -> Result<(), SysError> {
        if self.synchronized {
            Ok(())
        } else {
            Err(error(NativeError::NotReady))
        }
    }
    fn dismiss(&mut self, _: Correlation, _: u64) {
        self.dismissals += 1;
    }
    fn reply_error(&self, _: u64, _: SysError) {}
}
fn begin(
    frontends: &mut Frontends,
    registry: &mut execution_requests::Registry,
    controller: &mut Controller,
    authority: &mut NativeObservations,
) -> Offer {
    begin_at(frontends, registry, controller, authority, 100)
}
fn begin_at(
    frontends: &mut Frontends,
    registry: &mut execution_requests::Registry,
    controller: &mut Controller,
    authority: &mut NativeObservations,
    now: u64,
) -> Offer {
    let code = approvals::code();
    let selected = signed_image::select_snapshot(&empty_state(), None, &code).unwrap();
    assert!(selected.needs_consent(&policy::AppPromptPolicy::default()));
    let reservation = registry.reserve(77, code.len()).unwrap();
    let (offer, destination) = frontends
        .begin(
            reservation,
            controller,
            selected,
            code,
            approvals::peer(101),
            "opaque:approval",
            3,
            now,
            authority,
        )
        .unwrap();
    assert_eq!(destination, 2);
    offer
}
fn command(
    frontends: &mut Frontends,
    registry: &mut execution_requests::Registry,
    controller: &mut Controller,
    authority: &mut NativeObservations,
    offer: Offer,
    action: Command,
    generation: u64,
    replies: &mut Vec<execution_requests::Reply>,
) -> Result<(), SysError> {
    frontends.command(
        registry,
        controller,
        &renderer(),
        offer.correlation,
        action,
        generation,
        110,
        authority,
        |reply| replies.push(reply),
    )
}
fn initialized() -> (
    Frontends,
    execution_requests::Registry,
    Controller,
    NativeObservations,
) {
    setup(approvals::code());
    let mut frontends = Frontends::new();
    let authority = NativeObservations::default();
    frontends
        .wait(renderer(), Kind::Graphical, &authority)
        .unwrap();
    (
        frontends,
        execution_requests::Registry::new().unwrap(),
        Controller::new(),
        authority,
    )
}

#[test]
fn reused_renderer_needs_a_new_correlation_display_and_input_arm() {
    let (mut frontends, mut registry, mut controller, mut authority) = initialized();
    let first = begin(
        &mut frontends,
        &mut registry,
        &mut controller,
        &mut authority,
    );
    let mut replies = Vec::new();
    command(
        &mut frontends,
        &mut registry,
        &mut controller,
        &mut authority,
        first,
        Command::Decide(Choice::Deny),
        3,
        &mut replies,
    )
    .unwrap();
    assert_eq!(registry.len(), 0);
    assert_eq!(replies.len(), 1);
    assert!(replies[0].result.is_err());
    frontends
        .wait(renderer(), Kind::Graphical, &authority)
        .unwrap();
    let next = begin_at(
        &mut frontends,
        &mut registry,
        &mut controller,
        &mut authority,
        120,
    );
    assert_ne!(first.correlation, next.correlation);
    let mut send = |correlation, action| {
        frontends.command(
            &mut registry,
            &mut controller,
            &renderer(),
            correlation,
            action,
            3,
            130,
            &mut authority,
            |reply| replies.push(reply),
        )
    };
    assert!(send(first.correlation, Command::Decide(Choice::AllowOnce)).is_err());
    assert_eq!(
        send(next.correlation, Command::Decide(Choice::AllowOnce))
            .unwrap_err()
            .native_error(),
        Some(NativeError::NotReady)
    );
    send(next.correlation, Command::Presented).unwrap();
    assert_eq!(
        send(next.correlation, Command::Decide(Choice::AllowOnce))
            .unwrap_err()
            .native_error(),
        Some(NativeError::NotReady)
    );
    send(next.correlation, Command::Dismissed).unwrap();
    assert_eq!(registry.len(), 0);
    assert_eq!(replies.len(), 2);
    assert!(replies.iter().all(|reply| reply.result.is_err()));
    assert_eq!(authority.arms, 1);
}

#[test]
fn unavailable_presenter_is_retryable_and_rolls_back_the_source_reservation() {
    let (mut frontends, mut registry, mut controller, mut authority) = initialized();
    let _offer = begin(
        &mut frontends,
        &mut registry,
        &mut controller,
        &mut authority,
    );
    // The presenter is handling a request instead of waiting. A following
    // launch must wait for availability instead of reporting ENOMEM to libc.
    let code = approvals::code();
    let selected = signed_image::select_snapshot(&empty_state(), None, &code).unwrap();
    let reservation = registry.reserve(88, code.len()).unwrap();
    let failure = frontends
        .begin(
            reservation,
            &mut controller,
            selected,
            code,
            approvals::peer(404),
            "next-image",
            3,
            110,
            &mut authority,
        )
        .unwrap_err();
    assert_eq!(failure.native_error(), Some(NativeError::NotReady));
    assert_eq!(
        mochios_posix_protocol::status::normalize_failure(failure.raw()),
        mochios_posix_protocol::STATUS_EAGAIN
    );
    assert_eq!(registry.len(), 1);

    let mut frontends = Frontends::new();
    let code = approvals::code();
    let selected = signed_image::select_snapshot(&empty_state(), None, &code).unwrap();
    let reservation = registry.reserve(88, code.len()).unwrap();
    let failure = frontends
        .begin(
            reservation,
            &mut controller,
            selected,
            code,
            approvals::peer(404),
            "next-image",
            3,
            110,
            &mut authority,
        )
        .unwrap_err();
    assert_eq!(failure.native_error(), Some(NativeError::NotReady));
    assert_eq!(registry.len(), 1);
}

#[test]
fn retained_waiter_gets_exact_source_and_only_physical_input_can_complete_it() {
    let (mut frontends, mut registry, mut controller, mut authority) = initialized();
    let offer = begin(
        &mut frontends,
        &mut registry,
        &mut controller,
        &mut authority,
    );
    let mut payload = [0; platform_real::capability::consent::prompt::MAX_MESSAGE_BYTES];
    let n = registry
        .write_prompt(
            offer.correlation,
            frontends.presenter_instance(offer.correlation).unwrap(),
            101,
            &mut payload,
        )
        .unwrap();
    let prompt = platform_real::capability::consent::prompt::decode(&payload[..n]).unwrap();
    assert_eq!(prompt.capabilities().collect::<Vec<_>>(), ["net.connect"]);
    let mut replies = Vec::new();
    assert!(
        command(
            &mut frontends,
            &mut registry,
            &mut controller,
            &mut authority,
            offer,
            Command::Decide(Choice::AllowOnce),
            3,
            &mut replies
        )
        .is_err()
    );
    assert!(replies.is_empty());
    assert_eq!(authority.arms, 0);
    command(
        &mut frontends,
        &mut registry,
        &mut controller,
        &mut authority,
        offer,
        Command::Presented,
        3,
        &mut replies,
    )
    .unwrap();
    for transition in [
        Transition::Synthetic,
        Transition::Repeat,
        Transition::Release,
    ] {
        let serial = authority.arm_serial + 1;
        authority.arm_serial = serial;
        controller
            .input(
                route().source,
                offer.correlation,
                route(),
                serial,
                transition,
                110,
            )
            .unwrap();
        assert!(
            command(
                &mut frontends,
                &mut registry,
                &mut controller,
                &mut authority,
                offer,
                Command::Decide(Choice::AllowOnce),
                3,
                &mut replies
            )
            .is_err()
        );
        STATE.with_borrow(|state| assert_eq!(state.issue_calls, 0));
    }
    controller
        .input(
            route().source,
            offer.correlation,
            route(),
            24,
            Transition::AllReleased,
            110,
        )
        .unwrap();
    controller
        .input(
            route().source,
            offer.correlation,
            route(),
            25,
            Transition::PhysicalPress,
            110,
        )
        .unwrap();
    command(
        &mut frontends,
        &mut registry,
        &mut controller,
        &mut authority,
        offer,
        Command::Decide(Choice::AllowOnce),
        3,
        &mut replies,
    )
    .unwrap();
    assert_eq!(replies.len(), 1);
    assert_eq!(replies[0].target, 77);
    assert_eq!(replies[0].result, Ok(()));
    assert_eq!(
        (registry.len(), registry.bytes(), controller.len()),
        (0, 0, 0)
    );
    assert_eq!(authority.dismissals, 1);
    STATE.with_borrow(|state| {
        assert_eq!(state.issue_calls, 1);
        assert_eq!(state.issued_caps, [b"net.connect\0".to_vec()]);
    });
    assert!(
        command(
            &mut frontends,
            &mut registry,
            &mut controller,
            &mut authority,
            offer,
            Command::Decide(Choice::AllowOnce),
            3,
            &mut replies
        )
        .is_err()
    );
    assert_eq!(replies.len(), 1);
}

#[test]
fn queued_or_unpresented_frame_never_arms_the_input_route() {
    let (mut frontends, mut registry, mut controller, mut authority) = initialized();
    authority.displayed = false;
    let offer = begin(
        &mut frontends,
        &mut registry,
        &mut controller,
        &mut authority,
    );
    let mut replies = Vec::new();
    assert!(
        command(
            &mut frontends,
            &mut registry,
            &mut controller,
            &mut authority,
            offer,
            Command::Presented,
            3,
            &mut replies
        )
        .is_err()
    );
    assert_eq!((authority.arms, registry.len()), (0, 1));
    assert!(replies.is_empty());
    authority.displayed = true;
    command(
        &mut frontends,
        &mut registry,
        &mut controller,
        &mut authority,
        offer,
        Command::Presented,
        3,
        &mut replies,
    )
    .unwrap();
    assert_eq!(authority.arms, 1);
}

#[test]
fn denial_and_window_dismissal_need_no_positive_witness_and_reply_once() {
    for action in [Command::Decide(Choice::Deny), Command::Dismissed] {
        let (mut frontends, mut registry, mut controller, mut authority) = initialized();
        let offer = begin(
            &mut frontends,
            &mut registry,
            &mut controller,
            &mut authority,
        );
        let mut replies = Vec::new();
        command(
            &mut frontends,
            &mut registry,
            &mut controller,
            &mut authority,
            offer,
            action,
            3,
            &mut replies,
        )
        .unwrap();
        assert_eq!(replies.len(), 1);
        assert!(replies[0].result.is_err());
        assert_eq!(
            (registry.len(), registry.bytes(), controller.len()),
            (0, 0, 0)
        );
        STATE.with_borrow(|state| assert_eq!(state.issue_calls, 0));
    }
}

#[test]
fn changed_session_policy_or_missing_membership_cannot_issue_a_permit() {
    for case in 0..3 {
        let (mut frontends, mut registry, mut controller, mut authority) = initialized();
        let offer = begin(
            &mut frontends,
            &mut registry,
            &mut controller,
            &mut authority,
        );
        let mut replies = Vec::new();
        command(
            &mut frontends,
            &mut registry,
            &mut controller,
            &mut authority,
            offer,
            Command::Presented,
            3,
            &mut replies,
        )
        .unwrap();
        controller
            .input(
                route().source,
                offer.correlation,
                route(),
                21,
                Transition::PhysicalPress,
                110,
            )
            .unwrap();
        if case == 0 {
            authority.session.generation += 1;
        }
        if case == 1 {
            authority.member = false;
        }
        assert!(
            command(
                &mut frontends,
                &mut registry,
                &mut controller,
                &mut authority,
                offer,
                Command::Decide(Choice::AllowOnce),
                if case == 2 { 4 } else { 3 },
                &mut replies
            )
            .is_err()
        );
        assert_eq!(replies.len(), 1);
        assert!(replies[0].result.is_err());
        assert_eq!(registry.len(), 0);
        STATE.with_borrow(|state| assert_eq!(state.issue_calls, 0));
    }
}

#[test]
fn forged_peer_cannot_cancel_or_complete_another_presenters_question() {
    let (mut frontends, mut registry, mut controller, mut authority) = initialized();
    let offer = begin(
        &mut frontends,
        &mut registry,
        &mut controller,
        &mut authority,
    );
    let mut forged = renderer();
    forged.instance.revision += 1;
    assert!(
        frontends
            .command(
                &mut registry,
                &mut controller,
                &forged,
                offer.correlation,
                Command::Dismissed,
                3,
                110,
                &mut authority,
                |_| panic!()
            )
            .is_err()
    );
    assert_eq!(registry.len(), 1);
    assert_eq!(authority.dismissals, 0);
    STATE.with_borrow(|state| assert_eq!(state.issue_calls, 0));
}

#[test]
fn authority_events_must_catch_up_before_consuming_a_valid_press() {
    let (mut frontends, mut registry, mut controller, mut authority) = initialized();
    let offer = begin(
        &mut frontends,
        &mut registry,
        &mut controller,
        &mut authority,
    );
    let mut replies = Vec::new();
    command(
        &mut frontends,
        &mut registry,
        &mut controller,
        &mut authority,
        offer,
        Command::Presented,
        3,
        &mut replies,
    )
    .unwrap();
    controller
        .input(
            route().source,
            offer.correlation,
            route(),
            21,
            Transition::PhysicalPress,
            110,
        )
        .unwrap();
    authority.synchronized = false;
    assert!(
        command(
            &mut frontends,
            &mut registry,
            &mut controller,
            &mut authority,
            offer,
            Command::Decide(Choice::AllowOnce),
            3,
            &mut replies
        )
        .is_err()
    );
    assert_eq!(registry.len(), 1);
    assert!(replies.is_empty());
    authority.synchronized = true;
    command(
        &mut frontends,
        &mut registry,
        &mut controller,
        &mut authority,
        offer,
        Command::Decide(Choice::AllowOnce),
        3,
        &mut replies,
    )
    .unwrap();
    assert_eq!(replies.len(), 1);
}

#[test]
fn failed_admission_rolls_back_the_byte_budget_and_keeps_the_idle_waiter() {
    let (mut frontends, mut registry, mut controller, mut authority) = initialized();
    authority.member = false;
    let code = approvals::code();
    let selection = signed_image::select_snapshot(&empty_state(), None, &code).unwrap();
    let reservation = registry.reserve(77, code.len()).unwrap();
    assert!(
        frontends
            .begin(
                reservation,
                &mut controller,
                selection,
                code,
                approvals::peer(101),
                "key",
                3,
                100,
                &mut authority
            )
            .is_err()
    );
    assert_eq!((registry.len(), registry.bytes()), (0, 0));
    authority.member = true;
    begin(
        &mut frontends,
        &mut registry,
        &mut controller,
        &mut authority,
    );
}

#[test]
fn dead_presenter_cancels_the_source_and_wait_plan_keeps_native_refs() {
    let (mut frontends, mut registry, mut controller, mut authority) = initialized();
    let mut watched = Vec::new();
    frontends.process_handles(|handle| watched.push(handle));
    assert_eq!(watched, [303]);
    begin(
        &mut frontends,
        &mut registry,
        &mut controller,
        &mut authority,
    );
    authority.alive = false;
    let mut replies = Vec::new();
    frontends.maintain(&mut registry, &mut controller, &mut authority, |reply| {
        replies.push(reply)
    });
    assert_eq!(replies.len(), 1);
    assert_eq!((registry.len(), registry.bytes()), (0, 0));
    let mut watched = Vec::new();
    frontends.process_handles(|handle| watched.push(handle));
    assert!(watched.is_empty());
}
