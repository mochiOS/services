use crate::service_config::FixedService;
use mochi_user_platform::service_ready::SessionIdentity;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct ChildProcesses {
    pub(crate) drivers: Option<u64>,
    pub(crate) mboot_agent: Option<u64>,
    pub(crate) input: Option<u64>,
    pub(crate) display: Option<u64>,
    pub(crate) compositor: Option<u64>,
    pub(crate) network: Option<u64>,
    pub(crate) user: Option<u64>,
    pub(crate) secure_ui: Option<u64>,
    pub(crate) linux: Option<u64>,
    pub(crate) binder: Option<u64>,
    pub(crate) update: Option<u64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum StopReason {
    Running,
    DriverControlInitializationFailed,
    DriversSpawnFailed,
    DriverDelegateRegistrationFailed,
    DriverHelloFailed,
    InputSpawnFailed,
    DisplaySpawnFailed,
    DisplayReadyFailed,
    InputReadyFailed,
    StartDiscoveryFailed,
    DiscoveryCompleteFailed,
    UserSpawnFailed,
    UserReadyFailed,
    SecureUiSpawnFailed,
    SecureUiLoginFailed,
    BinderSpawnFailed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct BootstrapOutcome {
    pub(crate) children: ChildProcesses,
    pub(crate) reason: StopReason,
    pub(crate) identity: Option<SessionIdentity>,
    pub(crate) session_id: u64,
}

impl BootstrapOutcome {
    pub(crate) const fn initialization_failed() -> Self {
        Self {
            children: ChildProcesses {
                drivers: None,
                mboot_agent: None,
                input: None,
                display: None,
                compositor: None,
                network: None,
                user: None,
                secure_ui: None,
                linux: None,
                binder: None,
                update: None,
            },
            reason: StopReason::DriverControlInitializationFailed,
            identity: None,
            session_id: 0,
        }
    }
}

pub(crate) trait BootstrapOperations {
    fn spawn_drivers(&mut self) -> Option<u64>;
    fn register_driver_delegate(&mut self, process_id: u64) -> bool;
    fn wait_driver_hello(&mut self, process_id: u64) -> bool;
    fn spawn_mboot_agent(&mut self) -> Option<u64>;
    fn notify_mboot_stage(&mut self, stage: MbootStage);
    fn spawn_fixed(&mut self, service: FixedService) -> Option<u64>;
    fn spawn_user_session(
        &mut self,
        service: FixedService,
        identity: SessionIdentity,
        session_id: u64,
    ) -> Option<u64>;
    fn wait_display_ready(&mut self, process_id: u64) -> bool;
    fn wait_input_ready(&mut self, process_id: u64) -> bool;
    fn start_discovery(&mut self) -> bool;
    fn wait_discovery_complete(&mut self, process_id: u64) -> bool;
    fn wait_network_ready(&mut self, process_id: u64) -> bool;
    fn wait_user_ready(&mut self, process_id: u64) -> bool;
    fn wait_secure_ui_login(&mut self, process_id: u64) -> Option<SessionIdentity>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum MbootStage {
    Userspace = 1,
    Display = 2,
    Desktop = 3,
}

pub(crate) fn orchestrate(operations: &mut impl BootstrapOperations) -> BootstrapOutcome {
    let mut children = ChildProcesses::default();

    let Some(drivers) = operations.spawn_drivers() else {
        return outcome(children, StopReason::DriversSpawnFailed);
    };
    children.drivers = Some(drivers);
    if !operations.register_driver_delegate(drivers) {
        return outcome(children, StopReason::DriverDelegateRegistrationFailed);
    }
    if !operations.wait_driver_hello(drivers) {
        return outcome(children, StopReason::DriverHelloFailed);
    }
    children.mboot_agent = operations.spawn_mboot_agent();
    operations.notify_mboot_stage(MbootStage::Userspace);

    let Some(input) = operations.spawn_fixed(FixedService::Input) else {
        return outcome(children, StopReason::InputSpawnFailed);
    };
    children.input = Some(input);
    let Some(display) = operations.spawn_fixed(FixedService::Display) else {
        return outcome(children, StopReason::DisplaySpawnFailed);
    };
    children.display = Some(display);

    if !operations.wait_display_ready(display) {
        return outcome(children, StopReason::DisplayReadyFailed);
    }
    if !operations.wait_input_ready(input) {
        return outcome(children, StopReason::InputReadyFailed);
    }

    children.compositor = operations.spawn_fixed(FixedService::Compositor);
    if children.compositor.is_some() {
        operations.notify_mboot_stage(MbootStage::Display);
    }
    if !operations.start_discovery() {
        return outcome(children, StopReason::StartDiscoveryFailed);
    }
    if !operations.wait_discovery_complete(drivers) {
        return outcome(children, StopReason::DiscoveryCompleteFailed);
    }

    children.network = operations.spawn_fixed(FixedService::Network);
    let Some(user) = operations.spawn_fixed(FixedService::User) else {
        return outcome(children, StopReason::UserSpawnFailed);
    };
    children.user = Some(user);
    if !operations.wait_user_ready(user) {
        return outcome(children, StopReason::UserReadyFailed);
    }

    let Some(secure_ui) = operations.spawn_fixed(FixedService::SecureUi) else {
        return outcome(children, StopReason::SecureUiSpawnFailed);
    };
    children.secure_ui = Some(secure_ui);
    let Some(identity) = operations.wait_secure_ui_login(secure_ui) else {
        return outcome(children, StopReason::SecureUiLoginFailed);
    };

    let session_id = 1;
    children.linux = operations.spawn_user_session(FixedService::Linux, identity, session_id);
    let Some(binder) = operations.spawn_user_session(FixedService::Binder, identity, session_id)
    else {
        return outcome(children, StopReason::BinderSpawnFailed);
    };
    children.binder = Some(binder);
    operations.notify_mboot_stage(MbootStage::Desktop);
    if let Some(network) = children.network
        && operations.wait_network_ready(network)
    {
        children.update = operations.spawn_fixed(FixedService::Update);
    }
    BootstrapOutcome {
        children,
        reason: StopReason::Running,
        identity: Some(identity),
        session_id,
    }
}

const fn outcome(children: ChildProcesses, reason: StopReason) -> BootstrapOutcome {
    BootstrapOutcome {
        children,
        reason,
        identity: None,
        session_id: 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    const TEST_IDENTITY: SessionIdentity = SessionIdentity { uid: 1000, gid: 20 };

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Event {
        SpawnDrivers,
        RegisterDriverDelegate,
        WaitHello,
        SpawnMbootAgent,
        NotifyMbootStage(MbootStage),
        Spawn(FixedService),
        SpawnUserSession(FixedService, SessionIdentity),
        WaitDisplay,
        WaitInput,
        StartDiscovery,
        WaitDiscovery,
        WaitNetwork,
        WaitUser,
        WaitSecureUiLogin,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Failure {
        None,
        SpawnDrivers,
        RegisterDriverDelegate,
        Hello,
        Spawn(FixedService),
        DisplayReady,
        InputReady,
        StartDiscovery,
        DiscoveryComplete,
        NetworkReady,
        UserReady,
        SecureUiLogin,
    }

    struct FakeOperations {
        events: Vec<Event>,
        failure: Failure,
    }

    impl FakeOperations {
        fn new(failure: Failure) -> Self {
            Self {
                events: Vec::new(),
                failure,
            }
        }
    }

    impl BootstrapOperations for FakeOperations {
        fn spawn_drivers(&mut self) -> Option<u64> {
            self.events.push(Event::SpawnDrivers);
            (self.failure != Failure::SpawnDrivers).then_some(10)
        }

        fn register_driver_delegate(&mut self, _process_id: u64) -> bool {
            self.events.push(Event::RegisterDriverDelegate);
            self.failure != Failure::RegisterDriverDelegate
        }

        fn wait_driver_hello(&mut self, _process_id: u64) -> bool {
            self.events.push(Event::WaitHello);
            self.failure != Failure::Hello
        }

        fn spawn_mboot_agent(&mut self) -> Option<u64> {
            self.events.push(Event::SpawnMbootAgent);
            Some(11)
        }

        fn notify_mboot_stage(&mut self, stage: MbootStage) {
            self.events.push(Event::NotifyMbootStage(stage));
        }

        fn spawn_fixed(&mut self, service: FixedService) -> Option<u64> {
            self.events.push(Event::Spawn(service));
            if self.failure == Failure::Spawn(service) {
                return None;
            }
            Some(match service {
                FixedService::MbootAgent => 19,
                FixedService::Input => 11,
                FixedService::Display => 12,
                FixedService::Compositor => 13,
                FixedService::Network => 14,
                FixedService::User => 15,
                FixedService::SecureUi => 16,
                FixedService::Linux => 20,
                FixedService::Binder => 17,
                FixedService::Update => 18,
            })
        }

        fn spawn_user_session(
            &mut self,
            service: FixedService,
            identity: SessionIdentity,
            _session_id: u64,
        ) -> Option<u64> {
            self.events.push(Event::SpawnUserSession(service, identity));
            (self.failure != Failure::Spawn(service)).then_some(match service {
                FixedService::Linux => 20,
                FixedService::Binder => 17,
                _ => unreachable!("only user-session services are accepted"),
            })
        }

        fn wait_display_ready(&mut self, _process_id: u64) -> bool {
            self.events.push(Event::WaitDisplay);
            self.failure != Failure::DisplayReady
        }

        fn wait_input_ready(&mut self, _process_id: u64) -> bool {
            self.events.push(Event::WaitInput);
            self.failure != Failure::InputReady
        }

        fn start_discovery(&mut self) -> bool {
            self.events.push(Event::StartDiscovery);
            self.failure != Failure::StartDiscovery
        }

        fn wait_discovery_complete(&mut self, _process_id: u64) -> bool {
            self.events.push(Event::WaitDiscovery);
            self.failure != Failure::DiscoveryComplete
        }

        fn wait_network_ready(&mut self, _process_id: u64) -> bool {
            self.events.push(Event::WaitNetwork);
            self.failure != Failure::NetworkReady
        }

        fn wait_user_ready(&mut self, _process_id: u64) -> bool {
            self.events.push(Event::WaitUser);
            self.failure != Failure::UserReady
        }

        fn wait_secure_ui_login(&mut self, _process_id: u64) -> Option<SessionIdentity> {
            self.events.push(Event::WaitSecureUiLogin);
            (self.failure != Failure::SecureUiLogin).then_some(TEST_IDENTITY)
        }
    }

    fn expected_success_events() -> Vec<Event> {
        alloc::vec![
            Event::SpawnDrivers,
            Event::RegisterDriverDelegate,
            Event::WaitHello,
            Event::SpawnMbootAgent,
            Event::NotifyMbootStage(MbootStage::Userspace),
            Event::Spawn(FixedService::Input),
            Event::Spawn(FixedService::Display),
            Event::WaitDisplay,
            Event::WaitInput,
            Event::Spawn(FixedService::Compositor),
            Event::NotifyMbootStage(MbootStage::Display),
            Event::StartDiscovery,
            Event::WaitDiscovery,
            Event::Spawn(FixedService::Network),
            Event::Spawn(FixedService::User),
            Event::WaitUser,
            Event::Spawn(FixedService::SecureUi),
            Event::WaitSecureUiLogin,
            Event::SpawnUserSession(FixedService::Linux, TEST_IDENTITY),
            Event::SpawnUserSession(FixedService::Binder, TEST_IDENTITY),
            Event::NotifyMbootStage(MbootStage::Desktop),
            Event::WaitNetwork,
            Event::Spawn(FixedService::Update),
        ]
    }

    #[test]
    fn successful_order_starts_drivers_first_and_waits_display_before_input() {
        let mut operations = FakeOperations::new(Failure::None);
        let outcome = orchestrate(&mut operations);
        assert_eq!(operations.events, expected_success_events());
        assert_eq!(outcome.reason, StopReason::Running);
        assert_eq!(outcome.children.drivers, Some(10));
        assert_eq!(outcome.children.mboot_agent, Some(11));
        assert_eq!(outcome.children.input, Some(11));
        assert_eq!(outcome.children.display, Some(12));
        assert_eq!(outcome.children.compositor, Some(13));
        assert_eq!(outcome.children.network, Some(14));
        assert_eq!(outcome.children.user, Some(15));
        assert_eq!(outcome.children.secure_ui, Some(16));
        assert_eq!(outcome.children.linux, Some(20));
        assert_eq!(outcome.children.binder, Some(17));
        assert_eq!(outcome.children.update, Some(18));
        assert_eq!(outcome.identity, Some(TEST_IDENTITY));
        assert_eq!(outcome.session_id, 1);
    }

    #[test]
    fn driver_input_and_display_failures_stop_following_services() {
        let cases = [
            (Failure::SpawnDrivers, StopReason::DriversSpawnFailed),
            (
                Failure::RegisterDriverDelegate,
                StopReason::DriverDelegateRegistrationFailed,
            ),
            (Failure::Hello, StopReason::DriverHelloFailed),
            (
                Failure::Spawn(FixedService::Input),
                StopReason::InputSpawnFailed,
            ),
            (
                Failure::Spawn(FixedService::Display),
                StopReason::DisplaySpawnFailed,
            ),
            (Failure::DisplayReady, StopReason::DisplayReadyFailed),
            (Failure::InputReady, StopReason::InputReadyFailed),
        ];
        for (failure, reason) in cases {
            let mut operations = FakeOperations::new(failure);
            let outcome = orchestrate(&mut operations);
            assert_eq!(outcome.reason, reason);
            assert!(!operations.events.contains(&Event::StartDiscovery));
            assert!(!operations.events.contains(&Event::SpawnUserSession(
                FixedService::Binder,
                TEST_IDENTITY
            )));
        }
    }

    #[test]
    fn compositor_failure_still_runs_driver_discovery() {
        let mut operations = FakeOperations::new(Failure::Spawn(FixedService::Compositor));
        let outcome = orchestrate(&mut operations);
        assert_eq!(outcome.reason, StopReason::Running);
        assert_eq!(outcome.children.compositor, None);
        assert!(operations.events.contains(&Event::StartDiscovery));
        assert!(operations.events.contains(&Event::WaitDiscovery));
        assert!(operations.events.contains(&Event::SpawnUserSession(
            FixedService::Binder,
            TEST_IDENTITY
        )));
    }

    #[test]
    fn user_and_login_failures_prevent_binder() {
        for (failure, reason) in [
            (
                Failure::Spawn(FixedService::User),
                StopReason::UserSpawnFailed,
            ),
            (Failure::UserReady, StopReason::UserReadyFailed),
            (
                Failure::Spawn(FixedService::SecureUi),
                StopReason::SecureUiSpawnFailed,
            ),
            (Failure::SecureUiLogin, StopReason::SecureUiLoginFailed),
        ] {
            let mut operations = FakeOperations::new(failure);
            let outcome = orchestrate(&mut operations);
            assert_eq!(outcome.reason, reason);
            assert_eq!(outcome.children.binder, None);
            assert!(!operations.events.contains(&Event::SpawnUserSession(
                FixedService::Binder,
                TEST_IDENTITY
            )));
        }
    }

    #[test]
    fn driver_protocol_failure_prevents_binder_start() {
        for (failure, reason) in [
            (Failure::StartDiscovery, StopReason::StartDiscoveryFailed),
            (
                Failure::DiscoveryComplete,
                StopReason::DiscoveryCompleteFailed,
            ),
        ] {
            let mut operations = FakeOperations::new(failure);
            let outcome = orchestrate(&mut operations);
            assert_eq!(outcome.reason, reason);
            assert!(!operations.events.contains(&Event::SpawnUserSession(
                FixedService::Binder,
                TEST_IDENTITY
            )));
        }
    }

    #[test]
    fn binder_failure_enters_resident_outcome_without_binder_pid() {
        let mut operations = FakeOperations::new(Failure::Spawn(FixedService::Binder));
        let outcome = orchestrate(&mut operations);
        assert_eq!(outcome.reason, StopReason::BinderSpawnFailed);
        assert_eq!(outcome.children.binder, None);
        assert_eq!(
            operations.events.last(),
            Some(&Event::SpawnUserSession(
                FixedService::Binder,
                TEST_IDENTITY
            ))
        );
    }

    #[test]
    fn linux_bridge_is_best_effort_and_does_not_prevent_binder() {
        let mut operations = FakeOperations::new(Failure::Spawn(FixedService::Linux));
        let outcome = orchestrate(&mut operations);
        assert_eq!(outcome.reason, StopReason::Running);
        assert_eq!(outcome.children.linux, None);
        assert_eq!(outcome.children.binder, Some(17));
    }

    #[test]
    fn update_is_best_effort_and_requires_network_ready() {
        let mut network_failure = FakeOperations::new(Failure::NetworkReady);
        let outcome = orchestrate(&mut network_failure);
        assert_eq!(outcome.reason, StopReason::Running);
        assert_eq!(outcome.children.update, None);
        assert!(
            !network_failure
                .events
                .contains(&Event::Spawn(FixedService::Update))
        );

        let mut update_failure = FakeOperations::new(Failure::Spawn(FixedService::Update));
        let outcome = orchestrate(&mut update_failure);
        assert_eq!(outcome.reason, StopReason::Running);
        assert_eq!(outcome.children.update, None);
        assert_eq!(
            update_failure.events.last(),
            Some(&Event::Spawn(FixedService::Update))
        );
    }
}
