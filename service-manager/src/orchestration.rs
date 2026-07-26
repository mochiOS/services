use crate::service_config::FixedService;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct ChildProcesses {
    pub(crate) drivers: Option<u64>,
    pub(crate) input: Option<u64>,
    pub(crate) display: Option<u64>,
    pub(crate) compositor: Option<u64>,
    pub(crate) network: Option<u64>,
    pub(crate) tty: Option<u64>,
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
    TtySpawnFailed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct BootstrapOutcome {
    pub(crate) children: ChildProcesses,
    pub(crate) reason: StopReason,
}

impl BootstrapOutcome {
    pub(crate) const fn initialization_failed() -> Self {
        Self {
            children: ChildProcesses {
                drivers: None,
                input: None,
                display: None,
                compositor: None,
                network: None,
                tty: None,
            },
            reason: StopReason::DriverControlInitializationFailed,
        }
    }
}

pub(crate) trait BootstrapOperations {
    fn spawn_drivers(&mut self) -> Option<u64>;
    fn register_driver_delegate(&mut self, process_id: u64) -> bool;
    fn wait_driver_hello(&mut self, process_id: u64) -> bool;
    fn spawn_fixed(&mut self, service: FixedService) -> Option<u64>;
    fn wait_display_ready(&mut self, process_id: u64) -> bool;
    fn wait_input_ready(&mut self, process_id: u64) -> bool;
    fn start_discovery(&mut self) -> bool;
    fn wait_discovery_complete(&mut self, process_id: u64) -> bool;
    fn wait_network_ready(&mut self, process_id: u64) -> bool;
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
    if !operations.start_discovery() {
        return outcome(children, StopReason::StartDiscoveryFailed);
    }
    if !operations.wait_discovery_complete(drivers) {
        return outcome(children, StopReason::DiscoveryCompleteFailed);
    }

    children.network = operations.spawn_fixed(FixedService::Network);

    let Some(tty) = operations.spawn_fixed(FixedService::Tty) else {
        return outcome(children, StopReason::TtySpawnFailed);
    };
    children.tty = Some(tty);
    if let Some(network) = children.network {
        let _ = operations.wait_network_ready(network);
    }
    outcome(children, StopReason::Running)
}

const fn outcome(children: ChildProcesses, reason: StopReason) -> BootstrapOutcome {
    BootstrapOutcome { children, reason }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Event {
        SpawnDrivers,
        RegisterDriverDelegate,
        WaitHello,
        Spawn(FixedService),
        WaitDisplay,
        WaitInput,
        StartDiscovery,
        WaitDiscovery,
        WaitNetwork,
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

        fn spawn_fixed(&mut self, service: FixedService) -> Option<u64> {
            self.events.push(Event::Spawn(service));
            if self.failure == Failure::Spawn(service) {
                return None;
            }
            Some(match service {
                FixedService::Input => 11,
                FixedService::Display => 12,
                FixedService::Compositor => 13,
                FixedService::Network => 14,
                FixedService::Tty => 15,
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
            true
        }
    }

    fn expected_success_events() -> Vec<Event> {
        alloc::vec![
            Event::SpawnDrivers,
            Event::RegisterDriverDelegate,
            Event::WaitHello,
            Event::Spawn(FixedService::Input),
            Event::Spawn(FixedService::Display),
            Event::WaitDisplay,
            Event::WaitInput,
            Event::Spawn(FixedService::Compositor),
            Event::StartDiscovery,
            Event::WaitDiscovery,
            Event::Spawn(FixedService::Network),
            Event::Spawn(FixedService::Tty),
            Event::WaitNetwork,
        ]
    }

    #[test]
    fn successful_order_starts_drivers_first_and_waits_display_before_input() {
        let mut operations = FakeOperations::new(Failure::None);
        let outcome = orchestrate(&mut operations);
        assert_eq!(operations.events, expected_success_events());
        assert_eq!(outcome.reason, StopReason::Running);
        assert_eq!(outcome.children.drivers, Some(10));
        assert_eq!(outcome.children.input, Some(11));
        assert_eq!(outcome.children.display, Some(12));
        assert_eq!(outcome.children.compositor, Some(13));
        assert_eq!(outcome.children.network, Some(14));
        assert_eq!(outcome.children.tty, Some(15));
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
            assert!(!operations.events.contains(&Event::Spawn(FixedService::Tty)));
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
        assert!(operations.events.contains(&Event::Spawn(FixedService::Tty)));
    }

    #[test]
    fn driver_protocol_failure_prevents_tty_start() {
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
            assert!(!operations.events.contains(&Event::Spawn(FixedService::Tty)));
        }
    }

    #[test]
    fn tty_failure_enters_resident_outcome_without_tty_pid() {
        let mut operations = FakeOperations::new(Failure::Spawn(FixedService::Tty));
        let outcome = orchestrate(&mut operations);
        assert_eq!(outcome.reason, StopReason::TtySpawnFailed);
        assert_eq!(outcome.children.tty, None);
        assert_eq!(
            operations.events.last(),
            Some(&Event::Spawn(FixedService::Tty))
        );
    }
}
