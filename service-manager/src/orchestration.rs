use crate::service_config::FixedService;
use mochi_user_platform::service_ready::SessionIdentity;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ChildProcesses<
    Input = u64,
    Display = u64,
    Drivers = u64,
    Compositor = u64,
    Network = u64,
    User = u64,
    Update = u64,
    SecureUi = u64,
> {
    pub(crate) drivers: Option<Drivers>,
    pub(crate) mboot_agent: Option<u64>,
    pub(crate) filesystem: Option<u64>,
    pub(crate) posix: Option<u64>,
    pub(crate) input: Option<Input>,
    pub(crate) display: Option<Display>,
    pub(crate) compositor: Option<Compositor>,
    pub(crate) network: Option<Network>,
    pub(crate) user: Option<User>,
    pub(crate) secure_ui: Option<SecureUi>,
    pub(crate) linux: Option<u64>,
    pub(crate) binder: Option<u64>,
    pub(crate) installer: Option<u64>,
    pub(crate) update: Option<Update>,
    pub(crate) workspace: Option<u64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum StopReason {
    Running,
    DriverControlInitializationFailed,
    DriversSpawnFailed,
    DriverHelloFailed,
    FilesystemSpawnFailed,
    FilesystemReadyFailed,
    PosixSpawnFailed,
    PosixReadyFailed,
    InputSpawnFailed,
    DisplaySpawnFailed,
    DisplayReadyFailed,
    InputReadyFailed,
    UserSpawnFailed,
    UserReadyFailed,
    SecureUiSpawnFailed,
    SecureUiLoginFailed,
    BinderSpawnFailed,
    BinderReadyFailed,
    InstallerSpawnFailed,
    WorkspaceSpawnFailed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct BootstrapOutcome<
    Input = u64,
    Display = u64,
    Drivers = u64,
    Compositor = u64,
    Network = u64,
    User = u64,
    Update = u64,
    SecureUi = u64,
> {
    pub(crate) children:
        ChildProcesses<Input, Display, Drivers, Compositor, Network, User, Update, SecureUi>,
    pub(crate) reason: StopReason,
    pub(crate) identity: Option<SessionIdentity>,
    pub(crate) session_id: u64,
}

impl<Input, Display, Drivers, Compositor, Network, User, Update, SecureUi>
    BootstrapOutcome<Input, Display, Drivers, Compositor, Network, User, Update, SecureUi>
{
    pub(crate) const fn initialization_failed() -> Self {
        Self {
            children: ChildProcesses {
                drivers: None,
                mboot_agent: None,
                filesystem: None,
                posix: None,
                input: None,
                display: None,
                compositor: None,
                network: None,
                user: None,
                secure_ui: None,
                linux: None,
                binder: None,
                installer: None,
                update: None,
                workspace: None,
            },
            reason: StopReason::DriverControlInitializationFailed,
            identity: None,
            session_id: 0,
        }
    }
}

impl<Input, Display, Drivers, Compositor, Network, User, Update, SecureUi> Default
    for ChildProcesses<Input, Display, Drivers, Compositor, Network, User, Update, SecureUi>
{
    fn default() -> Self {
        BootstrapOutcome::<Input, Display, Drivers, Compositor, Network, User, Update, SecureUi>::initialization_failed()
            .children
    }
}

pub(crate) trait BootstrapOperations {
    type InputProcess;
    type DisplayProcess;
    type DriversProcess;
    type CompositorProcess;
    type NetworkProcess;
    type UserProcess;
    type UpdateProcess;
    type SecureUiProcess;
    fn spawn_secure_ui(&mut self) -> Option<Self::SecureUiProcess>;
    fn spawn_update(&mut self) -> Option<Self::UpdateProcess>;
    fn spawn_user(&mut self) -> Option<Self::UserProcess>;
    fn spawn_network(&mut self) -> Option<Self::NetworkProcess>;
    fn spawn_compositor(&mut self) -> Option<Self::CompositorProcess>;
    fn spawn_input(&mut self) -> Option<Self::InputProcess>;
    fn spawn_display(&mut self) -> Option<Self::DisplayProcess>;
    fn spawn_drivers(&mut self) -> Option<Self::DriversProcess>;
    fn wait_driver_hello(&mut self, process: &Self::DriversProcess) -> bool;
    fn spawn_mboot_agent(&mut self) -> Option<u64>;
    fn notify_mboot_stage(&mut self, stage: MbootStage);
    fn spawn_fixed(&mut self, service: FixedService) -> Option<u64>;
    fn spawn_user_session(
        &mut self,
        service: FixedService,
        identity: SessionIdentity,
        session_id: u64,
    ) -> Option<u64>;
    fn installation_required(&self) -> bool;
    fn wait_display_ready(&mut self, process: &Self::DisplayProcess) -> bool;
    fn wait_filesystem_ready(&mut self, process_id: u64) -> bool;
    fn wait_posix_ready(&mut self, process_id: u64) -> bool;
    fn wait_input_ready(&mut self, process: &Self::InputProcess) -> bool;
    fn start_discovery(&mut self) -> bool;
    fn wait_discovery_complete(&mut self, process: &Self::DriversProcess) -> bool;
    fn wait_network_ready(&mut self, process: &Self::NetworkProcess) -> bool;
    fn wait_user_ready(&mut self, process: &Self::UserProcess) -> bool;
    fn wait_secure_ui_login(&mut self, process: &Self::SecureUiProcess) -> Option<SessionIdentity>;
    fn wait_binder_ready(&mut self, process_id: u64) -> bool;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum MbootStage {
    Userspace = 1,
    Display = 2,
    Desktop = 3,
}

const FIRST_BOOT_IDENTITY: SessionIdentity = SessionIdentity { uid: 0, gid: 0 };

pub(crate) fn orchestrate<O: BootstrapOperations>(
    operations: &mut O,
) -> BootstrapOutcome<
    O::InputProcess,
    O::DisplayProcess,
    O::DriversProcess,
    O::CompositorProcess,
    O::NetworkProcess,
    O::UserProcess,
    O::UpdateProcess,
    O::SecureUiProcess,
> {
    let mut children = ChildProcesses::default();

    let Some(filesystem) = operations.spawn_fixed(FixedService::Filesystem) else {
        return outcome(children, StopReason::FilesystemSpawnFailed);
    };
    children.filesystem = Some(filesystem);
    if !operations.wait_filesystem_ready(filesystem) {
        return outcome(children, StopReason::FilesystemReadyFailed);
    }
    let Some(posix) = operations.spawn_fixed(FixedService::Posix) else {
        return outcome(children, StopReason::PosixSpawnFailed);
    };
    children.posix = Some(posix);
    if !operations.wait_posix_ready(posix) {
        return outcome(children, StopReason::PosixReadyFailed);
    }
    let Some(drivers) = operations.spawn_drivers() else {
        return outcome(children, StopReason::DriversSpawnFailed);
    };
    children.drivers = Some(drivers);
    if !operations.wait_driver_hello(children.drivers.as_ref().unwrap()) {
        return outcome(children, StopReason::DriverHelloFailed);
    }
    children.mboot_agent = operations.spawn_mboot_agent();
    operations.notify_mboot_stage(MbootStage::Userspace);

    let Some(input) = operations.spawn_input() else {
        return outcome(children, StopReason::InputSpawnFailed);
    };
    children.input = Some(input);
    let Some(display) = operations.spawn_display() else {
        return outcome(children, StopReason::DisplaySpawnFailed);
    };
    children.display = Some(display);

    if !operations.wait_display_ready(children.display.as_ref().unwrap()) {
        return outcome(children, StopReason::DisplayReadyFailed);
    }
    if !operations.wait_input_ready(children.input.as_ref().unwrap()) {
        return outcome(children, StopReason::InputReadyFailed);
    }

    children.compositor = operations.spawn_compositor();
    if children.compositor.is_some() {
        operations.notify_mboot_stage(MbootStage::Display);
    }
    // Driver discovery is best-effort after the display and input paths are
    // already usable. Slow or failed optional hardware must not prevent the
    // desktop and Installer from starting.
    let discovery_started = operations.start_discovery();

    children.network = operations.spawn_network();
    if children.network.is_some() {
        children.update = operations.spawn_update();
    }
    let Some(user) = operations.spawn_user() else {
        return outcome(children, StopReason::UserSpawnFailed);
    };
    children.user = Some(user);
    if !operations.wait_user_ready(children.user.as_ref().unwrap()) {
        return outcome(children, StopReason::UserReadyFailed);
    }

    let installation_required = operations.installation_required();
    let identity = if installation_required {
        FIRST_BOOT_IDENTITY
    } else {
        let Some(secure_ui) = operations.spawn_secure_ui() else {
            return outcome(children, StopReason::SecureUiSpawnFailed);
        };
        children.secure_ui = Some(secure_ui);
        let Some(identity) = operations.wait_secure_ui_login(children.secure_ui.as_ref().unwrap())
        else {
            return outcome(children, StopReason::SecureUiLoginFailed);
        };
        identity
    };

    let session_id = 1;
    let Some(workspace) =
        operations.spawn_user_session(FixedService::Workspace, identity, session_id)
    else {
        return outcome(children, StopReason::WorkspaceSpawnFailed);
    };
    children.workspace = Some(workspace);
    children.linux = operations.spawn_user_session(FixedService::Linux, identity, session_id);
    let Some(binder) = operations.spawn_user_session(FixedService::Binder, identity, session_id)
    else {
        return outcome(children, StopReason::BinderSpawnFailed);
    };
    children.binder = Some(binder);
    if !operations.wait_binder_ready(binder) {
        return outcome(children, StopReason::BinderReadyFailed);
    }
    if installation_required {
        let Some(installer) =
            operations.spawn_user_session(FixedService::Installer, identity, session_id)
        else {
            return outcome(children, StopReason::InstallerSpawnFailed);
        };
        children.installer = Some(installer);
    }
    operations.notify_mboot_stage(MbootStage::Desktop);
    if discovery_started {
        let _ = operations.wait_discovery_complete(children.drivers.as_ref().unwrap());
    }
    if let Some(network) = children.network.as_ref() {
        let _ = operations.wait_network_ready(network);
    }
    BootstrapOutcome {
        children,
        reason: StopReason::Running,
        identity: Some(identity),
        session_id,
    }
}

const fn outcome<Input, Display, Drivers, Compositor, Network, User, Update, SecureUi>(
    children: ChildProcesses<Input, Display, Drivers, Compositor, Network, User, Update, SecureUi>,
    reason: StopReason,
) -> BootstrapOutcome<Input, Display, Drivers, Compositor, Network, User, Update, SecureUi> {
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
        WaitHello,
        SpawnMbootAgent,
        NotifyMbootStage(MbootStage),
        Spawn(FixedService),
        SpawnUserSession(FixedService, SessionIdentity),
        WaitFilesystem,
        WaitPosix,
        WaitDisplay,
        WaitInput,
        StartDiscovery,
        WaitDiscovery,
        WaitNetwork,
        WaitUser,
        WaitSecureUiLogin,
        WaitBinder,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Failure {
        None,
        SpawnDrivers,
        Hello,
        Spawn(FixedService),
        FilesystemReady,
        PosixReady,
        DisplayReady,
        InputReady,
        StartDiscovery,
        DiscoveryComplete,
        NetworkReady,
        UserReady,
        SecureUiLogin,
        BinderReady,
    }

    struct FakeOperations {
        events: Vec<Event>,
        failure: Failure,
        installation_required: bool,
    }

    impl FakeOperations {
        fn new(failure: Failure) -> Self {
            Self {
                events: Vec::new(),
                failure,
                installation_required: false,
            }
        }

        fn first_boot() -> Self {
            Self {
                events: Vec::new(),
                failure: Failure::None,
                installation_required: true,
            }
        }
    }

    impl BootstrapOperations for FakeOperations {
        type InputProcess = u64;
        type DisplayProcess = u64;
        type DriversProcess = u64;
        type CompositorProcess = u64;
        type NetworkProcess = u64;
        type UserProcess = u64;
        type UpdateProcess = u64;
        type SecureUiProcess = u64;

        fn spawn_secure_ui(&mut self) -> Option<Self::SecureUiProcess> {
            self.spawn_fixed(FixedService::SecureUi)
        }

        fn spawn_update(&mut self) -> Option<Self::UpdateProcess> {
            self.spawn_fixed(FixedService::Update)
        }

        fn spawn_user(&mut self) -> Option<Self::UserProcess> {
            self.spawn_fixed(FixedService::User)
        }

        fn spawn_network(&mut self) -> Option<Self::NetworkProcess> {
            self.spawn_fixed(FixedService::Network)
        }

        fn spawn_compositor(&mut self) -> Option<Self::CompositorProcess> {
            self.spawn_fixed(FixedService::Compositor)
        }

        fn spawn_display(&mut self) -> Option<Self::DisplayProcess> {
            self.spawn_fixed(FixedService::Display)
        }

        fn spawn_input(&mut self) -> Option<Self::InputProcess> {
            self.spawn_fixed(FixedService::Input)
        }
        fn spawn_drivers(&mut self) -> Option<u64> {
            self.events.push(Event::SpawnDrivers);
            (self.failure != Failure::SpawnDrivers).then_some(10)
        }

        fn wait_driver_hello(&mut self, _process_id: &u64) -> bool {
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
                FixedService::Filesystem => 23,
                FixedService::Posix => 24,
                FixedService::Input => 11,
                FixedService::Display => 12,
                FixedService::Compositor => 13,
                FixedService::Network => 14,
                FixedService::User => 15,
                FixedService::SecureUi => 16,
                FixedService::Linux => 20,
                FixedService::Binder => 17,
                FixedService::Installer => 21,
                FixedService::Update => 18,
                FixedService::Workspace => 22,
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
                FixedService::Installer => 21,
                FixedService::Workspace => 22,
                _ => unreachable!("only user-session services are accepted"),
            })
        }

        fn wait_filesystem_ready(&mut self, _process_id: u64) -> bool {
            self.events.push(Event::WaitFilesystem);
            self.failure != Failure::FilesystemReady
        }

        fn wait_posix_ready(&mut self, _process_id: u64) -> bool {
            self.events.push(Event::WaitPosix);
            self.failure != Failure::PosixReady
        }

        fn installation_required(&self) -> bool {
            self.installation_required
        }

        fn wait_display_ready(&mut self, _process_id: &u64) -> bool {
            self.events.push(Event::WaitDisplay);
            self.failure != Failure::DisplayReady
        }

        fn wait_input_ready(&mut self, _process_id: &u64) -> bool {
            self.events.push(Event::WaitInput);
            self.failure != Failure::InputReady
        }

        fn start_discovery(&mut self) -> bool {
            self.events.push(Event::StartDiscovery);
            self.failure != Failure::StartDiscovery
        }

        fn wait_discovery_complete(&mut self, _process_id: &u64) -> bool {
            self.events.push(Event::WaitDiscovery);
            self.failure != Failure::DiscoveryComplete
        }

        fn wait_network_ready(&mut self, _process: &u64) -> bool {
            self.events.push(Event::WaitNetwork);
            self.failure != Failure::NetworkReady
        }

        fn wait_user_ready(&mut self, _process: &Self::UserProcess) -> bool {
            self.events.push(Event::WaitUser);
            self.failure != Failure::UserReady
        }

        fn wait_secure_ui_login(
            &mut self,
            _process: &Self::SecureUiProcess,
        ) -> Option<SessionIdentity> {
            self.events.push(Event::WaitSecureUiLogin);
            (self.failure != Failure::SecureUiLogin).then_some(TEST_IDENTITY)
        }

        fn wait_binder_ready(&mut self, _process_id: u64) -> bool {
            self.events.push(Event::WaitBinder);
            self.failure != Failure::BinderReady
        }
    }

    fn expected_success_events() -> Vec<Event> {
        alloc::vec![
            Event::Spawn(FixedService::Filesystem),
            Event::WaitFilesystem,
            Event::Spawn(FixedService::Posix),
            Event::WaitPosix,
            Event::SpawnDrivers,
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
            Event::Spawn(FixedService::Network),
            Event::Spawn(FixedService::Update),
            Event::Spawn(FixedService::User),
            Event::WaitUser,
            Event::Spawn(FixedService::SecureUi),
            Event::WaitSecureUiLogin,
            Event::SpawnUserSession(FixedService::Workspace, TEST_IDENTITY),
            Event::SpawnUserSession(FixedService::Linux, TEST_IDENTITY),
            Event::SpawnUserSession(FixedService::Binder, TEST_IDENTITY),
            Event::WaitBinder,
            Event::NotifyMbootStage(MbootStage::Desktop),
            Event::WaitDiscovery,
            Event::WaitNetwork,
        ]
    }

    #[test]
    fn successful_order_waits_for_posix_before_drivers_and_display_before_input() {
        let mut operations = FakeOperations::new(Failure::None);
        let outcome = orchestrate(&mut operations);
        assert_eq!(operations.events, expected_success_events());
        assert_eq!(outcome.reason, StopReason::Running);
        assert_eq!(outcome.children.drivers, Some(10));
        assert_eq!(outcome.children.mboot_agent, Some(11));
        assert_eq!(outcome.children.filesystem, Some(23));
        assert_eq!(outcome.children.posix, Some(24));
        assert_eq!(outcome.children.input, Some(11));
        assert_eq!(outcome.children.display, Some(12));
        assert_eq!(outcome.children.compositor, Some(13));
        assert_eq!(outcome.children.network, Some(14));
        assert_eq!(outcome.children.user, Some(15));
        assert_eq!(outcome.children.secure_ui, Some(16));
        assert_eq!(outcome.children.workspace, Some(22));
        assert_eq!(outcome.children.linux, Some(20));
        assert_eq!(outcome.children.binder, Some(17));
        assert_eq!(outcome.children.installer, None);
        assert_eq!(outcome.children.update, Some(18));
        assert_eq!(outcome.identity, Some(TEST_IDENTITY));
        assert_eq!(outcome.session_id, 1);
    }

    #[test]
    fn first_boot_opens_installer_after_binder() {
        let mut operations = FakeOperations::first_boot();
        let outcome = orchestrate(&mut operations);
        assert_eq!(outcome.reason, StopReason::Running);
        assert_eq!(outcome.children.binder, Some(17));
        assert_eq!(outcome.children.installer, Some(21));
        assert_eq!(outcome.children.secure_ui, None);
        assert!(!operations.events.contains(&Event::WaitSecureUiLogin));
        let binder = operations.events.iter().position(|event| {
            *event == Event::SpawnUserSession(FixedService::Binder, FIRST_BOOT_IDENTITY)
        });
        let installer = operations.events.iter().position(|event| {
            *event == Event::SpawnUserSession(FixedService::Installer, FIRST_BOOT_IDENTITY)
        });
        assert!(
            matches!((binder, installer), (Some(binder), Some(installer)) if binder < installer)
        );
    }

    #[test]
    fn driver_input_and_display_failures_stop_following_services() {
        let cases = [
            (Failure::SpawnDrivers, StopReason::DriversSpawnFailed),
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
    fn driver_protocol_failure_does_not_prevent_binder_start() {
        for failure in [Failure::StartDiscovery, Failure::DiscoveryComplete] {
            let mut operations = FakeOperations::new(failure);
            let outcome = orchestrate(&mut operations);
            assert_eq!(outcome.reason, StopReason::Running);
            assert!(operations.events.contains(&Event::SpawnUserSession(
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
    fn binder_must_present_before_desktop_is_ready() {
        let mut operations = FakeOperations::new(Failure::BinderReady);
        let outcome = orchestrate(&mut operations);
        assert_eq!(outcome.reason, StopReason::BinderReadyFailed);
        assert_eq!(outcome.children.binder, Some(17));
        assert_eq!(operations.events.last(), Some(&Event::WaitBinder));
        assert!(
            !operations
                .events
                .contains(&Event::NotifyMbootStage(MbootStage::Desktop))
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
    fn update_starts_before_waiting_for_network_and_is_best_effort() {
        let mut network_failure = FakeOperations::new(Failure::NetworkReady);
        let outcome = orchestrate(&mut network_failure);
        assert_eq!(outcome.reason, StopReason::Running);
        assert_eq!(outcome.children.update, Some(18));
        assert_eq!(network_failure.events.last(), Some(&Event::WaitNetwork));
        let update = network_failure
            .events
            .iter()
            .position(|event| *event == Event::Spawn(FixedService::Update));
        let wait = network_failure
            .events
            .iter()
            .position(|event| *event == Event::WaitNetwork);
        assert!(matches!((update, wait), (Some(update), Some(wait)) if update < wait));

        let mut update_failure = FakeOperations::new(Failure::Spawn(FixedService::Update));
        let outcome = orchestrate(&mut update_failure);
        assert_eq!(outcome.reason, StopReason::Running);
        assert_eq!(outcome.children.update, None);
        assert_eq!(update_failure.events.last(), Some(&Event::WaitNetwork));
    }
}
