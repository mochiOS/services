use alloc::collections::VecDeque;
use mochi_user_platform as platform;

use crate::driver_controller::{DriverControlError, DriverController};
use crate::native_process::NativeProcess;
use crate::orchestration::{BootstrapOperations, BootstrapOutcome, MbootStage, orchestrate};
use crate::readiness::{DeferredMessage, ReadyError, ReadyHandshake, ReadyService};
use crate::service_config::FixedService;
use crate::service_launcher;
use crate::session::ActiveSession;
use crate::session_teardown::{SessionTeardown, TeardownError, terminate_owned_root};
use crate::spawn_support::errno;

struct Runtime {
    logger_endpoint: u64,
    driver_controller: DriverController,
    ready: Option<ReadyHandshake>,
    mboot_agent: Option<(NativeProcess, u64)>,
    deferred_requests: VecDeque<DeferredMessage>,
    permission_prompt: crate::portal::PermissionPrompts,
    iommu_warning: Option<NativeProcess>,
    filesystem_endpoint: Option<platform::handle::Handle>,
    posix_endpoint: Option<platform::handle::Handle>,
    session_processes: alloc::collections::BTreeMap<u64, NativeProcess>,
    unpublished_session_roots: alloc::vec::Vec<u64>,
    failed_session_cleanup: Option<PendingSessionCleanup>,
}

struct PendingSessionCleanup {
    plan: SessionTeardown,
    client: mochios_posix_client::Client<mochios_posix_client::SyscallEndpointTransport>,
    last_error: Option<u64>,
}

struct PendingLogout {
    session: ActiveSession,
    sender: u64,
    plan: SessionTeardown,
    client: mochios_posix_client::Client<mochios_posix_client::SyscallEndpointTransport>,
    acknowledged: bool,
    last_error: Option<u64>,
}

impl Runtime {
    fn login_next_session(&mut self, previous: ActiveSession) -> Option<ActiveSession> {
        if self.failed_session_cleanup.is_some()
            || !self.unpublished_session_roots.is_empty()
            || service_launcher::has_failed_launch_cleanup()
        {
            return None;
        }
        let session = self.launch_next_session(previous);
        if session.is_some() {
            self.unpublished_session_roots.clear();
        } else {
            self.schedule_failed_session_cleanup();
        }
        session
    }

    fn schedule_failed_session_cleanup(&mut self) {
        if self.unpublished_session_roots.is_empty() || self.failed_session_cleanup.is_some() {
            return;
        }
        let Some(endpoint) = self.posix_endpoint else {
            // Keep the unpublished roots and owners; never replace authority
            // with a PID lookup or discard them when the endpoint is missing.
            return;
        };
        match SessionTeardown::begin_failed_launch(
            &self.unpublished_session_roots,
            &self.session_processes,
        ) {
            Ok(plan) => {
                self.failed_session_cleanup = Some(PendingSessionCleanup {
                    plan,
                    client: mochios_posix_client::Client::new(
                        mochios_posix_client::SyscallEndpointTransport::new(endpoint),
                    ),
                    last_error: None,
                });
                self.unpublished_session_roots.clear();
            }
            Err(error) => platform::logln!(
                "service-manager.service: failed session cleanup preflight failed: {error:?}"
            ),
        }
    }

    fn retry_failed_session_cleanup(&mut self) {
        let Some(cleanup) = self.failed_session_cleanup.as_mut() else {
            return;
        };
        match cleanup.plan.step(|process_id| {
            terminate_owned_root(&cleanup.client, &mut self.session_processes, process_id)
        }) {
            Ok(true) => self.failed_session_cleanup = None,
            Ok(false) => cleanup.last_error = None,
            Err(error) => {
                let status = match error {
                    mochios_posix_client::ClientError::Transport(error) => errno(error),
                    mochios_posix_client::ClientError::Remote(status) => {
                        status.unsigned_abs() as u64
                    }
                    _ => mochi_user_syscall::EIO,
                };
                if cleanup.last_error != Some(status) {
                    platform::logln!(
                        "service-manager.service: failed session cleanup pending errno={}",
                        status
                    );
                    cleanup.last_error = Some(status);
                }
                let _ = platform::thread::sleep_milliseconds(10);
            }
        }
    }

    fn launch_next_session(&mut self, previous: ActiveSession) -> Option<ActiveSession> {
        let identity = self.authenticate_session(None)?;
        let session_id = previous.next_id();
        let workspace_pid = self.spawn_workspace_session(identity, session_id)?;
        let linux_pid = self
            .launch_session_image(FixedService::Linux, identity, session_id, None)
            .ok();
        match self.launch_session_image(FixedService::Binder, identity, session_id, None) {
            Ok(binder_pid) => ActiveSession::from_process_ids(
                session_id,
                identity,
                linux_pid,
                workspace_pid,
                binder_pid,
            )
            .map_err(|error| {
                eprintln!(
                    "service-manager.service: session identity resolution failed: {:?}",
                    error
                );
            })
            .ok(),
            Err(error) => {
                platform::logln!(
                    "service-manager.service: Binder.app spawn failed errno={}",
                    errno(error)
                );
                None
            }
        }
    }

    fn launch_session_image(
        &mut self,
        service: FixedService,
        identity: platform::service_ready::SessionIdentity,
        session_id: u64,
        target: Option<platform::service_ready::Target>,
    ) -> Result<u64, mochi_user_syscall::SysError> {
        let process = service_launcher::spawn_user_session(
            service,
            self.logger_endpoint,
            identity,
            session_id,
            target,
            self.posix_endpoint,
        )?;
        let id = process.process_id();
        self.session_processes.insert(id, process);
        self.unpublished_session_roots.push(id);
        Ok(id)
    }

    fn create(logger_endpoint: u64) -> Result<Self, DriverControlError> {
        Ok(Self {
            logger_endpoint,
            driver_controller: DriverController::create()?,
            ready: None,
            mboot_agent: None,
            deferred_requests: VecDeque::new(),
            permission_prompt: crate::portal::PermissionPrompts::default(),
            iommu_warning: None,
            filesystem_endpoint: None,
            posix_endpoint: None,
            session_processes: alloc::collections::BTreeMap::new(),
            unpublished_session_roots: alloc::vec::Vec::new(),
            failed_session_cleanup: None,
        })
    }

    fn ensure_ready_handshake(&mut self) -> bool {
        if self.ready.is_some() {
            return true;
        }
        match ReadyHandshake::create() {
            Ok(handshake) => {
                self.ready = Some(handshake);
                true
            }
            Err(error) => {
                platform::logln!(
                    "service-manager.service: ready handshake create failed error={:?}",
                    error
                );
                false
            }
        }
    }

    fn wait_ready(
        &mut self,
        service: ReadyService,
        process_id: impl Into<crate::process_watch::ProcessWatchTarget>,
    ) -> bool {
        platform::logln!(
            "service-manager.service: waiting for {} ready",
            service.name()
        );
        let result = match self.ready.as_mut() {
            Some(handshake) => handshake.wait_for_service_ready(service, process_id),
            None => Err(ReadyError::InvalidMessage),
        };
        if service == ReadyService::Network {
            if let Some(handshake) = self.ready.as_mut() {
                self.deferred_requests.extend(handshake.take_deferred());
            }
            self.ready = None;
        }
        match result {
            Ok(()) => {
                platform::logln!("service-manager.service: {} ready", service.name());
                if service == ReadyService::Binder {
                    eprintln!("service-manager.service: Binder.app ready");
                    let _ = platform::logger::flush_pending();
                }
                true
            }
            Err(error) => {
                log_ready_error(service, error);
                false
            }
        }
    }

    fn spawn_workspace_session(
        &mut self,
        identity: platform::service_ready::SessionIdentity,
        session_id: u64,
    ) -> Option<u64> {
        let owns_handshake = self.ready.is_none();
        if !self.ensure_ready_handshake() {
            return None;
        }
        let target = self
            .ready
            .as_ref()
            .map(|handshake| handshake.target(ReadyService::Workspace))?;
        let process_id = match self.launch_session_image(
            FixedService::Workspace,
            identity,
            session_id,
            Some(target),
        ) {
            Ok(process_id) => process_id,
            Err(error) => {
                platform::logln!(
                    "service-manager.service: workspace.service spawn failed errno={}",
                    errno(error)
                );
                return None;
            }
        };
        platform::logln!(
            "service-manager.service: workspace.service spawned pid={}",
            process_id
        );
        let watch = self.session_processes.get(&process_id)?.watch_target();
        let ready = self.wait_ready(ReadyService::Workspace, watch);
        if owns_handshake {
            if let Some(handshake) = self.ready.as_mut() {
                self.deferred_requests.extend(handshake.take_deferred());
            }
            self.ready = None;
        }
        ready.then_some(process_id)
    }

    fn authenticate_session(
        &mut self,
        lock_uid: Option<u32>,
    ) -> Option<platform::service_ready::SessionIdentity> {
        let mut handshake = match ReadyHandshake::create() {
            Ok(handshake) => handshake,
            Err(error) => {
                platform::logln!(
                    "service-manager.service: secure UI handshake create failed error={:?}",
                    error
                );
                return None;
            }
        };
        let target = handshake.target(ReadyService::SecureUi);
        let process = match service_launcher::spawn_secure_ui(
            self.logger_endpoint,
            target,
            lock_uid,
            self.posix_endpoint?,
        ) {
            Ok(process) => process,
            Err(error) => {
                platform::logln!(
                    "service-manager.service: secure-ui.service spawn failed errno={}",
                    errno(error)
                );
                return None;
            }
        };
        match handshake.wait_for_login_complete(process.watch_target()) {
            Ok(identity) => Some(identity),
            Err(error) => {
                log_ready_error(ReadyService::SecureUi, error);
                None
            }
        }
    }
}

impl BootstrapOperations for Runtime {
    type InputProcess = NativeProcess;
    type DisplayProcess = NativeProcess;
    type DriversProcess = NativeProcess;
    type CompositorProcess = NativeProcess;
    type NetworkProcess = NativeProcess;
    type UserProcess = NativeProcess;
    type UpdateProcess = NativeProcess;
    type SecureUiProcess = NativeProcess;

    fn spawn_secure_ui(&mut self) -> Option<Self::SecureUiProcess> {
        let endpoint = self.posix_endpoint?;
        if !self.ensure_ready_handshake() {
            return None;
        }
        let target = self.ready.as_ref()?.target(ReadyService::SecureUi);
        match service_launcher::spawn_secure_ui(self.logger_endpoint, target, None, endpoint) {
            Ok(process) => {
                eprintln!("service-manager.service: secure-ui.service native process created");
                Some(process)
            }
            Err(error) => {
                eprintln!(
                    "service-manager.service: secure-ui.service native spawn failed errno={}",
                    errno(error)
                );
                None
            }
        }
    }

    fn spawn_update(&mut self) -> Option<Self::UpdateProcess> {
        match service_launcher::spawn_update_service(self.logger_endpoint, self.posix_endpoint?) {
            Ok(process) => {
                eprintln!("service-manager.service: update.service native process created");
                Some(process)
            }
            Err(error) => {
                eprintln!(
                    "service-manager.service: update.service native spawn failed errno={}",
                    errno(error)
                );
                None
            }
        }
    }

    fn spawn_user(&mut self) -> Option<Self::UserProcess> {
        let endpoint = self.posix_endpoint?;
        if !self.ensure_ready_handshake() {
            return None;
        }
        let target = self.ready.as_ref()?.target(ReadyService::User);
        match service_launcher::spawn_user_service(self.logger_endpoint, target, endpoint) {
            Ok(process) => {
                eprintln!("service-manager.service: user.service native process created");
                Some(process)
            }
            Err(error) => {
                eprintln!(
                    "service-manager.service: user.service native spawn failed errno={}",
                    errno(error)
                );
                None
            }
        }
    }

    fn spawn_network(&mut self) -> Option<Self::NetworkProcess> {
        let endpoint = self.posix_endpoint?;
        if !self.ensure_ready_handshake() {
            return None;
        }
        let target = self.ready.as_ref()?.target(ReadyService::Network);
        match service_launcher::spawn_network_service(self.logger_endpoint, target, endpoint) {
            Ok(process) => {
                eprintln!("service-manager.service: network.service native process created");
                Some(process)
            }
            Err(error) => {
                eprintln!(
                    "service-manager.service: network.service native spawn failed errno={}",
                    errno(error)
                );
                None
            }
        }
    }

    fn spawn_compositor(&mut self) -> Option<Self::CompositorProcess> {
        let endpoint = self.posix_endpoint?;
        match service_launcher::spawn_compositor_service(self.logger_endpoint, endpoint) {
            Ok(process) => {
                eprintln!("service-manager.service: compositor.service native process created");
                Some(process)
            }
            Err(error) => {
                eprintln!(
                    "service-manager.service: compositor.service native spawn failed errno={}",
                    errno(error)
                );
                None
            }
        }
    }

    fn spawn_display(&mut self) -> Option<Self::DisplayProcess> {
        let endpoint = self.posix_endpoint?;
        if !self.ensure_ready_handshake() {
            return None;
        }
        let target = self.ready.as_ref()?.target(ReadyService::Display);
        match service_launcher::spawn_display_service(self.logger_endpoint, target, endpoint) {
            Ok(process) => {
                platform::logln!(
                    "service-manager.service: display.driver spawned with retained Process Handle"
                );
                Some(process)
            }
            Err(error) => {
                eprintln!(
                    "service-manager.service: display.driver native spawn failed errno={}",
                    errno(error)
                );
                None
            }
        }
    }

    fn spawn_input(&mut self) -> Option<Self::InputProcess> {
        let endpoint = self.posix_endpoint?;
        if !self.ensure_ready_handshake() {
            return None;
        }
        let target = self.ready.as_ref()?.target(ReadyService::Input);
        match service_launcher::spawn_input_service(self.logger_endpoint, target, endpoint) {
            Ok(process) => {
                platform::logln!(
                    "service-manager.service: input.service spawned with retained Process Handle"
                );
                Some(process)
            }
            Err(error) => {
                eprintln!(
                    "service-manager.service: input.service native spawn failed errno={}",
                    errno(error)
                );
                platform::logln!(
                    "service-manager.service: input.service native spawn failed errno={}",
                    errno(error)
                );
                None
            }
        }
    }
    fn spawn_drivers(&mut self) -> Option<Self::DriversProcess> {
        match service_launcher::spawn_drivers(
            self.logger_endpoint,
            self.driver_controller.target(),
            self.posix_endpoint?,
        ) {
            Ok(process) => {
                platform::logln!(
                    "service-manager.service: drivers.service spawned with retained Process Handle"
                );
                Some(process)
            }
            Err(error) => {
                eprintln!(
                    "service-manager.service: drivers.service spawn failed errno={}",
                    errno(error)
                );
                None
            }
        }
    }

    fn wait_driver_hello(&mut self, process: &Self::DriversProcess) -> bool {
        platform::logln!("service-manager.service: waiting for drivers.service hello");
        match self
            .driver_controller
            .wait_for_hello(process.watch_target())
        {
            Ok(_) => {
                eprintln!("service-manager.service: drivers.service native HELLO received");
                platform::logln!("service-manager.service: drivers.service hello received");
                true
            }
            Err(error) => {
                platform::logln!(
                    "service-manager.service: drivers.service hello failed error={:?}",
                    error
                );
                false
            }
        }
    }

    fn spawn_mboot_agent(&mut self) -> Option<u64> {
        let endpoint = self.posix_endpoint.filter(|endpoint| *endpoint != 0)?;
        let token = match platform::service_ready::generate_token() {
            Ok(token) => token,
            Err(error) => {
                platform::logln!(
                    "service-manager.service: mboot-agent token generation failed errno={}",
                    errno(error)
                );
                return None;
            }
        };
        match service_launcher::spawn_mboot_agent(self.logger_endpoint, token, endpoint) {
            Ok(process) => {
                let process_id = process.process_id();
                self.mboot_agent = Some((process, token));
                eprintln!("service-manager.service: mboot-agent.service native process created");
                platform::logln!(
                    "service-manager.service: mboot-agent.service spawned pid={}",
                    process_id
                );
                Some(process_id)
            }
            Err(error) => {
                eprintln!(
                    "service-manager.service: mboot-agent.service native creation failed errno={}",
                    errno(error)
                );
                platform::logln!(
                    "service-manager.service: mboot-agent.service spawn failed errno={}",
                    errno(error)
                );
                None
            }
        }
    }

    fn notify_mboot_stage(&mut self, stage: MbootStage) {
        let Some((process, token)) = self.mboot_agent.as_ref() else {
            return;
        };
        let request = platform::service_ready::notification(*token, stage as i32);
        if platform::ipc::send(process.process_id(), &request).is_err() {
            platform::logln!(
                "service-manager.service: mboot-agent stage notification failed stage={}",
                stage as i32
            );
        }
    }

    fn spawn_fixed(&mut self, service: FixedService) -> Option<u64> {
        let ready_target = match service {
            FixedService::Filesystem => {
                if !self.ensure_ready_handshake() {
                    return None;
                }
                self.ready
                    .as_ref()
                    .map(|handshake| handshake.target(ReadyService::Filesystem))
            }
            FixedService::Posix => {
                if !self.ensure_ready_handshake() {
                    return None;
                }
                self.ready
                    .as_ref()
                    .map(|handshake| handshake.target(ReadyService::Posix))
            }
            FixedService::Input => {
                if !self.ensure_ready_handshake() {
                    return None;
                }
                self.ready
                    .as_ref()
                    .map(|handshake| handshake.target(ReadyService::Input))
            }
            FixedService::Display => self
                .ready
                .as_ref()
                .map(|handshake| handshake.target(ReadyService::Display)),
            FixedService::Network => {
                if !self.ensure_ready_handshake() {
                    return None;
                }
                self.ready
                    .as_ref()
                    .map(|handshake| handshake.target(ReadyService::Network))
            }
            FixedService::User => {
                if !self.ensure_ready_handshake() {
                    return None;
                }
                self.ready
                    .as_ref()
                    .map(|handshake| handshake.target(ReadyService::User))
            }
            FixedService::SecureUi => {
                if !self.ensure_ready_handshake() {
                    return None;
                }
                self.ready
                    .as_ref()
                    .map(|handshake| handshake.target(ReadyService::SecureUi))
            }
            FixedService::MbootAgent
            | FixedService::Compositor
            | FixedService::Linux
            | FixedService::Binder
            | FixedService::Installer
            | FixedService::Update
            | FixedService::Workspace => None,
        };
        if matches!(service, FixedService::Display) && ready_target.is_none() {
            platform::logln!(
                "service-manager.service: display.driver spawn failed no ready target"
            );
            return None;
        }
        match service_launcher::spawn_fixed_service(
            service,
            self.logger_endpoint,
            ready_target,
            self.filesystem_endpoint,
            self.posix_endpoint,
        ) {
            Ok(process_id) => {
                platform::logln!(
                    "service-manager.service: {} spawned pid={}",
                    service_name(service),
                    process_id
                );
                Some(process_id)
            }
            Err(error) => {
                platform::logln!(
                    "service-manager.service: {} spawn failed errno={}",
                    service_name(service),
                    errno(error)
                );
                None
            }
        }
    }

    fn spawn_user_session(
        &mut self,
        service: FixedService,
        identity: platform::service_ready::SessionIdentity,
        session_id: u64,
    ) -> Option<u64> {
        if service == FixedService::Workspace {
            return self.spawn_workspace_session(identity, session_id);
        }
        let ready_target = if service == FixedService::Binder {
            if !self.ensure_ready_handshake() {
                return None;
            }
            self.ready
                .as_ref()
                .map(|handshake| handshake.target(ReadyService::Binder))
        } else {
            None
        };
        match self.launch_session_image(service, identity, session_id, ready_target) {
            Ok(process_id) => {
                platform::logln!(
                    "service-manager.service: {} spawned pid={}",
                    service_name(service),
                    process_id
                );
                Some(process_id)
            }
            Err(error) => {
                platform::logln!(
                    "service-manager.service: {} spawn failed errno={}",
                    service_name(service),
                    errno(error)
                );
                None
            }
        }
    }

    fn wait_display_ready(&mut self, process: &Self::DisplayProcess) -> bool {
        let ready = self.wait_ready(ReadyService::Display, process.watch_target());
        if ready {
            eprintln!("service-manager.service: display.driver native READY received");
        }
        ready
    }

    fn wait_binder_ready(&mut self, process_id: u64) -> bool {
        let Some(process) = self.session_processes.get(&process_id) else {
            return false;
        };
        self.wait_ready(ReadyService::Binder, process.watch_target())
    }

    fn wait_filesystem_ready(&mut self, process_id: u64) -> bool {
        platform::logln!("service-manager.service: waiting for filesystem.service ready");
        let result = self
            .ready
            .as_mut()
            .ok_or(ReadyError::InvalidMessage)
            .and_then(|handshake| {
                handshake.wait_for_endpoint_ready(ReadyService::Filesystem, process_id)
            });
        match result {
            Ok(endpoint) => {
                self.filesystem_endpoint = Some(endpoint);
                platform::logln!(
                    "service-manager.service: filesystem.service ready endpoint={}",
                    endpoint
                );
                true
            }
            Err(error) => {
                log_ready_error(ReadyService::Filesystem, error);
                false
            }
        }
    }

    fn wait_posix_ready(&mut self, process_id: u64) -> bool {
        platform::logln!("service-manager.service: waiting for posix.service ready");
        let result = self
            .ready
            .as_mut()
            .ok_or(ReadyError::InvalidMessage)
            .and_then(|handshake| {
                handshake.wait_for_endpoint_ready(ReadyService::Posix, process_id)
            });
        match result {
            Ok(endpoint) => {
                if let Err(error) = platform::handle::set_context_handle(
                    mochios_posix_protocol::CONTROL_HANDLE_KEY,
                    endpoint,
                ) {
                    platform::logln!(
                        "service-manager.service: local POSIX endpoint bind failed status={}",
                        error.raw()
                    );
                    return false;
                }
                if let Err(error) = crate::spawn_support::install_early_posix_endpoints(
                    endpoint,
                    self.logger_endpoint,
                ) {
                    platform::logln!(
                        "service-manager.service: capability POSIX endpoint install failed errno={}",
                        crate::spawn_support::errno(error)
                    );
                    return false;
                }
                self.posix_endpoint = Some(endpoint);
                platform::logln!(
                    "service-manager.service: posix.service ready endpoint={}",
                    endpoint
                );
                true
            }
            Err(error) => {
                log_ready_error(ReadyService::Posix, error);
                false
            }
        }
    }

    fn wait_input_ready(&mut self, process: &Self::InputProcess) -> bool {
        self.wait_ready(ReadyService::Input, process.watch_target())
    }

    fn wait_user_ready(&mut self, process: &Self::UserProcess) -> bool {
        let ready = self.wait_ready(ReadyService::User, process.watch_target());
        if ready {
            eprintln!("service-manager.service: user.service native READY received");
        }
        ready
    }

    fn wait_secure_ui_login(
        &mut self,
        process: &Self::SecureUiProcess,
    ) -> Option<platform::service_ready::SessionIdentity> {
        platform::logln!("service-manager.service: waiting for secure-ui.service login");
        let result = match self.ready.as_mut() {
            Some(handshake) => handshake.wait_for_login_complete(process.watch_target()),
            None => Err(ReadyError::InvalidMessage),
        };
        match result {
            Ok(identity) => {
                platform::logln!("service-manager.service: secure-ui.service login complete");
                Some(identity)
            }
            Err(error) => {
                log_ready_error(ReadyService::SecureUi, error);
                None
            }
        }
    }

    fn start_discovery(&mut self) -> bool {
        match self.driver_controller.start_discovery() {
            Ok(()) => {
                platform::logln!("service-manager.service: driver discovery requested");
                true
            }
            Err(error) => {
                platform::logln!(
                    "service-manager.service: driver discovery request failed error={:?}",
                    error
                );
                false
            }
        }
    }

    fn wait_discovery_complete(&mut self, process: &Self::DriversProcess) -> bool {
        match self
            .driver_controller
            .wait_for_complete(process.watch_target())
        {
            Ok(()) => {
                platform::logln!("service-manager.service: driver discovery complete");
                true
            }
            Err(error) => {
                platform::logln!(
                    "service-manager.service: driver discovery failed error={:?}",
                    error
                );
                false
            }
        }
    }

    fn wait_network_ready(&mut self, process: &Self::NetworkProcess) -> bool {
        self.wait_ready(ReadyService::Network, process.watch_target())
    }

    fn installation_required(&self) -> bool {
        std::fs::metadata("/system/.installed").is_err()
    }
}

pub(crate) fn run() -> ! {
    platform::logln!("service-manager.service: start");
    let logger_endpoint = platform::logger::endpoint().map_or(0, |endpoint| endpoint);
    let (outcome, mut runtime) = match Runtime::create(logger_endpoint) {
        Ok(mut runtime) => {
            let outcome = orchestrate(&mut runtime);
            (outcome, Some(runtime))
        }
        Err(error) => {
            eprintln!(
                "service-manager.service: driver controller create failed error={:?}",
                error
            );
            (BootstrapOutcome::initialization_failed(), None)
        }
    };
    platform::logln!(
        "service-manager.service: resident phase reason={:?}",
        outcome.reason
    );
    if outcome.children.binder.is_some()
        // KVM accelerates the CPU but does not imply an emulated VT-d/AMD-Vi
        // device. Do not show a physical-firmware warning inside a VM.
        && !running_under_hypervisor()
        && platform::memory::framebuffer_info().is_ok_and(|info| {
            info.addr != 0
                && info.format & mnu_abi::hypervisor::FRAMEBUFFER_FORMAT_SHARED_SURFACE == 0
        })
        && let Some(runtime) = runtime.as_mut()
        && let Some(endpoint) = runtime.posix_endpoint
    {
        let vendor = cpu_iommu_vendor();
        match service_launcher::spawn_iommu_warning(logger_endpoint, vendor, endpoint) {
            Ok(process) => {
                runtime.iommu_warning = Some(process);
                platform::logln!(
                    "service-manager.service: hardware acceleration warning native process created"
                );
            }
            Err(error) => platform::logln!(
                "service-manager.service: hardware acceleration warning spawn failed errno={}",
                errno(error)
            ),
        }
    }
    resident(outcome, runtime)
}

fn running_under_hypervisor() -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        core::arch::x86_64::__cpuid(1).ecx & (1 << 31) != 0
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        false
    }
}

fn cpu_iommu_vendor() -> &'static str {
    #[cfg(target_arch = "x86_64")]
    {
        let leaf = core::arch::x86_64::__cpuid(0);
        let mut vendor = [0u8; 12];
        vendor[0..4].copy_from_slice(&leaf.ebx.to_le_bytes());
        vendor[4..8].copy_from_slice(&leaf.edx.to_le_bytes());
        vendor[8..12].copy_from_slice(&leaf.ecx.to_le_bytes());
        if &vendor == b"AuthenticAMD" {
            return "amd";
        }
    }
    "intel"
}

fn service_name(service: FixedService) -> &'static str {
    match service {
        FixedService::MbootAgent => "mboot-agent.service",
        FixedService::Filesystem => "filesystem.service",
        FixedService::Posix => "posix.service",
        FixedService::Input => "input.service",
        FixedService::Display => "display.driver",
        FixedService::Compositor => "compositor.service",
        FixedService::Network => "network.service",
        FixedService::User => "user.service",
        FixedService::SecureUi => "secure-ui.service",
        FixedService::Linux => "linux.service",
        FixedService::Binder => "Binder.app",
        FixedService::Installer => "Installer.app",
        FixedService::Update => "update.service",
        FixedService::Workspace => "workspace.service",
    }
}

fn log_ready_error(service: ReadyService, error: ReadyError) {
    // Startup failures must remain visible before logger persistence is ready.
    eprintln!(
        "service-manager.service: {} readiness failed: {:?}",
        service.name(),
        error
    );
}

fn resident(
    outcome: BootstrapOutcome<
        NativeProcess,
        NativeProcess,
        NativeProcess,
        NativeProcess,
        NativeProcess,
        NativeProcess,
        NativeProcess,
        NativeProcess,
    >,
    runtime: Option<Runtime>,
) -> ! {
    let mut runtime = runtime;
    let mut active_session = outcome
        .identity
        .zip(outcome.children.binder)
        .zip(outcome.children.workspace)
        .and_then(|((identity, binder_thread), workspace_thread)| {
            ActiveSession::from_process_ids(
                outcome.session_id,
                identity,
                outcome.children.linux,
                workspace_thread,
                binder_thread,
            )
            .map_err(|error| {
                eprintln!(
                    "service-manager.service: session identity resolution failed: {:?}",
                    error
                );
            })
            .ok()
        });
    if active_session.is_some()
        && let Some(runtime) = runtime.as_mut()
    {
        crate::portal::prewarm(&mut runtime.permission_prompt, runtime.logger_endpoint);
    }
    let mut request_bytes = [0u8; 1024];
    if let Some(runtime) = runtime.as_mut() {
        if active_session.is_some() {
            runtime.unpublished_session_roots.clear();
        } else {
            runtime.schedule_failed_session_cleanup();
        }
    }
    let mut pending_logout: Option<PendingLogout> = None;
    loop {
        service_launcher::retry_failed_launch_cleanup();
        if let Some(runtime) = runtime.as_mut() {
            runtime.retry_failed_session_cleanup();
        }
        if let (Some(logout), Some(runtime)) = (pending_logout.as_mut(), runtime.as_mut()) {
            // Binder exits voluntarily on success. Do not acknowledge until
            // all preceding roots have confirmed exit AND released their refs.
            if !logout.acknowledged && logout.plan.pending_root() == Some(logout.session.binder_pid)
            {
                reply_session_status(
                    logout.sender,
                    platform::session_control::Action::LogOut,
                    logout.session.id,
                    0,
                );
                logout.acknowledged = true;
            }
            let result = logout.plan.step(|process_id| {
                terminate_owned_root(&logout.client, &mut runtime.session_processes, process_id)
            });
            match result {
                Ok(true) => {
                    let previous = logout.session;
                    pending_logout = None;
                    let _ = active_session.take();
                    // No authentication or new image may precede this gate.
                    active_session = runtime.login_next_session(previous);
                }
                Ok(false) => logout.last_error = None,
                Err(error) => {
                    let status = match error {
                        mochios_posix_client::ClientError::Transport(error) => errno(error),
                        mochios_posix_client::ClientError::Remote(status) => {
                            status.unsigned_abs() as u64
                        }
                        _ => mochi_user_syscall::EIO,
                    };
                    if logout.last_error != Some(status) {
                        platform::logln!(
                            "service-manager.service: session termination pending errno={}",
                            status
                        );
                        logout.last_error = Some(status);
                    }
                    // Retain both the session and the failed root's owner;
                    // throttle retries while still servicing incoming IPC.
                    let _ = platform::thread::sleep_milliseconds(10);
                }
            }
        }
        let received = if let Some(deferred) = runtime.as_mut().and_then(|runtime| {
            runtime
                .permission_prompt
                .deferred
                .pop_front()
                .or_else(|| runtime.deferred_requests.pop_front())
        }) {
            let length = deferred.bytes.len().min(request_bytes.len());
            request_bytes[..length].copy_from_slice(&deferred.bytes[..length]);
            (deferred.sender << 32) | length as u64
        } else {
            match platform::ipc::try_wait(&mut request_bytes) {
                Ok(received) => received,
                Err(error)
                    if error.native_error() == Some(mochi_user_syscall::NativeError::NotReady) =>
                {
                    platform::thread::yield_now();
                    continue;
                }
                Err(_) => {
                    platform::thread::yield_now();
                    continue;
                }
            }
        };
        let sender = received >> 32;
        let length = (received & 0xffff_ffff) as usize;
        let Some(message) = request_bytes.get(..length) else {
            continue;
        };
        if message.starts_with(&mochios_linux_portal_protocol::MAGIC.to_le_bytes()) {
            let available_session = if pending_logout.is_none() {
                active_session
            } else {
                None
            };
            if let Some(runtime) = runtime.as_mut() {
                crate::portal::handle(
                    message,
                    sender,
                    available_session,
                    runtime.logger_endpoint,
                    &mut runtime.permission_prompt,
                );
            } else {
                let mut prompt = crate::portal::PermissionPrompts::default();
                crate::portal::handle(message, sender, available_session, 0, &mut prompt);
            }
            continue;
        }
        let request = request_bytes
            .get(..length)
            .ok_or(())
            .and_then(|bytes| platform::session_control::decode_request(bytes).map_err(|_| ()));
        let Ok(request) = request else {
            reply_session_status(
                sender,
                platform::session_control::Action::Lock,
                1,
                mochi_user_syscall::EINVAL as i32,
            );
            continue;
        };
        let Some(session) = active_session else {
            reply_session_status(
                sender,
                request.action,
                request.session_id,
                mochi_user_syscall::EPERM as i32,
            );
            continue;
        };
        let sender_process = platform::ipc::endpoint_owner_process(sender).ok();
        if sender_process != Some(session.binder_pid) || request.session_id != session.id {
            reply_session_status(
                sender,
                request.action,
                request.session_id,
                mochi_user_syscall::EPERM as i32,
            );
            continue;
        }
        if pending_logout.is_some() {
            reply_session_status(
                sender,
                request.action,
                request.session_id,
                mochi_user_syscall::EAGAIN as i32,
            );
            continue;
        }
        let Some(runtime) = runtime.as_mut() else {
            reply_session_status(
                sender,
                request.action,
                request.session_id,
                mochi_user_syscall::EIO as i32,
            );
            continue;
        };
        match request.action {
            platform::session_control::Action::Lock => {
                let status = match runtime.authenticate_session(Some(session.identity.uid)) {
                    Some(identity) if identity == session.identity => 0,
                    Some(_) => mochi_user_syscall::EACCES as i32,
                    None => mochi_user_syscall::EIO as i32,
                };
                reply_session_status(sender, request.action, session.id, status);
            }
            platform::session_control::Action::LogOut => {
                let Some(endpoint) = runtime.posix_endpoint else {
                    reply_session_status(
                        sender,
                        request.action,
                        session.id,
                        mochi_user_syscall::EIO as i32,
                    );
                    continue;
                };
                match SessionTeardown::begin(
                    session.linux_pid,
                    session.workspace_pid,
                    session.binder_pid,
                    &runtime.session_processes,
                ) {
                    Ok(plan) => {
                        pending_logout = Some(PendingLogout {
                            session,
                            sender,
                            plan,
                            client: mochios_posix_client::Client::new(
                                mochios_posix_client::SyscallEndpointTransport::new(endpoint),
                            ),
                            acknowledged: false,
                            last_error: None,
                        });
                    }
                    Err(error) => reply_session_status(
                        sender,
                        request.action,
                        session.id,
                        match error {
                            TeardownError::InvalidRoot => mochi_user_syscall::EINVAL,
                            TeardownError::MissingOwner => mochi_user_syscall::ESRCH,
                        } as i32,
                    ),
                }
            }
        }
    }
}

fn reply_session_status(
    sender: u64,
    action: platform::session_control::Action,
    session_id: u64,
    status: i32,
) {
    let response =
        platform::session_control::encode_response(platform::session_control::Response {
            action,
            session_id,
            status,
        });
    let _ = platform::ipc::reply(sender, &response);
}
