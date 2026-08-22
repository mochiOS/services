use alloc::collections::VecDeque;
use mochi_user_platform as platform;

use crate::driver_controller::{DriverControlError, DriverController};
use crate::orchestration::{BootstrapOperations, BootstrapOutcome, MbootStage, orchestrate};
use crate::readiness::{DeferredMessage, ReadyError, ReadyHandshake, ReadyService};
use crate::service_config::FixedService;
use crate::service_launcher;
use crate::session::{ActiveSession, terminate_process_tree};
use crate::spawn_support::{errno, sys_error};

const DELEGATE_REGISTER_ATTEMPTS: usize = 32;

struct Runtime {
    logger_endpoint: u64,
    driver_controller: DriverController,
    ready: Option<ReadyHandshake>,
    mboot_agent: Option<(u64, u64)>,
    deferred_requests: VecDeque<DeferredMessage>,
    permission_prompt: Option<crate::portal::PermissionPromptProcess>,
}

impl Runtime {
    fn create(logger_endpoint: u64) -> Result<Self, DriverControlError> {
        Ok(Self {
            logger_endpoint,
            driver_controller: DriverController::create()?,
            ready: None,
            mboot_agent: None,
            deferred_requests: VecDeque::new(),
            permission_prompt: None,
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

    fn wait_ready(&mut self, service: ReadyService, process_id: u64) -> bool {
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
                true
            }
            Err(error) => {
                log_ready_error(service, error);
                false
            }
        }
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
        let process_id =
            match service_launcher::spawn_secure_ui(self.logger_endpoint, target, lock_uid) {
                Ok(process_id) => process_id,
                Err(error) => {
                    platform::logln!(
                        "service-manager.service: secure-ui.service spawn failed errno={}",
                        errno(error)
                    );
                    return None;
                }
            };
        match handshake.wait_for_login_complete(process_id) {
            Ok(identity) => Some(identity),
            Err(error) => {
                log_ready_error(ReadyService::SecureUi, error);
                None
            }
        }
    }
}

impl BootstrapOperations for Runtime {
    fn spawn_drivers(&mut self) -> Option<u64> {
        match service_launcher::spawn_drivers(self.logger_endpoint, self.driver_controller.target())
        {
            Ok(process_id) => {
                platform::logln!(
                    "service-manager.service: drivers.service spawned pid={}",
                    process_id
                );
                Some(process_id)
            }
            Err(error) => {
                platform::logln!(
                    "service-manager.service: drivers.service spawn failed errno={}",
                    errno(error)
                );
                None
            }
        }
    }

    fn register_driver_delegate(&mut self, process_id: u64) -> bool {
        let mut last_error = sys_error(mochi_user_syscall::ESRCH);
        for _ in 0..DELEGATE_REGISTER_ATTEMPTS {
            match platform::service::register_delegate(
                platform::service::DELEGATE_DRIVER_SPAWN,
                process_id,
            ) {
                Ok(_) => {
                    platform::logln!(
                        "service-manager.service: registered drivers.service as driver delegate"
                    );
                    return true;
                }
                Err(error) => {
                    last_error = error;
                    if errno(error) != mochi_user_syscall::ESRCH {
                        break;
                    }
                    platform::thread::yield_now();
                }
            }
        }
        platform::logln!(
            "service-manager.service: driver delegate registration failed errno={}",
            errno(last_error)
        );
        false
    }

    fn wait_driver_hello(&mut self, process_id: u64) -> bool {
        platform::logln!("service-manager.service: waiting for drivers.service hello");
        match self.driver_controller.wait_for_hello(process_id) {
            Ok(_) => {
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
        match service_launcher::spawn_mboot_agent(self.logger_endpoint, token) {
            Ok(process_id) => {
                self.mboot_agent = Some((process_id, token));
                platform::logln!(
                    "service-manager.service: mboot-agent.service spawned pid={}",
                    process_id
                );
                Some(process_id)
            }
            Err(error) => {
                platform::logln!(
                    "service-manager.service: mboot-agent.service spawn failed errno={}",
                    errno(error)
                );
                None
            }
        }
    }

    fn notify_mboot_stage(&mut self, stage: MbootStage) {
        let Some((process_id, token)) = self.mboot_agent else {
            return;
        };
        let request = platform::service_ready::notification(token, stage as i32);
        let mut reply = [0u8; 4];
        let result = crate::spawn_support::call_with_wait(process_id, &request, &mut reply);
        let valid = result.is_ok_and(|message| {
            (message & 0xffff_ffff) as usize == reply.len() && i32::from_le_bytes(reply) == 0
        });
        if !valid {
            platform::logln!(
                "service-manager.service: mboot-agent stage notification failed stage={}",
                stage as i32
            );
        }
    }

    fn spawn_fixed(&mut self, service: FixedService) -> Option<u64> {
        let ready_target = match service {
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
            | FixedService::Update => None,
        };
        if matches!(service, FixedService::Display) && ready_target.is_none() {
            platform::logln!(
                "service-manager.service: display.driver spawn failed no ready target"
            );
            return None;
        }
        match service_launcher::spawn_fixed_service(service, self.logger_endpoint, ready_target) {
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
        match service_launcher::spawn_user_session(
            service,
            self.logger_endpoint,
            identity,
            session_id,
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

    fn wait_display_ready(&mut self, process_id: u64) -> bool {
        self.wait_ready(ReadyService::Display, process_id)
    }

    fn wait_input_ready(&mut self, process_id: u64) -> bool {
        self.wait_ready(ReadyService::Input, process_id)
    }

    fn wait_user_ready(&mut self, process_id: u64) -> bool {
        self.wait_ready(ReadyService::User, process_id)
    }

    fn wait_secure_ui_login(
        &mut self,
        process_id: u64,
    ) -> Option<platform::service_ready::SessionIdentity> {
        platform::logln!("service-manager.service: waiting for secure-ui.service login");
        let result = match self.ready.as_mut() {
            Some(handshake) => handshake.wait_for_login_complete(process_id),
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

    fn wait_discovery_complete(&mut self, process_id: u64) -> bool {
        match self.driver_controller.wait_for_complete(process_id) {
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

    fn wait_network_ready(&mut self, process_id: u64) -> bool {
        self.wait_ready(ReadyService::Network, process_id)
    }
}

pub(crate) fn run() -> ! {
    platform::logln!("service-manager.service: start");
    let logger_endpoint = platform::logger::endpoint().map_or(0, |endpoint| endpoint);
    let (outcome, runtime) = match Runtime::create(logger_endpoint) {
        Ok(mut runtime) => {
            let outcome = orchestrate(&mut runtime);
            (outcome, Some(runtime))
        }
        Err(error) => {
            platform::logln!(
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
    resident(outcome, runtime)
}

fn service_name(service: FixedService) -> &'static str {
    match service {
        FixedService::MbootAgent => "mboot-agent.service",
        FixedService::Input => "input.service",
        FixedService::Display => "display.driver",
        FixedService::Compositor => "compositor.service",
        FixedService::Network => "network.service",
        FixedService::User => "user.service",
        FixedService::SecureUi => "secure-ui.service",
        FixedService::Linux => "linux.service",
        FixedService::Binder => "Binder.app",
        FixedService::Update => "update.service",
    }
}

fn log_ready_error(service: ReadyService, error: ReadyError) {
    match error {
        ReadyError::InvalidMessage => platform::logln!(
            "service-manager.service: invalid ready message from {}",
            service.name()
        ),
        ReadyError::Failed(status) => platform::logln!(
            "service-manager.service: {} ready failed status={}",
            service.name(),
            status
        ),
        ReadyError::TimedOut => {
            platform::logln!("service-manager.service: {} ready timeout", service.name())
        }
        ReadyError::ProcessExited(status) => platform::logln!(
            "service-manager.service: {} exited before ready status={}",
            service.name(),
            status
        ),
        ReadyError::Ipc(errno) => platform::logln!(
            "service-manager.service: {} ready IPC failed errno={}",
            service.name(),
            errno
        ),
        ReadyError::Clock(errno) => platform::logln!(
            "service-manager.service: {} ready clock failed errno={}",
            service.name(),
            errno
        ),
        ReadyError::ProcessWait(errno) => platform::logln!(
            "service-manager.service: {} ready process wait failed errno={}",
            service.name(),
            errno
        ),
    }
}

fn resident(outcome: BootstrapOutcome, runtime: Option<Runtime>) -> ! {
    let mut runtime = runtime;
    let mut active_session =
        outcome
            .identity
            .zip(outcome.children.binder)
            .map(|(identity, binder_pid)| ActiveSession {
                id: outcome.session_id,
                identity,
                linux_pid: outcome.children.linux,
                binder_pid,
            });
    if active_session.is_some()
        && let Some(runtime) = runtime.as_mut()
    {
        crate::portal::prewarm(&mut runtime.permission_prompt, runtime.logger_endpoint);
    }
    let mut request_bytes = [0u8; 1024];
    loop {
        let received = if let Some(deferred) = runtime
            .as_mut()
            .and_then(|runtime| runtime.deferred_requests.pop_front())
        {
            let length = deferred.bytes.len().min(request_bytes.len());
            request_bytes[..length].copy_from_slice(&deferred.bytes[..length]);
            (deferred.sender << 32) | length as u64
        } else {
            match platform::ipc::try_wait(&mut request_bytes) {
                Ok(received) => received,
                Err(error) if error.raw() == mochi_user_syscall::EAGAIN as i64 => {
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
            if let Some(runtime) = runtime.as_mut() {
                crate::portal::handle(
                    message,
                    sender,
                    active_session,
                    runtime.logger_endpoint,
                    &mut runtime.permission_prompt,
                );
            } else {
                let mut prompt = None;
                crate::portal::handle(message, sender, active_session, 0, &mut prompt);
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
                -(mochi_user_syscall::EINVAL as i32),
            );
            continue;
        };
        let Some(session) = active_session else {
            reply_session_status(
                sender,
                request.action,
                request.session_id,
                -(mochi_user_syscall::EPERM as i32),
            );
            continue;
        };
        let sender_process = platform::ipc::endpoint_owner_process(sender).ok();
        if sender_process != Some(session.binder_pid) || request.session_id != session.id {
            reply_session_status(
                sender,
                request.action,
                request.session_id,
                -(mochi_user_syscall::EPERM as i32),
            );
            continue;
        }
        let Some(runtime) = runtime.as_mut() else {
            reply_session_status(
                sender,
                request.action,
                request.session_id,
                -(mochi_user_syscall::EIO as i32),
            );
            continue;
        };
        match request.action {
            platform::session_control::Action::Lock => {
                let status = match runtime.authenticate_session(Some(session.identity.uid)) {
                    Some(identity) if identity == session.identity => 0,
                    Some(_) => -(mochi_user_syscall::EACCES as i32),
                    None => -(mochi_user_syscall::EIO as i32),
                };
                reply_session_status(sender, request.action, session.id, status);
            }
            platform::session_control::Action::LogOut => {
                reply_session_status(sender, request.action, session.id, 0);
                active_session = None;
                if let Err(error) = terminate_process_tree(session.binder_pid) {
                    platform::logln!(
                        "service-manager.service: session termination failed errno={}",
                        errno(error)
                    );
                }
                if let Some(linux_pid) = session.linux_pid {
                    let _ = terminate_process_tree(linux_pid);
                }
                let Some(identity) = runtime.authenticate_session(None) else {
                    continue;
                };
                let session_id = session.next_id();
                let linux_pid = service_launcher::spawn_user_session(
                    FixedService::Linux,
                    runtime.logger_endpoint,
                    identity,
                    session_id,
                )
                .ok();
                match service_launcher::spawn_user_session(
                    FixedService::Binder,
                    runtime.logger_endpoint,
                    identity,
                    session_id,
                ) {
                    Ok(binder_pid) => {
                        active_session = Some(ActiveSession {
                            id: session_id,
                            identity,
                            linux_pid,
                            binder_pid,
                        });
                    }
                    Err(error) => platform::logln!(
                        "service-manager.service: Binder.app spawn failed errno={}",
                        errno(error)
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
