use mochi_user_platform as platform;

use crate::driver_controller::{DriverControlError, DriverController};
use crate::fixed_service_launcher;
use crate::orchestration::{BootstrapOperations, BootstrapOutcome, orchestrate};
use crate::readiness::{ReadyError, ReadyHandshake, ReadyService};
use crate::service_config::FixedService;
use crate::spawn_support::{errno, sys_error};

const DELEGATE_REGISTER_ATTEMPTS: usize = 32;

struct Runtime {
    logger_endpoint: u64,
    driver_controller: DriverController,
    ready: Option<ReadyHandshake>,
}

impl Runtime {
    fn create(logger_endpoint: u64) -> Result<Self, DriverControlError> {
        Ok(Self {
            logger_endpoint,
            driver_controller: DriverController::create()?,
            ready: None,
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
                platform::println!(
                    "service-manager.service: ready handshake create failed error={:?}",
                    error
                );
                false
            }
        }
    }

    fn wait_ready(&mut self, service: ReadyService, process_id: u64) -> bool {
        platform::println!(
            "service-manager.service: waiting for {} ready",
            service.name()
        );
        let result = match self.ready.as_mut() {
            Some(handshake) => handshake.wait_for_service_ready(service, process_id),
            None => Err(ReadyError::InvalidMessage),
        };
        if service == ReadyService::Network {
            self.ready = None;
        }
        match result {
            Ok(()) => {
                platform::println!("service-manager.service: {} ready", service.name());
                true
            }
            Err(error) => {
                log_ready_error(service, error);
                false
            }
        }
    }
}

impl BootstrapOperations for Runtime {
    fn spawn_drivers(&mut self) -> Option<u64> {
        match fixed_service_launcher::spawn_drivers(
            self.logger_endpoint,
            self.driver_controller.target(),
        ) {
            Ok(process_id) => {
                platform::println!(
                    "service-manager.service: drivers.service spawned pid={}",
                    process_id
                );
                Some(process_id)
            }
            Err(error) => {
                platform::println!(
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
                    platform::println!(
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
        platform::println!(
            "service-manager.service: driver delegate registration failed errno={}",
            errno(last_error)
        );
        false
    }

    fn wait_driver_hello(&mut self, process_id: u64) -> bool {
        platform::println!("service-manager.service: waiting for drivers.service hello");
        match self.driver_controller.wait_for_hello(process_id) {
            Ok(_) => {
                platform::println!("service-manager.service: drivers.service hello received");
                true
            }
            Err(error) => {
                platform::println!(
                    "service-manager.service: drivers.service hello failed error={:?}",
                    error
                );
                false
            }
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
            FixedService::Compositor | FixedService::Binder | FixedService::Update => None,
        };
        if matches!(service, FixedService::Display) && ready_target.is_none() {
            platform::println!(
                "service-manager.service: display.driver spawn failed no ready target"
            );
            return None;
        }
        match fixed_service_launcher::spawn_fixed_service(
            service,
            self.logger_endpoint,
            ready_target,
        ) {
            Ok(process_id) => {
                platform::println!(
                    "service-manager.service: {} spawned pid={}",
                    service_name(service),
                    process_id
                );
                Some(process_id)
            }
            Err(error) => {
                platform::println!(
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

    fn start_discovery(&mut self) -> bool {
        match self.driver_controller.start_discovery() {
            Ok(()) => {
                platform::println!("service-manager.service: driver discovery requested");
                true
            }
            Err(error) => {
                platform::println!(
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
                platform::println!("service-manager.service: driver discovery complete");
                true
            }
            Err(error) => {
                platform::println!(
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
    platform::println!("service-manager.service: start");
    let logger_endpoint = platform::logger::endpoint().map_or(0, |endpoint| endpoint);
    let (outcome, runtime) = match Runtime::create(logger_endpoint) {
        Ok(mut runtime) => {
            let outcome = orchestrate(&mut runtime);
            (outcome, Some(runtime))
        }
        Err(error) => {
            platform::println!(
                "service-manager.service: driver controller create failed error={:?}",
                error
            );
            (BootstrapOutcome::initialization_failed(), None)
        }
    };
    platform::println!(
        "service-manager.service: resident phase reason={:?}",
        outcome.reason
    );
    resident(outcome, runtime)
}

fn service_name(service: FixedService) -> &'static str {
    match service {
        FixedService::Input => "input.service",
        FixedService::Display => "display.driver",
        FixedService::Compositor => "compositor.service",
        FixedService::Network => "network.service",
        FixedService::Binder => "Binder.app",
        FixedService::Update => "update.service",
    }
}

fn log_ready_error(service: ReadyService, error: ReadyError) {
    match error {
        ReadyError::InvalidMessage => platform::println!(
            "service-manager.service: invalid ready message from {}",
            service.name()
        ),
        ReadyError::Failed(status) => platform::println!(
            "service-manager.service: {} ready failed status={}",
            service.name(),
            status
        ),
        ReadyError::TimedOut => {
            platform::println!("service-manager.service: {} ready timeout", service.name())
        }
        ReadyError::ProcessExited(status) => platform::println!(
            "service-manager.service: {} exited before ready status={}",
            service.name(),
            status
        ),
        ReadyError::Ipc(errno) => platform::println!(
            "service-manager.service: {} ready IPC failed errno={}",
            service.name(),
            errno
        ),
        ReadyError::Clock(errno) => platform::println!(
            "service-manager.service: {} ready clock failed errno={}",
            service.name(),
            errno
        ),
        ReadyError::ProcessWait(errno) => platform::println!(
            "service-manager.service: {} ready process wait failed errno={}",
            service.name(),
            errno
        ),
    }
}

fn resident(_outcome: BootstrapOutcome, _runtime: Option<Runtime>) -> ! {
    loop {
        platform::thread::yield_now();
    }
}
