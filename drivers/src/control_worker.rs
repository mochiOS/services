use mochi_user_platform as platform;
use mochios_driver_control_protocol::{
    DISCOVERY_COMPLETE_LEN, DRIVER_HELLO_LEN, DiscoveryComplete, EncodeError,
};

use crate::bootstrap;
use crate::control_state::{ControlAction, DiscoveryController, driver_hello};
use crate::readiness;
use crate::startup_args::DriverManagerConfig;

const CONTROL_BUFFER_LEN: usize = DRIVER_HELLO_LEN;

pub(crate) fn run(config: DriverManagerConfig) -> ! {
    platform::println!("drivers.service: start");
    let logger_endpoint = match platform::logger::endpoint() {
        Some(endpoint) => endpoint,
        None => 0,
    };
    let control_endpoint = match platform::ipc::create() {
        Ok(endpoint) => endpoint,
        Err(err) => {
            let errno = match err.errno() {
                Some(errno) => errno,
                None => 0,
            };
            platform::println!(
                "drivers.service: control endpoint create failed errno={}",
                errno
            );
            readiness::idle()
        }
    };
    let request_id = match platform::service_ready::generate_token() {
        Ok(request_id) => request_id,
        Err(err) => {
            let errno = match err.errno() {
                Some(errno) => errno,
                None => 0,
            };
            platform::println!(
                "drivers.service: hello request id generation failed errno={}",
                errno
            );
            readiness::idle()
        }
    };
    if let Err(error) = send_hello(config, control_endpoint, request_id) {
        log_send_error("hello", error);
        readiness::idle()
    }

    let mut controller = DiscoveryController::new(config.token);
    let mut buffer = [0u8; CONTROL_BUFFER_LEN];
    loop {
        let message = match platform::ipc::wait(control_endpoint, &mut buffer) {
            Ok(message) => message,
            Err(_) => {
                platform::thread::yield_now();
                continue;
            }
        };
        let len = (message & 0xffff_ffff) as usize;
        let Some(bytes) = buffer.get(..len) else {
            continue;
        };
        match controller.handle_message(bytes) {
            ControlAction::Ignore => {}
            ControlAction::Reply {
                response_endpoint,
                message,
            } => send_complete(response_endpoint, message),
            ControlAction::Run(pending) => {
                let result = bootstrap::run_driver_discovery(logger_endpoint, || {
                    drain_running_requests(&mut controller)
                });
                drain_running_requests(&mut controller);
                if let ControlAction::Reply {
                    response_endpoint,
                    message,
                } = controller.complete(pending, result)
                {
                    send_complete(response_endpoint, message);
                }
            }
        }
    }
}

fn send_hello(
    config: DriverManagerConfig,
    control_endpoint: u64,
    request_id: u64,
) -> Result<(), SendError> {
    let hello = driver_hello(request_id, config.token, control_endpoint);
    let mut buffer = [0u8; DRIVER_HELLO_LEN];
    let len = hello.encode(&mut buffer).map_err(SendError::Encode)?;
    platform::ipc::send(config.endpoint, &buffer[..len])
        .map(|_| ())
        .map_err(|err| SendError::Ipc(err.raw().unsigned_abs()))
}

fn send_complete(response_endpoint: u64, message: DiscoveryComplete) {
    let mut buffer = [0u8; DISCOVERY_COMPLETE_LEN];
    let len = match message.encode(&mut buffer) {
        Ok(len) => len,
        Err(error) => {
            log_send_error("discovery complete encode", SendError::Encode(error));
            return;
        }
    };
    if let Err(err) = platform::ipc::send(response_endpoint, &buffer[..len]) {
        log_send_error(
            "discovery complete",
            SendError::Ipc(err.raw().unsigned_abs()),
        );
    }
}

fn drain_running_requests(controller: &mut DiscoveryController) {
    let mut buffer = [0u8; CONTROL_BUFFER_LEN];
    loop {
        let message = match platform::ipc::try_wait(&mut buffer) {
            Ok(message) => message,
            Err(err) if err.raw() == mochi_user_syscall::EAGAIN as i64 => return,
            Err(_) => return,
        };
        let len = (message & 0xffff_ffff) as usize;
        let Some(bytes) = buffer.get(..len) else {
            continue;
        };
        if let ControlAction::Reply {
            response_endpoint,
            message,
        } = controller.handle_message(bytes)
        {
            send_complete(response_endpoint, message);
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SendError {
    Encode(EncodeError),
    Ipc(u64),
}

fn log_send_error(operation: &str, error: SendError) {
    match error {
        SendError::Encode(error) => {
            platform::println!("drivers.service: {} failed error={:?}", operation, error)
        }
        SendError::Ipc(errno) => {
            platform::println!("drivers.service: {} failed errno={}", operation, errno)
        }
    }
}
