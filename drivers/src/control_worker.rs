use mochi_user_platform as platform;
use mochios_driver_control_protocol::{
    DISCOVERY_COMPLETE_LEN, DRIVER_HELLO_LEN, DiscoveryComplete, EncodeError,
};

use crate::control_state::{ControlAction, DiscoveryController, driver_hello};
use crate::discovery;
use crate::startup_args::DriverManagerConfig;

const CONTROL_BUFFER_LEN: usize = DRIVER_HELLO_LEN;

pub(crate) fn run(config: DriverManagerConfig) -> ! {
    platform::logln!("drivers.service: start");
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
            platform::logln!(
                "drivers.service: control endpoint create failed errno={}",
                errno
            );
            idle()
        }
    };
    let request_id = match platform::service_ready::generate_token() {
        Ok(request_id) => request_id,
        Err(err) => {
            let errno = match err.errno() {
                Some(errno) => errno,
                None => 0,
            };
            platform::logln!(
                "drivers.service: hello request id generation failed errno={}",
                errno
            );
            idle()
        }
    };
    if let Err(error) = send_hello(config, control_endpoint, request_id) {
        log_send_error("hello", error);
        idle()
    }

    let mut controller = DiscoveryController::new(config.token);
    let posix_endpoint =
        match platform::handle::inherited(mochios_posix_protocol::CONTROL_HANDLE_KEY) {
            Ok(endpoint) if endpoint != 0 => endpoint,
            _ => {
                platform::logln!("drivers.service: inherited POSIX endpoint missing");
                idle()
            }
        };
    let mut started_drivers = crate::driver_registry::StartedDrivers::new();
    let mut buffer = [0u8; CONTROL_BUFFER_LEN];
    loop {
        started_drivers.retry_failed(posix_endpoint);
        let mut attached = ReceivedHandles(platform::ipc::IpcObjectHandles::default());
        let incoming = if started_drivers.has_failed_cleanup() {
            platform::ipc::try_wait_object_handles(&mut buffer, &mut attached.0)
        } else {
            platform::ipc::wait_object_handles(control_endpoint, &mut buffer, &mut attached.0)
        };
        let message = match incoming {
            Ok(message) => message,
            Err(_) => {
                let _ = platform::thread::sleep_milliseconds(10);
                continue;
            }
        };
        if !attached.0.is_user_delivery() || !is_manager_request(message >> 32) {
            continue;
        }
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
                let result = if let Some(raw_input) = attached.raw_input() {
                    discovery::run(
                        logger_endpoint,
                        posix_endpoint,
                        raw_input,
                        &mut started_drivers,
                        || drain_running_requests(&mut controller),
                    )
                } else {
                    mochios_driver_control_protocol::DiscoveryResult { status: -13 }
                };
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

pub(crate) fn idle() -> ! {
    loop {
        platform::thread::yield_now();
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

fn is_manager_request(sender: u64) -> bool {
    crate::control_authorization::manager_request(sender, |endpoint| {
        platform::capability::check_thread(endpoint, "capabilities.manage") == Ok(1)
    })
}

fn drain_running_requests(controller: &mut DiscoveryController) {
    let mut buffer = [0u8; CONTROL_BUFFER_LEN];
    loop {
        let mut attached = ReceivedHandles(platform::ipc::IpcObjectHandles::default());
        let message = match platform::ipc::try_wait_object_handles(&mut buffer, &mut attached.0) {
            Ok(message) => message,
            Err(err)
                if err.native_error() == Some(mochi_user_syscall::NativeError::NotReady) =>
            {
                return;
            }
            Err(_) => return,
        };
        if !attached.0.is_user_delivery() || !is_manager_request(message >> 32) {
            continue;
        }
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
            platform::logln!("drivers.service: {} failed error={:?}", operation, error)
        }
        SendError::Ipc(errno) => {
            platform::logln!("drivers.service: {} failed errno={}", operation, errno)
        }
    }
}

// The request owns received references until discovery has finished creating
// children. Every malformed, unauthorized and duplicate request also drops them.
struct ReceivedHandles(platform::ipc::IpcObjectHandles);
impl ReceivedHandles {
    fn raw_input(&self) -> Option<u32> {
        let expected = platform::handle::HANDLE_RIGHT_SEND
            | platform::handle::HANDLE_RIGHT_DUPLICATE
            | platform::handle::HANDLE_RIGHT_TRANSFER;
        let entry = self.0.handles[0];
        (self.0.is_user_delivery()
            && self.0.count == 1
            && entry.handle != 0
            && entry.reserved == 0
            && entry.rights == expected)
            .then_some(entry.handle)
    }
}
impl Drop for ReceivedHandles {
    fn drop(&mut self) {
        for entry in self.0.handles.iter().take(self.0.count as usize) {
            if entry.handle != 0 {
                let _ = platform::handle::close(entry.handle);
            }
        }
    }
}
