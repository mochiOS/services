#[cfg(not(test))]
use mochi_user_platform as platform;
#[cfg(not(test))]
use mochios_driver_control_protocol::START_DISCOVERY_LEN;
use mochios_driver_control_protocol::{
    DRIVER_HELLO_LEN, DecodeError, EncodeError, Message, StartDiscovery,
};

#[cfg(not(test))]
use crate::fixed_service_launcher::DriverManagerTarget;

pub(crate) const DRIVER_CONTROL_TIMEOUT_TICKS: u64 = 5_000;
#[cfg(not(test))]
const WAIT_NO_HANG: u64 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DriverSessionState {
    WaitingHello,
    Ready {
        control_endpoint: u64,
    },
    WaitingComplete {
        control_endpoint: u64,
        request_id: u64,
    },
    Complete,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DriverControlError {
    InvalidState,
    UnexpectedMessage,
    TokenMismatch,
    RequestIdMismatch,
    DiscoveryFailed(i32),
    Protocol(DecodeError),
    Encode(EncodeError),
    Ipc(u64),
    Clock(u64),
    ProcessWait(u64),
    ProcessExited(i32),
    TimedOut,
}

pub(crate) struct DriverSession {
    token: u64,
    state: DriverSessionState,
}

impl DriverSession {
    pub(crate) const fn new(token: u64) -> Self {
        Self {
            token,
            state: DriverSessionState::WaitingHello,
        }
    }

    #[cfg(test)]
    pub(crate) const fn state(&self) -> DriverSessionState {
        self.state
    }

    pub(crate) fn accept_hello(&mut self, bytes: &[u8]) -> Result<u64, DriverControlError> {
        if self.state != DriverSessionState::WaitingHello {
            return Err(DriverControlError::InvalidState);
        }
        let message = Message::decode(bytes).map_err(DriverControlError::Protocol)?;
        let Message::DriverHello(hello) = message else {
            return Err(DriverControlError::UnexpectedMessage);
        };
        if hello.token != self.token {
            return Err(DriverControlError::TokenMismatch);
        }
        self.state = DriverSessionState::Ready {
            control_endpoint: hello.control_endpoint,
        };
        Ok(hello.control_endpoint)
    }

    pub(crate) fn start_request(
        &mut self,
        request_id: u64,
        response_endpoint: u64,
    ) -> Result<StartDiscovery, DriverControlError> {
        let DriverSessionState::Ready { control_endpoint } = self.state else {
            return Err(DriverControlError::InvalidState);
        };
        self.state = DriverSessionState::WaitingComplete {
            control_endpoint,
            request_id,
        };
        Ok(StartDiscovery {
            request_id,
            token: self.token,
            response_endpoint,
        })
    }

    pub(crate) fn control_endpoint(&self) -> Result<u64, DriverControlError> {
        match self.state {
            DriverSessionState::Ready { control_endpoint }
            | DriverSessionState::WaitingComplete {
                control_endpoint, ..
            } => Ok(control_endpoint),
            _ => Err(DriverControlError::InvalidState),
        }
    }

    pub(crate) fn accept_complete(&mut self, bytes: &[u8]) -> Result<(), DriverControlError> {
        let DriverSessionState::WaitingComplete { request_id, .. } = self.state else {
            return Err(DriverControlError::InvalidState);
        };
        let message = Message::decode(bytes).map_err(DriverControlError::Protocol)?;
        let Message::DiscoveryComplete(complete) = message else {
            return Err(DriverControlError::UnexpectedMessage);
        };
        if complete.request_id != request_id {
            return Err(DriverControlError::RequestIdMismatch);
        }
        self.state = DriverSessionState::Complete;
        if complete.status != 0 {
            return Err(DriverControlError::DiscoveryFailed(complete.status));
        }
        Ok(())
    }
}

#[cfg(not(test))]
pub(crate) struct DriverController {
    manager_endpoint: u64,
    response_endpoint: Option<u64>,
    session: DriverSession,
}

#[cfg(not(test))]
impl DriverController {
    pub(crate) fn create() -> Result<Self, DriverControlError> {
        let manager_endpoint = platform::ipc::create()
            .map_err(|error| DriverControlError::Ipc(error.raw().unsigned_abs()))?;
        let token = platform::service_ready::generate_token()
            .map_err(|error| DriverControlError::Ipc(error.raw().unsigned_abs()))?;
        Ok(Self {
            manager_endpoint,
            response_endpoint: None,
            session: DriverSession::new(token),
        })
    }

    pub(crate) const fn target(&self) -> DriverManagerTarget {
        DriverManagerTarget {
            endpoint: self.manager_endpoint,
            token: self.session.token,
        }
    }

    pub(crate) fn wait_for_hello(
        &mut self,
        drivers_process: u64,
    ) -> Result<u64, DriverControlError> {
        let mut buffer = [0u8; DRIVER_HELLO_LEN];
        let length = wait_for_message(drivers_process, &mut buffer)?;
        self.session.accept_hello(&buffer[..length])
    }

    pub(crate) fn start_discovery(&mut self) -> Result<(), DriverControlError> {
        let response_endpoint = platform::ipc::create()
            .map_err(|error| DriverControlError::Ipc(error.raw().unsigned_abs()))?;
        let request_id = platform::service_ready::generate_token()
            .map_err(|error| DriverControlError::Ipc(error.raw().unsigned_abs()))?;
        let control_endpoint = self.session.control_endpoint()?;
        let request = self.session.start_request(request_id, response_endpoint)?;
        self.response_endpoint = Some(response_endpoint);
        let mut buffer = [0u8; START_DISCOVERY_LEN];
        let length = request
            .encode(&mut buffer)
            .map_err(DriverControlError::Encode)?;
        platform::ipc::send(control_endpoint, &buffer[..length])
            .map(|_| ())
            .map_err(|error| DriverControlError::Ipc(error.raw().unsigned_abs()))
    }

    pub(crate) fn wait_for_complete(
        &mut self,
        drivers_process: u64,
    ) -> Result<(), DriverControlError> {
        let mut buffer = [0u8; DRIVER_HELLO_LEN];
        let length = wait_for_message(drivers_process, &mut buffer)?;
        self.session.accept_complete(&buffer[..length])
    }
}

#[cfg(not(test))]
fn wait_for_message(process_id: u64, buffer: &mut [u8]) -> Result<usize, DriverControlError> {
    let started = current_ticks()?;
    loop {
        match platform::ipc::try_wait(buffer) {
            Ok(message) => {
                let length = (message & 0xffff_ffff) as usize;
                return if length <= buffer.len() {
                    Ok(length)
                } else {
                    Err(DriverControlError::UnexpectedMessage)
                };
            }
            Err(error) if error.raw() == mochi_user_syscall::EAGAIN as i64 => {}
            Err(error) => return Err(DriverControlError::Ipc(error.raw().unsigned_abs())),
        }
        if let Some(status) = process_exit_status(process_id)? {
            return Err(DriverControlError::ProcessExited(status));
        }
        let now = current_ticks()?;
        if now.saturating_sub(started) >= DRIVER_CONTROL_TIMEOUT_TICKS {
            return Err(DriverControlError::TimedOut);
        }
        platform::thread::yield_now();
    }
}

#[cfg(not(test))]
fn current_ticks() -> Result<u64, DriverControlError> {
    platform::time::ticks().map_err(|error| DriverControlError::Clock(error.raw().unsigned_abs()))
}

#[cfg(not(test))]
fn process_exit_status(process_id: u64) -> Result<Option<i32>, DriverControlError> {
    let mut status = 0i32;
    match platform::process::wait(
        process_id as i64,
        core::ptr::addr_of_mut!(status) as u64,
        WAIT_NO_HANG,
    ) {
        Ok(0) => Ok(None),
        Ok(_) => Ok(Some(status)),
        Err(error) => Err(DriverControlError::ProcessWait(error.raw().unsigned_abs())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mochios_driver_control_protocol::{DISCOVERY_COMPLETE_LEN, DiscoveryComplete, DriverHello};

    fn hello_bytes(token: u64, control_endpoint: u64) -> [u8; DRIVER_HELLO_LEN] {
        let hello = DriverHello {
            request_id: 41,
            token,
            control_endpoint,
        };
        let mut bytes = [0u8; DRIVER_HELLO_LEN];
        assert_eq!(hello.encode(&mut bytes), Ok(DRIVER_HELLO_LEN));
        bytes
    }

    #[test]
    fn hello_validates_token_and_records_control_endpoint() {
        let mut session = DriverSession::new(55);
        assert_eq!(session.accept_hello(&hello_bytes(55, 77)), Ok(77));
        assert_eq!(
            session.state(),
            DriverSessionState::Ready {
                control_endpoint: 77,
            }
        );

        let mut wrong_token = DriverSession::new(55);
        assert_eq!(
            wrong_token.accept_hello(&hello_bytes(54, 77)),
            Err(DriverControlError::TokenMismatch)
        );
        assert_eq!(wrong_token.state(), DriverSessionState::WaitingHello);
    }

    #[test]
    fn start_request_contains_request_id_token_and_response_endpoint_once() {
        let mut session = DriverSession::new(55);
        assert_eq!(session.accept_hello(&hello_bytes(55, 77)), Ok(77));
        let request = match session.start_request(101, 202) {
            Ok(request) => request,
            Err(error) => panic!("start request failed: {error:?}"),
        };
        assert_eq!(request.request_id, 101);
        assert_eq!(request.token, 55);
        assert_eq!(request.response_endpoint, 202);
        assert_eq!(session.control_endpoint(), Ok(77));
        assert_eq!(
            session.start_request(102, 203),
            Err(DriverControlError::InvalidState)
        );
    }

    #[test]
    fn completion_requires_matching_request_id_and_zero_status() {
        let mut session = DriverSession::new(55);
        assert_eq!(session.accept_hello(&hello_bytes(55, 77)), Ok(77));
        assert!(session.start_request(101, 202).is_ok());

        let mut wrong_id = [0u8; DISCOVERY_COMPLETE_LEN];
        let complete = DiscoveryComplete {
            request_id: 102,
            status: 0,
        };
        assert_eq!(complete.encode(&mut wrong_id), Ok(DISCOVERY_COMPLETE_LEN));
        assert_eq!(
            session.accept_complete(&wrong_id),
            Err(DriverControlError::RequestIdMismatch)
        );

        let mut failed = [0u8; DISCOVERY_COMPLETE_LEN];
        let complete = DiscoveryComplete {
            request_id: 101,
            status: -16,
        };
        assert_eq!(complete.encode(&mut failed), Ok(DISCOVERY_COMPLETE_LEN));
        assert_eq!(
            session.accept_complete(&failed),
            Err(DriverControlError::DiscoveryFailed(-16))
        );
        assert_eq!(session.state(), DriverSessionState::Complete);
    }

    #[test]
    fn malformed_and_unknown_messages_are_not_accepted() {
        let mut session = DriverSession::new(55);
        assert!(matches!(
            session.accept_hello(b"invalid"),
            Err(DriverControlError::Protocol(_))
        ));
        assert_eq!(session.state(), DriverSessionState::WaitingHello);

        let mut unknown = hello_bytes(55, 77);
        unknown[6..8].copy_from_slice(&0x7777u16.to_le_bytes());
        assert!(matches!(
            session.accept_hello(&unknown),
            Err(DriverControlError::Protocol(_))
        ));
        assert_eq!(session.state(), DriverSessionState::WaitingHello);
    }
}
