use mochi_user_platform as platform;

use crate::service_config::SERVICE_READY_TIMEOUT_TICKS;
const WAIT_NO_HANG: u64 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ReadyService {
    Input,
    Display,
    Network,
    User,
}

impl ReadyService {
    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::Input => "input.service",
            Self::Display => "display.driver",
            Self::Network => "network.service",
            Self::User => "user.service",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ReadyError {
    InvalidMessage,
    Failed(i32),
    TimedOut,
    ProcessExited(i32),
    Ipc(u64),
    Clock(u64),
    ProcessWait(u64),
}

pub(crate) struct ReadyHandshake {
    endpoint: u64,
    input_token: u64,
    display_token: u64,
    network_token: u64,
    user_token: u64,
    input_status: platform::service_ready::OneShotStatus,
    display_status: platform::service_ready::OneShotStatus,
    network_status: platform::service_ready::OneShotStatus,
    user_status: platform::service_ready::OneShotStatus,
}

impl ReadyHandshake {
    pub(crate) fn create() -> Result<Self, ReadyError> {
        let endpoint =
            platform::ipc::create().map_err(|error| ReadyError::Ipc(error.raw().unsigned_abs()))?;
        let input_token = platform::service_ready::generate_token()
            .map_err(|error| ReadyError::Ipc(error.raw().unsigned_abs()))?;
        let mut display_token = platform::service_ready::generate_token()
            .map_err(|error| ReadyError::Ipc(error.raw().unsigned_abs()))?;
        if display_token == input_token {
            display_token ^= 0xa5a5_5a5a_d3c3_3c3c;
            if display_token == 0 {
                display_token = 1;
            }
        }
        let mut network_token = platform::service_ready::generate_token()
            .map_err(|error| ReadyError::Ipc(error.raw().unsigned_abs()))?;
        if network_token == input_token || network_token == display_token {
            network_token ^= 0x3c3c_c3c3_5a5a_a5a5;
            if network_token == 0 {
                network_token = 1;
            }
        }
        let mut user_token = platform::service_ready::generate_token()
            .map_err(|error| ReadyError::Ipc(error.raw().unsigned_abs()))?;
        if user_token == input_token || user_token == display_token || user_token == network_token {
            user_token ^= 0x9696_6969_c3c3_3c3c;
            if user_token == 0 {
                user_token = 1;
            }
        }
        Ok(Self {
            endpoint,
            input_token,
            display_token,
            network_token,
            user_token,
            input_status: platform::service_ready::OneShotStatus::new(),
            display_status: platform::service_ready::OneShotStatus::new(),
            network_status: platform::service_ready::OneShotStatus::new(),
            user_status: platform::service_ready::OneShotStatus::new(),
        })
    }

    pub(crate) const fn target(&self, service: ReadyService) -> platform::service_ready::Target {
        let token = match service {
            ReadyService::Input => self.input_token,
            ReadyService::Display => self.display_token,
            ReadyService::Network => self.network_token,
            ReadyService::User => self.user_token,
        };
        platform::service_ready::Target {
            endpoint: self.endpoint,
            token,
        }
    }

    fn status(&self, service: ReadyService) -> Option<i32> {
        match service {
            ReadyService::Input => self.input_status.get(),
            ReadyService::Display => self.display_status.get(),
            ReadyService::Network => self.network_status.get(),
            ReadyService::User => self.user_status.get(),
        }
    }

    fn record(&mut self, token: u64, status: i32) -> Result<(), ReadyError> {
        let slot = if token == self.input_token {
            &mut self.input_status
        } else if token == self.display_token {
            &mut self.display_status
        } else if token == self.network_token {
            &mut self.network_status
        } else if token == self.user_token {
            &mut self.user_status
        } else {
            return Err(ReadyError::InvalidMessage);
        };
        let _ = slot.record(status);
        Ok(())
    }

    pub(crate) fn wait_for_service_ready(
        &mut self,
        service: ReadyService,
        process_id: u64,
    ) -> Result<(), ReadyError> {
        let started = current_ticks()?;
        loop {
            if let Some(status) = self.status(service) {
                return ready_result(status);
            }
            if let Some((token, status)) = receive_notification()? {
                self.record(token, status)?;
            }
            if let Some(status) = self.status(service) {
                return ready_result(status);
            }
            if let Some(status) = process_exit_status(process_id)? {
                return Err(ReadyError::ProcessExited(status));
            }
            let now = current_ticks()?;
            if now.saturating_sub(started) >= SERVICE_READY_TIMEOUT_TICKS {
                return Err(ReadyError::TimedOut);
            }
            platform::thread::yield_now();
        }
    }
}

fn ready_result(status: i32) -> Result<(), ReadyError> {
    if status == 0 {
        Ok(())
    } else {
        Err(ReadyError::Failed(status))
    }
}

#[inline(never)]
fn receive_notification() -> Result<Option<(u64, i32)>, ReadyError> {
    let mut message = [0u8; platform::service_ready::MESSAGE_LEN];
    let received = match platform::ipc::try_wait(&mut message) {
        Ok(received) => received,
        Err(error) if error.raw() == mochi_user_syscall::EAGAIN as i64 => return Ok(None),
        Err(error) => return Err(ReadyError::Ipc(error.raw().unsigned_abs())),
    };
    let length = (received & 0xffff_ffff) as usize;
    let Some(message) = message.get(..length) else {
        return Err(ReadyError::InvalidMessage);
    };
    let notification = platform::service_ready::decode_notification(message)
        .map_err(|_| ReadyError::InvalidMessage)?;
    Ok(Some(notification))
}

#[inline(never)]
fn current_ticks() -> Result<u64, ReadyError> {
    platform::time::ticks().map_err(|error| ReadyError::Clock(error.raw().unsigned_abs()))
}

#[inline(never)]
fn process_exit_status(process_id: u64) -> Result<Option<i32>, ReadyError> {
    let mut status = 0i32;
    match platform::process::wait(
        process_id as i64,
        core::ptr::addr_of_mut!(status) as u64,
        WAIT_NO_HANG,
    ) {
        Ok(0) => Ok(None),
        Ok(_) => Ok(Some(status)),
        Err(error) => Err(ReadyError::ProcessWait(error.raw().unsigned_abs())),
    }
}
