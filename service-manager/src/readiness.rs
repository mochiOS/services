use alloc::collections::VecDeque;
use alloc::vec::Vec;
use mochi_user_platform as platform;

use crate::service_config::{NETWORK_READY_TIMEOUT_TICKS, SERVICE_READY_TIMEOUT_TICKS};
const WAIT_NO_HANG: u64 = 1;
const BOOTSTRAP_MESSAGE_LEN: usize = 1024;

pub(crate) struct DeferredMessage {
    pub(crate) sender: u64,
    pub(crate) bytes: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ReadyService {
    Input,
    Display,
    Network,
    User,
    SecureUi,
}

impl ReadyService {
    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::Input => "input.service",
            Self::Display => "display.driver",
            Self::Network => "network.service",
            Self::User => "user.service",
            Self::SecureUi => "secure-ui.service",
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
    secure_ui_token: u64,
    input_status: platform::service_ready::OneShotStatus,
    display_status: platform::service_ready::OneShotStatus,
    network_status: platform::service_ready::OneShotStatus,
    user_status: platform::service_ready::OneShotStatus,
    secure_ui_status: platform::service_ready::OneShotStatus,
    deferred: VecDeque<DeferredMessage>,
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
        let mut secure_ui_token = platform::service_ready::generate_token()
            .map_err(|error| ReadyError::Ipc(error.raw().unsigned_abs()))?;
        if secure_ui_token == input_token
            || secure_ui_token == display_token
            || secure_ui_token == network_token
            || secure_ui_token == user_token
        {
            secure_ui_token ^= 0x5a5a_a5a5_9696_6969;
            if secure_ui_token == 0 {
                secure_ui_token = 1;
            }
        }
        Ok(Self {
            endpoint,
            input_token,
            display_token,
            network_token,
            user_token,
            secure_ui_token,
            input_status: platform::service_ready::OneShotStatus::new(),
            display_status: platform::service_ready::OneShotStatus::new(),
            network_status: platform::service_ready::OneShotStatus::new(),
            user_status: platform::service_ready::OneShotStatus::new(),
            secure_ui_status: platform::service_ready::OneShotStatus::new(),
            deferred: VecDeque::new(),
        })
    }

    pub(crate) fn take_deferred(&mut self) -> VecDeque<DeferredMessage> {
        core::mem::take(&mut self.deferred)
    }

    pub(crate) const fn target(&self, service: ReadyService) -> platform::service_ready::Target {
        let token = match service {
            ReadyService::Input => self.input_token,
            ReadyService::Display => self.display_token,
            ReadyService::Network => self.network_token,
            ReadyService::User => self.user_token,
            ReadyService::SecureUi => self.secure_ui_token,
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
            ReadyService::SecureUi => self.secure_ui_status.get(),
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
        } else if token == self.secure_ui_token {
            &mut self.secure_ui_status
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
        self.wait(service, process_id, true)
    }

    pub(crate) fn wait_for_login_complete(
        &mut self,
        process_id: u64,
    ) -> Result<platform::service_ready::SessionIdentity, ReadyError> {
        loop {
            if let Some(notification) = receive_notification()? {
                match notification {
                    ReceivedNotification::Ready { token, status } => {
                        self.record(token, status)?;
                    }
                    ReceivedNotification::Session {
                        token,
                        status,
                        identity,
                    } => {
                        if token != self.secure_ui_token {
                            return Err(ReadyError::InvalidMessage);
                        }
                        ready_result(status)?;
                        return Ok(identity);
                    }
                    ReceivedNotification::Deferred(message) => {
                        self.deferred.push_back(message);
                    }
                }
            }
            if let Some(status) = process_exit_status(process_id)? {
                return Err(ReadyError::ProcessExited(status));
            }
            platform::thread::yield_now();
        }
    }

    fn wait(
        &mut self,
        service: ReadyService,
        process_id: u64,
        has_timeout: bool,
    ) -> Result<(), ReadyError> {
        let started = has_timeout.then(current_ticks).transpose()?;
        let timeout = ready_timeout(service);
        loop {
            if let Some(status) = self.status(service) {
                return ready_result(status);
            }
            if let Some(notification) = receive_notification()? {
                match notification {
                    ReceivedNotification::Ready { token, status } => {
                        self.record(token, status)?;
                    }
                    ReceivedNotification::Session { .. } => {
                        return Err(ReadyError::InvalidMessage);
                    }
                    ReceivedNotification::Deferred(message) => {
                        self.deferred.push_back(message);
                    }
                }
            }
            if let Some(status) = self.status(service) {
                return ready_result(status);
            }
            if let Some(status) = process_exit_status(process_id)? {
                return Err(ReadyError::ProcessExited(status));
            }
            if let Some(started) = started {
                let now = current_ticks()?;
                if now.saturating_sub(started) >= timeout {
                    return Err(ReadyError::TimedOut);
                }
            }
            platform::thread::yield_now();
        }
    }
}

const fn ready_timeout(service: ReadyService) -> u64 {
    match service {
        ReadyService::Network => NETWORK_READY_TIMEOUT_TICKS,
        _ => SERVICE_READY_TIMEOUT_TICKS,
    }
}

fn ready_result(status: i32) -> Result<(), ReadyError> {
    if status == 0 {
        Ok(())
    } else {
        Err(ReadyError::Failed(status))
    }
}

enum ReceivedNotification {
    Ready {
        token: u64,
        status: i32,
    },
    Session {
        token: u64,
        status: i32,
        identity: platform::service_ready::SessionIdentity,
    },
    Deferred(DeferredMessage),
}

#[inline(never)]
fn receive_notification() -> Result<Option<ReceivedNotification>, ReadyError> {
    let mut message = [0u8; BOOTSTRAP_MESSAGE_LEN];
    let received = match platform::ipc::try_wait(&mut message) {
        Ok(received) => received,
        Err(error) if error.raw() == mochi_user_syscall::EAGAIN as i64 => return Ok(None),
        Err(error) => return Err(ReadyError::Ipc(error.raw().unsigned_abs())),
    };
    let length = (received & 0xffff_ffff) as usize;
    let sender = received >> 32;
    let Some(message) = message.get(..length) else {
        return Err(ReadyError::InvalidMessage);
    };
    match length {
        platform::service_ready::MESSAGE_LEN => {
            match platform::service_ready::decode_notification(message) {
                Ok((token, status)) => Ok(Some(ReceivedNotification::Ready { token, status })),
                Err(_) => Ok(Some(deferred_message(sender, message))),
            }
        }
        platform::service_ready::SESSION_MESSAGE_LEN => {
            match platform::service_ready::decode_session_notification(message) {
                Ok((token, status, identity)) => Ok(Some(ReceivedNotification::Session {
                    token,
                    status,
                    identity,
                })),
                Err(_) => Ok(Some(deferred_message(sender, message))),
            }
        }
        _ => Ok(Some(deferred_message(sender, message))),
    }
}

fn deferred_message(sender: u64, message: &[u8]) -> ReceivedNotification {
    ReceivedNotification::Deferred(DeferredMessage {
        sender,
        bytes: message.to_vec(),
    })
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn network_allows_for_dhcp_retries_without_extending_other_services() {
        assert_eq!(ready_timeout(ReadyService::Network), 30_000);
        assert_eq!(ready_timeout(ReadyService::Input), 5_000);
        assert_eq!(ready_timeout(ReadyService::Display), 5_000);
        assert_eq!(ready_timeout(ReadyService::User), 5_000);
        assert_eq!(ready_timeout(ReadyService::SecureUi), 5_000);
    }
}
