use alloc::collections::VecDeque;
use alloc::vec::Vec;
use mochi_user_platform as platform;

use crate::service_config::{NETWORK_READY_TIMEOUT_TICKS, SERVICE_READY_TIMEOUT_TICKS};
use crate::process_watch::ProcessWatch;
const BOOTSTRAP_MESSAGE_LEN: usize = 1024;

pub(crate) struct DeferredMessage {
    pub(crate) sender: u64,
    pub(crate) bytes: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ReadyService {
    Filesystem,
    Posix,
    Input,
    Display,
    Network,
    User,
    SecureUi,
    Workspace,
    Binder,
}

impl ReadyService {
    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::Filesystem => "filesystem.service",
            Self::Posix => "posix.service",
            Self::Input => "input.service",
            Self::Display => "display.driver",
            Self::Network => "network.service",
            Self::User => "user.service",
            Self::SecureUi => "secure-ui.service",
            Self::Workspace => "workspace.service",
            Self::Binder => "Binder.app",
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
    ProcessStatus(u64),
}

pub(crate) struct ReadyHandshake {
    endpoint: u64,
    filesystem_token: u64,
    posix_token: u64,
    input_token: u64,
    display_token: u64,
    network_token: u64,
    user_token: u64,
    secure_ui_token: u64,
    workspace_token: u64,
    binder_token: u64,
    filesystem_status: platform::service_ready::OneShotStatus,
    filesystem_endpoint: Option<platform::handle::Handle>,
    posix_status: platform::service_ready::OneShotStatus,
    posix_endpoint: Option<platform::handle::Handle>,
    input_status: platform::service_ready::OneShotStatus,
    display_status: platform::service_ready::OneShotStatus,
    network_status: platform::service_ready::OneShotStatus,
    user_status: platform::service_ready::OneShotStatus,
    secure_ui_status: platform::service_ready::OneShotStatus,
    workspace_status: platform::service_ready::OneShotStatus,
    binder_status: platform::service_ready::OneShotStatus,
    deferred: VecDeque<DeferredMessage>,
}

impl ReadyHandshake {
    pub(crate) fn create() -> Result<Self, ReadyError> {
        let endpoint =
            platform::ipc::create().map_err(|error| ReadyError::Ipc(error.raw().unsigned_abs()))?;
        let input_token = platform::service_ready::generate_token()
            .map_err(|error| ReadyError::Ipc(error.raw().unsigned_abs()))?;
        let mut filesystem_token = platform::service_ready::generate_token()
            .map_err(|error| ReadyError::Ipc(error.raw().unsigned_abs()))?;
        if filesystem_token == input_token {
            filesystem_token ^= 0x6d66_7331_a5a5_5a5a;
            if filesystem_token == 0 {
                filesystem_token = 1;
            }
        }
        let mut display_token = platform::service_ready::generate_token()
            .map_err(|error| ReadyError::Ipc(error.raw().unsigned_abs()))?;
        if display_token == input_token || display_token == filesystem_token {
            display_token ^= 0xa5a5_5a5a_d3c3_3c3c;
            if display_token == 0 {
                display_token = 1;
            }
        }
        let mut posix_token = platform::service_ready::generate_token()
            .map_err(|error| ReadyError::Ipc(error.raw().unsigned_abs()))?;
        if [input_token, filesystem_token, display_token].contains(&posix_token) {
            posix_token ^= 0x706f_7369_785f_7376;
            if posix_token == 0 {
                posix_token = 1;
            }
        }
        let mut network_token = platform::service_ready::generate_token()
            .map_err(|error| ReadyError::Ipc(error.raw().unsigned_abs()))?;
        if network_token == input_token
            || network_token == filesystem_token
            || network_token == display_token
            || network_token == posix_token
        {
            network_token ^= 0x3c3c_c3c3_5a5a_a5a5;
            if network_token == 0 {
                network_token = 1;
            }
        }
        let mut user_token = platform::service_ready::generate_token()
            .map_err(|error| ReadyError::Ipc(error.raw().unsigned_abs()))?;
        if user_token == input_token
            || user_token == filesystem_token
            || user_token == display_token
            || user_token == network_token
            || user_token == posix_token
        {
            user_token ^= 0x9696_6969_c3c3_3c3c;
            if user_token == 0 {
                user_token = 1;
            }
        }
        let mut secure_ui_token = platform::service_ready::generate_token()
            .map_err(|error| ReadyError::Ipc(error.raw().unsigned_abs()))?;
        if secure_ui_token == input_token
            || secure_ui_token == filesystem_token
            || secure_ui_token == display_token
            || secure_ui_token == network_token
            || secure_ui_token == user_token
            || secure_ui_token == posix_token
        {
            secure_ui_token ^= 0x5a5a_a5a5_9696_6969;
            if secure_ui_token == 0 {
                secure_ui_token = 1;
            }
        }
        let mut workspace_token = platform::service_ready::generate_token()
            .map_err(|error| ReadyError::Ipc(error.raw().unsigned_abs()))?;
        if [
            filesystem_token,
            posix_token,
            input_token,
            display_token,
            network_token,
            user_token,
            secure_ui_token,
        ]
        .contains(&workspace_token)
        {
            workspace_token ^= 0xc3c3_3c3c_a5a5_5a5a;
            if workspace_token == 0 {
                workspace_token = 1;
            }
        }
        let mut binder_token = platform::service_ready::generate_token()
            .map_err(|error| ReadyError::Ipc(error.raw().unsigned_abs()))?;
        if [
            filesystem_token,
            posix_token,
            input_token,
            display_token,
            network_token,
            user_token,
            secure_ui_token,
            workspace_token,
        ]
        .contains(&binder_token)
        {
            binder_token ^= 0x6969_9696_3c3c_c3c3;
            if binder_token == 0 {
                binder_token = 1;
            }
        }
        Ok(Self {
            endpoint,
            filesystem_token,
            posix_token,
            input_token,
            display_token,
            network_token,
            user_token,
            secure_ui_token,
            workspace_token,
            binder_token,
            filesystem_status: platform::service_ready::OneShotStatus::new(),
            filesystem_endpoint: None,
            posix_status: platform::service_ready::OneShotStatus::new(),
            posix_endpoint: None,
            input_status: platform::service_ready::OneShotStatus::new(),
            display_status: platform::service_ready::OneShotStatus::new(),
            network_status: platform::service_ready::OneShotStatus::new(),
            user_status: platform::service_ready::OneShotStatus::new(),
            secure_ui_status: platform::service_ready::OneShotStatus::new(),
            workspace_status: platform::service_ready::OneShotStatus::new(),
            binder_status: platform::service_ready::OneShotStatus::new(),
            deferred: VecDeque::new(),
        })
    }

    pub(crate) fn take_deferred(&mut self) -> VecDeque<DeferredMessage> {
        core::mem::take(&mut self.deferred)
    }

    pub(crate) const fn target(&self, service: ReadyService) -> platform::service_ready::Target {
        let token = match service {
            ReadyService::Filesystem => self.filesystem_token,
            ReadyService::Posix => self.posix_token,
            ReadyService::Input => self.input_token,
            ReadyService::Display => self.display_token,
            ReadyService::Network => self.network_token,
            ReadyService::User => self.user_token,
            ReadyService::SecureUi => self.secure_ui_token,
            ReadyService::Workspace => self.workspace_token,
            ReadyService::Binder => self.binder_token,
        };
        platform::service_ready::Target {
            endpoint: self.endpoint,
            token,
        }
    }

    fn status(&self, service: ReadyService) -> Option<i32> {
        match service {
            ReadyService::Filesystem => self.filesystem_status.get(),
            ReadyService::Posix => self.posix_status.get(),
            ReadyService::Input => self.input_status.get(),
            ReadyService::Display => self.display_status.get(),
            ReadyService::Network => self.network_status.get(),
            ReadyService::User => self.user_status.get(),
            ReadyService::SecureUi => self.secure_ui_status.get(),
            ReadyService::Workspace => self.workspace_status.get(),
            ReadyService::Binder => self.binder_status.get(),
        }
    }

    fn record(&mut self, token: u64, status: i32) -> Result<(), ReadyError> {
        let slot = if token == self.filesystem_token {
            &mut self.filesystem_status
        } else if token == self.posix_token {
            &mut self.posix_status
        } else if token == self.input_token {
            &mut self.input_status
        } else if token == self.display_token {
            &mut self.display_status
        } else if token == self.network_token {
            &mut self.network_status
        } else if token == self.user_token {
            &mut self.user_status
        } else if token == self.secure_ui_token {
            &mut self.secure_ui_status
        } else if token == self.workspace_token {
            &mut self.workspace_status
        } else if token == self.binder_token {
            &mut self.binder_status
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

    pub(crate) fn wait_for_endpoint_ready(
        &mut self,
        service: ReadyService,
        process_id: u64,
    ) -> Result<platform::handle::Handle, ReadyError> {
        if !matches!(service, ReadyService::Filesystem | ReadyService::Posix) {
            return Err(ReadyError::InvalidMessage);
        }
        let process = ProcessWatch::open(process_id)
            .map_err(|error| ReadyError::ProcessStatus(error.raw().unsigned_abs()))?;
        let started = current_ticks()?;
        loop {
            if let Some(status) = self.status(service) {
                ready_result(status)?;
                return self.endpoint_for(service).ok_or(ReadyError::InvalidMessage);
            }
            if let Some(notification) = receive_notification()? {
                match notification {
                    ReceivedNotification::Ready { token, status } => {
                        self.record(token, status)?;
                    }
                    ReceivedNotification::Endpoint {
                        token,
                        status,
                        endpoint,
                    } => {
                        if token != self.token_for(service)
                            || status != 0
                            || self.endpoint_for(service).is_some()
                        {
                            let _ = platform::handle::close(endpoint);
                            if status != 0 {
                                self.record(token, status)?;
                                continue;
                            }
                            return Err(ReadyError::InvalidMessage);
                        }
                        self.set_endpoint(service, endpoint)?;
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
            if let Some(status) = process
                .exit_status()
                .map_err(|error| ReadyError::ProcessStatus(error.raw().unsigned_abs()))?
            {
                return Err(ReadyError::ProcessExited(status));
            }
            if current_ticks()?.saturating_sub(started) >= ready_timeout(service) {
                return Err(ReadyError::TimedOut);
            }
            platform::thread::yield_now();
        }
    }

    fn token_for(&self, service: ReadyService) -> u64 {
        match service {
            ReadyService::Filesystem => self.filesystem_token,
            ReadyService::Posix => self.posix_token,
            _ => 0,
        }
    }

    fn endpoint_for(&self, service: ReadyService) -> Option<platform::handle::Handle> {
        match service {
            ReadyService::Filesystem => self.filesystem_endpoint,
            ReadyService::Posix => self.posix_endpoint,
            _ => None,
        }
    }

    fn set_endpoint(
        &mut self,
        service: ReadyService,
        endpoint: platform::handle::Handle,
    ) -> Result<(), ReadyError> {
        match service {
            ReadyService::Filesystem => self.filesystem_endpoint = Some(endpoint),
            ReadyService::Posix => self.posix_endpoint = Some(endpoint),
            _ => return Err(ReadyError::InvalidMessage),
        }
        Ok(())
    }

    pub(crate) fn wait_for_login_complete(
        &mut self,
        process_id: u64,
    ) -> Result<platform::service_ready::SessionIdentity, ReadyError> {
        let process = ProcessWatch::open(process_id)
            .map_err(|error| ReadyError::ProcessStatus(error.raw().unsigned_abs()))?;
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
                    ReceivedNotification::Endpoint { endpoint, .. } => {
                        let _ = platform::handle::close(endpoint);
                        return Err(ReadyError::InvalidMessage);
                    }
                    ReceivedNotification::Deferred(message) => {
                        self.deferred.push_back(message);
                    }
                }
            }
            if let Some(status) = process
                .exit_status()
                .map_err(|error| ReadyError::ProcessStatus(error.raw().unsigned_abs()))?
            {
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
        let process = ProcessWatch::open(process_id)
            .map_err(|error| ReadyError::ProcessStatus(error.raw().unsigned_abs()))?;
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
                    ReceivedNotification::Endpoint {
                        token,
                        status,
                        endpoint,
                    } => {
                        if token != self.posix_token || status != 0 || self.posix_endpoint.is_some()
                        {
                            let _ = platform::handle::close(endpoint);
                            if status != 0 {
                                self.record(token, status)?;
                                continue;
                            }
                            return Err(ReadyError::InvalidMessage);
                        }
                        self.posix_endpoint = Some(endpoint);
                        self.record(token, status)?;
                    }
                    ReceivedNotification::Deferred(message) => {
                        self.deferred.push_back(message);
                    }
                }
            }
            if let Some(status) = self.status(service) {
                return ready_result(status);
            }
            if let Some(status) = process
                .exit_status()
                .map_err(|error| ReadyError::ProcessStatus(error.raw().unsigned_abs()))?
            {
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
    Endpoint {
        token: u64,
        status: i32,
        endpoint: platform::handle::Handle,
    },
    Deferred(DeferredMessage),
}

#[inline(never)]
fn receive_notification() -> Result<Option<ReceivedNotification>, ReadyError> {
    let mut message = [0u8; BOOTSTRAP_MESSAGE_LEN];
    let mut handles = platform::ipc::IpcObjectHandles::default();
    let received = match platform::ipc::try_wait_object_handles(&mut message, &mut handles) {
        Ok(received) => received,
        Err(error) if error.raw() == mochi_user_syscall::EAGAIN as i64 => return Ok(None),
        Err(error) => return Err(ReadyError::Ipc(error.raw().unsigned_abs())),
    };
    let length = (received & 0xffff_ffff) as usize;
    let sender = received >> 32;
    let Some(message) = message.get(..length) else {
        close_received_handles(&handles);
        return Err(ReadyError::InvalidMessage);
    };
    let decoded = decode_received_notification(message, sender, &handles);
    if decoded.is_err() {
        close_received_handles(&handles);
    }
    decoded.map(Some)
}

fn decode_received_notification(
    message: &[u8],
    sender: u64,
    handles: &platform::ipc::IpcObjectHandles,
) -> Result<ReceivedNotification, ReadyError> {
    if let Ok((token, status)) = platform::service_ready::decode_handle_notification(message) {
        if handles.count != 1 {
            return Err(ReadyError::InvalidMessage);
        }
        let attached = handles.handles[0];
        let required =
            platform::handle::HANDLE_RIGHT_SEND | platform::handle::HANDLE_RIGHT_TRANSFER;
        let allowed = required | platform::handle::HANDLE_RIGHT_DUPLICATE;
        if attached.handle == 0
            || attached.reserved != 0
            || attached.rights & required != required
            || attached.rights & !allowed != 0
        {
            return Err(ReadyError::InvalidMessage);
        }
        return Ok(ReceivedNotification::Endpoint {
            token,
            status,
            endpoint: attached.handle,
        });
    }
    if handles.count != 0 {
        return Err(ReadyError::InvalidMessage);
    }
    if let Ok((token, status)) = platform::service_ready::decode_notification(message) {
        return Ok(ReceivedNotification::Ready { token, status });
    }
    if let Ok((token, status, identity)) =
        platform::service_ready::decode_session_notification(message)
    {
        return Ok(ReceivedNotification::Session {
            token,
            status,
            identity,
        });
    }
    Ok(deferred_message(sender, message))
}

fn close_received_handles(handles: &platform::ipc::IpcObjectHandles) {
    let count = core::cmp::min(handles.count as usize, handles.handles.len());
    for attached in &handles.handles[..count] {
        if attached.handle != 0 {
            let _ = platform::handle::close(attached.handle);
        }
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
        assert_eq!(ready_timeout(ReadyService::Workspace), 5_000);
    }

    #[test]
    fn endpoint_ready_uses_one_restricted_attached_handle() {
        let message = platform::service_ready::handle_notification(7, 0);
        let mut handles = platform::ipc::IpcObjectHandles::default();
        handles.count = 1;
        handles.handles[0] = platform::ipc::IpcObjectHandle {
            handle: 41,
            reserved: 0,
            rights: platform::handle::HANDLE_RIGHT_SEND
                | platform::handle::HANDLE_RIGHT_DUPLICATE
                | platform::handle::HANDLE_RIGHT_TRANSFER,
        };
        assert!(matches!(
            decode_received_notification(&message, 99, &handles),
            Ok(ReceivedNotification::Endpoint {
                token: 7,
                status: 0,
                endpoint: 41,
            })
        ));
    }

    #[test]
    fn endpoint_ready_rejects_missing_or_receive_capable_handles() {
        let message = platform::service_ready::handle_notification(7, 0);
        let mut handles = platform::ipc::IpcObjectHandles::default();
        assert!(matches!(
            decode_received_notification(&message, 99, &handles),
            Err(ReadyError::InvalidMessage)
        ));

        handles.count = 1;
        handles.handles[0] = platform::ipc::IpcObjectHandle {
            handle: 41,
            reserved: 0,
            rights: platform::handle::HANDLE_RIGHT_SEND
                | platform::handle::HANDLE_RIGHT_RECEIVE
                | platform::handle::HANDLE_RIGHT_TRANSFER,
        };
        assert!(matches!(
            decode_received_notification(&message, 99, &handles),
            Err(ReadyError::InvalidMessage)
        ));
    }
}
