use mochi_user_platform as platform;

const SERVICE_READY_TIMEOUT_TICKS: u64 = 5_000;
const WAIT_NO_HANG: u64 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ServiceKind {
    Input,
    Display,
}

impl ServiceKind {
    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::Input => "input.service",
            Self::Display => "display.driver",
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
    input_status: platform::service_ready::OneShotStatus,
    display_status: platform::service_ready::OneShotStatus,
}

impl ReadyHandshake {
    pub(crate) fn create() -> Result<Self, ReadyError> {
        let endpoint = platform::ipc::create()
            .map_err(|err| ReadyError::Ipc(err.raw().unsigned_abs()))?;
        let input_token = platform::service_ready::generate_token()
            .map_err(|err| ReadyError::Ipc(err.raw().unsigned_abs()))?;
        let mut display_token = platform::service_ready::generate_token()
            .map_err(|err| ReadyError::Ipc(err.raw().unsigned_abs()))?;
        if display_token == input_token {
            display_token ^= 0xa5a5_5a5a_d3c3_3c3c;
            if display_token == 0 {
                display_token = 1;
            }
        }
        Ok(Self {
            endpoint,
            input_token,
            display_token,
            input_status: platform::service_ready::OneShotStatus::new(),
            display_status: platform::service_ready::OneShotStatus::new(),
        })
    }

    pub(crate) const fn target(&self, service: ServiceKind) -> platform::service_ready::Target {
        let token = match service {
            ServiceKind::Input => self.input_token,
            ServiceKind::Display => self.display_token,
        };
        platform::service_ready::Target {
            endpoint: self.endpoint,
            token,
        }
    }

    fn status(&self, service: ServiceKind) -> Option<i32> {
        match service {
            ServiceKind::Input => self.input_status.get(),
            ServiceKind::Display => self.display_status.get(),
        }
    }

    fn record(&mut self, token: u64, status: i32) -> Result<(), ReadyError> {
        let slot = if token == self.input_token {
            &mut self.input_status
        } else if token == self.display_token {
            &mut self.display_status
        } else {
            return Err(ReadyError::InvalidMessage);
        };
        let _ = slot.record(status);
        Ok(())
    }

    pub(crate) fn wait_for_service_ready(
        &mut self,
        service: ServiceKind,
        process_id: u64,
    ) -> Result<(), ReadyError> {
        let started = current_ticks()?;
        loop {
            if let Some(status) = self.status(service) {
                return if status == 0 {
                    Ok(())
                } else {
                    Err(ReadyError::Failed(status))
                };
            }
            if let Some((token, status)) = receive_notification()? {
                self.record(token, status)?;
            }
            if let Some(status) = self.status(service) {
                return if status == 0 {
                    Ok(())
                } else {
                    Err(ReadyError::Failed(status))
                };
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

#[inline(never)]
fn receive_notification() -> Result<Option<(u64, i32)>, ReadyError> {
    let mut message = [0u8; platform::service_ready::MESSAGE_LEN];
    let msg = match platform::ipc::try_wait(&mut message) {
        Ok(msg) => msg,
        Err(err) if err.raw() == mochi_user_syscall::EAGAIN as i64 => return Ok(None),
        Err(err) => return Err(ReadyError::Ipc(err.raw().unsigned_abs())),
    };
    let len = (msg & 0xffff_ffff) as usize;
    let Some(message) = message.get(..len) else {
        return Err(ReadyError::InvalidMessage);
    };
    let notification = platform::service_ready::decode_notification(message)
        .map_err(|_| ReadyError::InvalidMessage)?;
    Ok(Some(notification))
}

#[inline(never)]
fn current_ticks() -> Result<u64, ReadyError> {
    platform::time::ticks().map_err(|err| ReadyError::Clock(err.raw().unsigned_abs()))
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
        Err(err) => Err(ReadyError::ProcessWait(err.raw().unsigned_abs())),
    }
}

pub(crate) fn idle() -> ! {
    loop {
        platform::thread::yield_now();
    }
}
