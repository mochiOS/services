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

fn decode_reply(msg: u64, reply: &[u8]) -> Result<(), ReadyError> {
    let len = (msg & 0xffff_ffff) as usize;
    let Some(message) = reply.get(..len) else {
        return Err(ReadyError::InvalidMessage);
    };
    match platform::service_ready::validate_result(message) {
        Ok(()) => Ok(()),
        Err(platform::service_ready::ResultError::InvalidMessage(_)) => {
            Err(ReadyError::InvalidMessage)
        }
        Err(platform::service_ready::ResultError::Failed(status)) => {
            Err(ReadyError::Failed(status))
        }
    }
}

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

pub(crate) fn wait_for_service_ready(
    _service: ServiceKind,
    process_id: u64,
) -> Result<(), ReadyError> {
    let started = platform::time::ticks()
        .map_err(|err| ReadyError::Clock(err.raw().unsigned_abs()))?;
    let request = platform::service_ready::query();
    let mut reply = [0u8; platform::service_ready::MESSAGE_LEN];
    match platform::ipc::call(process_id, &request, &mut reply) {
        Ok(msg) => return decode_reply(msg, &reply),
        Err(err) if err.raw() == mochi_user_syscall::EAGAIN as i64 => {}
        Err(err) => return Err(ReadyError::Ipc(err.raw().unsigned_abs())),
    }

    loop {
        match platform::ipc::try_wait(&mut reply) {
            Ok(msg) => return decode_reply(msg, &reply),
            Err(err) if err.raw() == mochi_user_syscall::EAGAIN as i64 => {}
            Err(err) => return Err(ReadyError::Ipc(err.raw().unsigned_abs())),
        }
        if let Some(status) = process_exit_status(process_id)? {
            return Err(ReadyError::ProcessExited(status));
        }
        let now = platform::time::ticks()
            .map_err(|err| ReadyError::Clock(err.raw().unsigned_abs()))?;
        if now.saturating_sub(started) >= SERVICE_READY_TIMEOUT_TICKS {
            return Err(ReadyError::TimedOut);
        }
        platform::thread::yield_now();
    }
}

pub(crate) fn idle() -> ! {
    loop {
        platform::thread::yield_now();
    }
}
