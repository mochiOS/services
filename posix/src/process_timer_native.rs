//! Timer observations of the retained owner object, never the service's own
//! CPU clock. Only generic native clock/process queries run under POSIX state.
use mochi_user_platform as platform;
use mochios_posix_protocol as protocol;
use posix_service::{
    process_timer::Clock,
    process_timer_request::{Reading, cpu_nanoseconds},
};

pub(super) fn read(process: u32, clock: Clock) -> Result<Reading, i32> {
    if clock == Clock::ProcessCpu {
        let usage = platform::process::execution_usage(Some(process))
            .map_err(|error| protocol::status::normalize_failure(error.raw()))?;
        return cpu_nanoseconds(usage).map(Reading::Counter);
    }
    let native = match clock {
        Clock::Realtime => mnu_abi::ClockId::Realtime,
        Clock::Monotonic => mnu_abi::ClockId::Monotonic,
        Clock::ProcessCpu => unreachable!(),
        Clock::ThreadCpu => return Err(posix_service::STATUS_EINVAL),
    };
    let mut instant = mnu_abi::ClockInstant::default();
    platform::syscall::call2(
        platform::syscall::SyscallNumber::ClockRead,
        native as u64,
        (&mut instant as *mut mnu_abi::ClockInstant) as u64,
    )
    .map_err(|error| protocol::status::normalize_failure(error.raw()))?;
    if instant.reserved != 0 || instant.nanoseconds >= 1_000_000_000 {
        return Err(protocol::STATUS_EIO);
    }
    let value = u128::from(instant.seconds) * 1_000_000_000 + u128::from(instant.nanoseconds);
    Ok(match clock {
        Clock::Realtime => Reading::Realtime(value as i128),
        _ => Reading::Counter(value),
    })
}

/// Observe a retained registration, checking the native Handle against the
/// authenticated owner/target before sampling. No ambient TID lookup exists.
pub(super) fn read_thread(owner: u64, target: u64, handle: u32) -> Result<Reading, i32> {
    let status =
        platform::thread::handle_status(handle).map_err(|error| thread_failure(error.raw()))?;
    if status.process_id != owner || status.thread_id != target || owner == 0 || target == 0 {
        return Err(protocol::STATUS_EPERM);
    }
    if status.reserved != 0
        || !(mnu_abi::THREAD_STATE_READY..=mnu_abi::THREAD_STATE_TERMINATED).contains(&status.state)
    {
        return Err(protocol::STATUS_EIO);
    }
    if status.state == mnu_abi::THREAD_STATE_TERMINATED {
        return Err(protocol::STATUS_ESRCH);
    }
    let instant =
        platform::thread::cpu_clock(handle).map_err(|error| thread_failure(error.raw()))?;
    if instant.reserved != 0 || instant.nanoseconds >= 1_000_000_000 {
        return Err(protocol::STATUS_EIO);
    }
    Ok(Reading::Counter(
        u128::from(instant.seconds) * 1_000_000_000 + u128::from(instant.nanoseconds),
    ))
}

fn thread_failure(raw: i64) -> i32 {
    if mnu_abi::status::Error::from_raw(raw as u64) == Some(mnu_abi::status::Error::NotFound) {
        protocol::STATUS_ESRCH
    } else {
        protocol::status::normalize_failure(raw)
    }
}

/// Resolve an explicitly received WAIT Handle, not a caller-supplied TID.
pub(super) fn thread_target(owner: u64, handle: u32) -> Result<u64, i32> {
    let status =
        platform::thread::handle_status(handle).map_err(|error| thread_failure(error.raw()))?;
    if owner == 0 || status.process_id != owner || status.thread_id == 0 {
        return Err(protocol::STATUS_EPERM);
    }
    if status.reserved != 0
        || !(mnu_abi::THREAD_STATE_READY..=mnu_abi::THREAD_STATE_TERMINATED).contains(&status.state)
    {
        return Err(protocol::STATUS_EIO);
    }
    if status.state == mnu_abi::THREAD_STATE_TERMINATED {
        return Err(protocol::STATUS_ESRCH);
    }
    Ok(status.thread_id)
}
