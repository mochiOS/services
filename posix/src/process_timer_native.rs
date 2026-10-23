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
