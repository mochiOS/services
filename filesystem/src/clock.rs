//! Provider-owned wall clock. It grants no caller-selected timestamp or time
//! authority; native reads retain the normal SystemTimeRead capability check.
use ext4plus::inode::InodeTimestamp;

pub type Clock = fn() -> Result<InodeTimestamp, i32>;

#[cfg(target_os = "mochios")]
pub fn realtime_timestamp() -> Result<InodeTimestamp, i32> {
    use mochi_user_platform::syscall;
    let mut instant = mnu_abi::ClockInstant::default();
    syscall::call2(
        syscall::SyscallNumber::ClockRead,
        mnu_abi::ClockId::Realtime as u64,
        (&mut instant as *mut mnu_abi::ClockInstant) as u64,
    )
    .map_err(|error| match error.native_error() {
        Some(syscall::NativeError::AccessDenied) => 13,
        Some(syscall::NativeError::NotReady) => 11,
        _ => 5,
    })?;
    if instant.reserved != 0 || instant.nanoseconds >= 1_000_000_000 {
        return Err(5);
    }
    Ok(InodeTimestamp {
        seconds: i64::try_from(instant.seconds).map_err(|_| 75)?,
        nanoseconds: instant.nanoseconds,
    })
}

#[cfg(not(target_os = "mochios"))]
pub fn realtime_timestamp() -> Result<InodeTimestamp, i32> {
    from_system_time(std::time::SystemTime::now())
}

#[cfg(not(target_os = "mochios"))]
pub(crate) fn from_system_time(time: std::time::SystemTime) -> Result<InodeTimestamp, i32> {
    let (duration, negative) = match time.duration_since(std::time::UNIX_EPOCH) {
        Ok(duration) => (duration, false),
        Err(error) => (error.duration(), true),
    };
    let total =
        i128::from(duration.as_secs()) * 1_000_000_000 + i128::from(duration.subsec_nanos());
    let total = if negative { -total } else { total };
    Ok(InodeTimestamp {
        seconds: i64::try_from(total.div_euclid(1_000_000_000)).map_err(|_| 75)?,
        nanoseconds: total.rem_euclid(1_000_000_000) as u32,
    })
}
