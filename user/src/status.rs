use mochi_user_platform::syscall;

/// Accepts either a native encoded failure or an internal positive errno.
/// Account protocol failures must always carry a negative signed status.
pub fn wire_status(raw: u64) -> i32 {
    if raw == 0 {
        return 0;
    }
    let errno = (raw as i64).unsigned_abs();
    i32::try_from(errno)
        .ok()
        .filter(|errno| *errno > 0)
        .map_or(syscall::EIO as i32, |errno| -errno)
}
