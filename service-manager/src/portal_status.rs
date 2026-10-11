use mochi_user_platform::syscall;

pub(crate) fn failure_status(error: u64) -> i32 {
    let errno = (error as i64).unsigned_abs();
    i32::try_from(errno)
        .ok()
        .filter(|errno| *errno > 0)
        .map_or(syscall::EIO as i32, |errno| -errno)
}
