/// Accepts either a native encoded failure or a POSIX wire failure/magnitude.
/// Account protocol failures must always carry a negative signed status.
pub fn wire_status(raw: u64) -> i32 {
    if raw == 0 {
        return 0;
    }
    mochios_posix_protocol::status::normalize_failure(raw as i64)
}

/// std::io carries the target libc's errno, not native or wire statuses.
pub fn io_status(error: &std::io::Error) -> i32 {
    let Some(errno) = error.raw_os_error().filter(|errno| *errno > 0) else {
        return mochios_posix_protocol::STATUS_EIO;
    };
    #[cfg(target_os = "mochios")]
    {
        mochios_posix_client::newlib_errno::to_status(errno)
    }
    #[cfg(not(target_os = "mochios"))]
    {
        // Host-side service tests use their host libc, not the mochiOS SDK.
        mochios_posix_protocol::status::normalize_failure(i64::from(errno))
    }
}
