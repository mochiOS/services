use mboot_protocol::ErrorCode;
use mochi_user_platform::syscall;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum HostError {
    Unavailable,
    InvalidReply,
    Rejected(ErrorCode),
}

// These replies carry signed userspace policy failures. Never negate an
// already-negative value when reporting it through the Linux service protocol.
pub(crate) fn launch_status(error: HostError) -> i32 {
    match error {
        HostError::Rejected(ErrorCode::PermissionDenied) => syscall::EACCES as i32,
        HostError::Rejected(ErrorCode::Busy) => -16,
        HostError::Rejected(_) => syscall::EINVAL as i32,
        HostError::Unavailable => syscall::EAGAIN as i32,
        HostError::InvalidReply => syscall::EIO as i32,
    }
}

pub(crate) fn portal_status(error: HostError) -> i32 {
    match error {
        HostError::Unavailable => syscall::EIO as i32,
        HostError::InvalidReply => syscall::EINVAL as i32,
        HostError::Rejected(_) => mochios_posix_protocol::STATUS_EPERM,
    }
}

pub(crate) fn io_status(error: std::io::Error) -> i32 {
    let Some(errno) = error.raw_os_error().filter(|errno| *errno > 0) else {
        return mochios_posix_protocol::STATUS_EIO;
    };
    // std::io carries the target libc's errno, not native or wire statuses.
    #[cfg(target_os = "mochios")]
    {
        mochios_posix_client::newlib_errno::to_status(errno)
    }
    #[cfg(not(target_os = "mochios"))]
    {
        mochios_posix_protocol::status::normalize_failure(i64::from(errno))
    }
}
