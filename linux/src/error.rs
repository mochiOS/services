use mboot_protocol::ErrorCode;
use mochi_user_platform::syscall;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum HostError {
    Unavailable,
    InvalidReply,
    Rejected(ErrorCode),
}

// Native error constants already encode a negative status. Never negate them
// again when reporting a Linux service failure through its wire protocol.
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
        HostError::Rejected(_) => syscall::EPERM as i32,
    }
}

pub(crate) fn io_status(error: std::io::Error) -> i32 {
    error
        .raw_os_error()
        .and_then(i32::checked_abs)
        .filter(|errno| *errno != 0)
        .map_or(syscall::EIO as i32, |errno| -errno)
}
