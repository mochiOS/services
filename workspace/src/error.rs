use mochi_user_platform::syscall;
use mochios_posix_client::ClientError;

// Internal Result errors are positive errno values; only the wire reply
// boundary negates them. Native and remote statuses can already be negative.
pub(crate) fn status_errno(status: i64) -> u64 {
    let errno = status.unsigned_abs();
    if errno == 0 || errno > i32::MAX as u64 {
        (syscall::EIO as i64).unsigned_abs()
    } else {
        errno
    }
}

pub(crate) fn io_errno(error: std::io::Error) -> u64 {
    error.raw_os_error().map_or_else(
        || status_errno(syscall::EIO as i64),
        |status| status_errno(i64::from(status)),
    )
}

pub(crate) fn posix_errno(error: ClientError<syscall::SysError>) -> u64 {
    match error {
        ClientError::Transport(error) => status_errno(error.raw()),
        ClientError::Remote(status) => status_errno(i64::from(status)),
        ClientError::RequestTooLarge => status_errno(syscall::EOVERFLOW as i64),
        ClientError::Protocol(_)
        | ClientError::ResponseTooLarge
        | ClientError::MismatchedResponse => status_errno(syscall::EIO as i64),
    }
}
