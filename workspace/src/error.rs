use mochi_user_platform::syscall;
use mochios_posix_client::ClientError;

// Internal Result errors are positive errno values; only the wire reply
// boundary negates them. Native and remote statuses can already be negative.
pub(crate) fn status_errno(status: i64) -> u64 {
    u64::from(mochios_posix_protocol::status::normalize_failure(status).unsigned_abs())
}

pub(crate) fn native_errno(error: syscall::SysError) -> u64 {
    status_errno(error.raw())
}

pub(crate) fn io_errno(error: std::io::Error) -> u64 {
    let Some(errno) = error.raw_os_error().filter(|errno| *errno > 0) else {
        return status_errno(i64::from(mochios_posix_protocol::STATUS_EIO));
    };
    #[cfg(target_os = "mochios")]
    {
        // The workspace wire format uses positive POSIX magnitudes, not C errno.
        u64::from(mochios_posix_client::newlib_errno::to_status(errno).unsigned_abs())
    }
    #[cfg(not(target_os = "mochios"))]
    {
        status_errno(i64::from(errno))
    }
}

pub(crate) fn posix_errno(error: ClientError<syscall::SysError>) -> u64 {
    match error {
        ClientError::Transport(error) => status_errno(error.raw()),
        ClientError::Remote(status) => status_errno(i64::from(status)),
        ClientError::RequestTooLarge => {
            status_errno(i64::from(mochios_posix_protocol::STATUS_EOVERFLOW))
        }
        ClientError::Protocol(_)
        | ClientError::ResponseTooLarge
        | ClientError::MismatchedResponse => status_errno(syscall::EIO as i64),
    }
}
