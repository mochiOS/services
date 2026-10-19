//! Setup displays both account-protocol and local filesystem failures. Local
//! std I/O contains libc errno, which must first enter the same wire namespace.
use mochios_posix_client::newlib_errno;
use std::io;

pub(crate) fn newlib_status(errno: i32) -> i32 {
    // Negative/native/wire statuses are not C errno. Never abs() them: in
    // particular i32::MIN must not panic or become a successful status.
    if errno <= 0 {
        return -newlib_errno::EIO;
    }
    newlib_errno::to_status(errno)
}

pub(crate) fn io_status(error: &io::Error) -> i32 {
    #[cfg(target_os = "mochios")]
    if let Some(errno) = error.raw_os_error() {
        return newlib_status(errno);
    }
    // Typed errors without OS errno (and host-side tests) must not depend on
    // host libc numbering. Unknown failures stay EIO, never copied raw.
    -match error.kind() {
        io::ErrorKind::NotFound => 2,
        io::ErrorKind::PermissionDenied => 13,
        io::ErrorKind::AlreadyExists => 17,
        io::ErrorKind::NotADirectory => 20,
        io::ErrorKind::IsADirectory => 21,
        io::ErrorKind::InvalidInput => 22,
        io::ErrorKind::FileTooLarge => 27,
        io::ErrorKind::StorageFull => 28,
        io::ErrorKind::ReadOnlyFilesystem => 30,
        io::ErrorKind::OutOfMemory => 12,
        io::ErrorKind::Interrupted => 4,
        io::ErrorKind::WouldBlock => 11,
        io::ErrorKind::Unsupported => 95,
        _ => newlib_errno::EIO,
    }
}
