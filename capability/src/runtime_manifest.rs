use alloc::vec::Vec;
use mochi_user_platform::{package, syscall};

/// Keep I/O failures intact; malformed manifest data is a distinct failure.
pub(crate) fn read_manifest(
    path: &str,
    read_file: impl FnOnce(&str) -> Result<Vec<u8>, syscall::SysError>,
) -> Result<package::PackageManifest, syscall::SysError> {
    let bytes = read_file(path)?;
    let text = core::str::from_utf8(&bytes)
        .map_err(|_| syscall::SysError::from_raw(syscall::EINVAL as i64))?;
    package::parse_manifest(text).ok_or_else(|| syscall::SysError::from_raw(syscall::EINVAL as i64))
}
