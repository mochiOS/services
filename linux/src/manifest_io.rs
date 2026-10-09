use mochi_user_platform::{package, syscall};

pub(crate) fn read_manifest(
    path: &str,
    read: impl FnOnce(&str) -> std::io::Result<Vec<u8>>,
) -> Result<package::PackageManifest, i32> {
    let bytes = read(path).map_err(|error| match error.raw_os_error() {
        Some(errno) => errno
            .checked_abs()
            .filter(|errno| *errno != 0)
            .map(|errno| -errno)
            .unwrap_or(syscall::EIO as i32),
        None => syscall::EIO as i32,
    })?;
    let text = core::str::from_utf8(&bytes).map_err(|_| syscall::EINVAL as i32)?;
    package::parse_manifest(text).ok_or(syscall::EINVAL as i32)
}
