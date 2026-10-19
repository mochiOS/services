use mochi_user_platform::{package, syscall};

pub(crate) fn read_manifest(
    path: &str,
    read: impl FnOnce(&str) -> std::io::Result<Vec<u8>>,
) -> Result<package::PackageManifest, i32> {
    let bytes = read(path).map_err(crate::error::io_status)?;
    let text = core::str::from_utf8(&bytes).map_err(|_| syscall::EINVAL as i32)?;
    package::parse_manifest(text).ok_or(syscall::EINVAL as i32)
}
