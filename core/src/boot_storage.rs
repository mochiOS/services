//! Bootstrap storage readiness, without requiring an optional discovery backend
//! when the boot extension has already initialized the selected disk.
use mochi_user_syscall::SysError;

pub(super) fn prepare(
    probe: impl FnOnce() -> Result<(), SysError>,
    discover: impl FnOnce() -> Result<(), SysError>,
) -> Result<(), SysError> {
    match probe() {
        Ok(()) => Ok(()),
        Err(error) if error.native_error() == Some(mnu_abi::status::Error::NotReady) => discover(),
        Err(error) => Err(error),
    }
}
