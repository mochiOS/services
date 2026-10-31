//! Object type, liveness and rights are native observations, never PID bytes.
use mochi_user_platform as p;
use mochios_posix_protocol as w;
pub fn authenticate(
    object: crate::AttachedObject<u32>,
) -> Result<crate::AuthenticatedProcess<u32>, i32> {
    if object.handle == 0 || object.rights != w::process_domain::PROCESS_RIGHTS {
        return Err(crate::STATUS_EINVAL);
    }
    let status = p::process::handle_status(object.handle).map_err(|error| {
        if error.native_error() == Some(p::syscall::NativeError::NotFound) {
            w::STATUS_ESRCH
        } else {
            w::status::normalize_failure(error.raw())
        }
    })?;
    if status.process_id == 0 || status.reserved != 0 {
        return Err(crate::STATUS_EINVAL);
    }
    if status.state != mnu_abi::PROCESS_STATE_RUNNING {
        return Err(w::STATUS_ESRCH);
    }
    Ok(crate::AuthenticatedProcess {
        handle: object.handle,
        process_id: status.process_id,
    })
}
