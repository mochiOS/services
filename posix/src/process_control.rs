use mochi_user_platform as platform;
use posix_service::{AttachedObject, AuthenticatedProcess, STATUS_EINVAL};

/// Authenticate the explicit root object, never a PID supplied in IPC bytes.
/// Native handle status enforces Process object type and WAIT authority.
pub(crate) fn authenticated_tree_root(
    root: AttachedObject<u32>,
) -> Result<AuthenticatedProcess<u32>, i32> {
    let rights = platform::handle::HANDLE_RIGHT_WAIT | platform::handle::HANDLE_RIGHT_SIGNAL;
    if root.handle == 0 || root.rights != rights {
        return Err(STATUS_EINVAL);
    }
    let status = platform::process::handle_status(root.handle)
        .map_err(|error| error.errno().map_or(-5, |errno| -(errno as i32)))?;
    if status.process_id == 0 {
        return Err(STATUS_EINVAL);
    }
    Ok(AuthenticatedProcess {
        handle: root.handle,
        process_id: status.process_id,
    })
}
