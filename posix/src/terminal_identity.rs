//! Identify a terminal only from a native-delivered, attenuated data reference.
use crate::pty::PtyManager;
use mnu_abi::{HANDLE_RIGHT_TRANSFER, IpcObjectHandles};

/// Positive wire errno. Native identification is meaningful only on the
/// creating provider endpoint; a foreign provider is a valid non-terminal,
/// not a bad process-local FD. No inline object ID or sender claim is accepted.
pub fn lookup(
    manager: &PtyManager,
    attached: &IpcObjectHandles,
    identify: impl FnOnce(u32) -> Result<u64, i64>,
) -> Result<u64, i32> {
    if attached.delivery_flags != mnu_abi::IPC_DELIVERY_ENDPOINT_HANDLE {
        return Err(13);
    }
    if attached.count != 1 {
        return Err(22);
    }
    let source = attached.handles[0];
    if source.handle == 0 || source.reserved != 0 || source.rights != HANDLE_RIGHT_TRANSFER {
        return Err(13);
    }
    let object = identify(source.handle).map_err(|error| {
        use mnu_abi::status::Error;
        match Error::from_raw(error as u64) {
            Some(Error::InvalidArgument | Error::AccessDenied) => 25,
            Some(Error::NotFound) => 9,
            _ => -mochios_posix_protocol::status::normalize_failure(error),
        }
    })?;
    manager
        .slave_terminal_id(object)
        .map_err(|error| if error == 9 { 25 } else { error })
}
