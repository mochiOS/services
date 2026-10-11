use alloc::collections::BTreeMap;
use mochios_posix_client::{Client, ClientError, ObjectTransport};

use crate::native_process::NativeProcess;

/// Select only a process owner retained by this launcher. Never capture a new
/// reference by PID. A failed or delayed service reply must preserve the owner
/// for retry; only a confirmed successful tree teardown may release it.
pub(crate) fn terminate_owned_root<T: ObjectTransport<Handle = u32>>(
    client: &Client<T>,
    owners: &mut BTreeMap<u64, NativeProcess>,
    process_id: u64,
) -> Result<(), ClientError<T::Error>> {
    let process = owners
        .get(&process_id)
        .ok_or(ClientError::Remote(mochios_posix_protocol::STATUS_ESRCH))?;
    client.terminate_launched_tree(process.termination_attachment())?;
    owners.remove(&process_id);
    Ok(())
}
