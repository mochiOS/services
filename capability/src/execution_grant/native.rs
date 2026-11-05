//! The broker's private durable store and authenticated POSIX user adapter.
use super::*;
use crate::persistent_grant::{self as files, PolicyFileSet};

const DATABASE: PolicyFileSet = PolicyFileSet {
    current: "/var/lib/security/execution-consent.db",
    temporary: "/var/lib/security/execution-consent.db.new",
    previous: "/var/lib/security/execution-consent.db.old",
};

pub(super) fn requester_uid(peer: &Peer) -> Result<u32, SysError> {
    let context = files::requester_context(peer.instance.endpoint)?;
    if context.process_id != peer.instance.process {
        return Err(error(NativeError::AccessDenied));
    }
    Ok(context.effective_uid)
}

pub(super) fn read() -> Result<Option<Vec<u8>>, SysError> {
    files::recover_policy_file(DATABASE)?;
    match files::read_file_bounded(DATABASE.current, MAX_BYTES) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(reason) if reason.raw() == mochios_posix_protocol::STATUS_ENOENT as i64 => Ok(None),
        Err(reason) => Err(reason),
    }
}

pub(super) fn replace(bytes: &[u8]) -> Result<(), SysError> {
    files::ensure_policy_dir()?;
    files::replace_policy_file(DATABASE, bytes, 0o600)
}
