//! Device ledger in the existing broker policy store, never in a user's home.
use super::*;
use crate::persistent_grant::{self as files, PolicyFileSet};
use mochios_posix_client::StatAtBase;
use mochios_posix_protocol as posix;

const LEDGER: PolicyFileSet = PolicyFileSet {
    current: "/var/lib/security/standard-applications.db",
    temporary: "/var/lib/security/standard-applications.db.new",
    previous: "/var/lib/security/standard-applications.db.old",
};

fn validate() -> Result<(), SysError> {
    // Validate each ancestor before creating anything beneath it. An existing
    // symlink or writable directory must not redirect privileged recovery I/O.
    for path in ["/", "/var", "/var/lib", "/var/lib/security"] {
        let result =
            files::with_client(|c| c.stat_at(StatAtBase::ProcessRoot, posix::STAT_NOFOLLOW, path));
        let stat = match result {
            Err(e) if e.raw() == -2 && path != "/" => {
                files::with_client(|c| {
                    c.mkdir_at(mochios_posix_client::OpenAtBase::ProcessRoot, 0o755, path)
                })?;
                files::with_client(|c| {
                    c.stat_at(StatAtBase::ProcessRoot, posix::STAT_NOFOLLOW, path)
                })?
            }
            other => other?,
        };
        if stat.uid != 0 || stat.mode & 0o170000 != 0o040000 || stat.mode & 0o022 != 0 {
            return Err(denied());
        }
    }
    for path in [LEDGER.current, LEDGER.temporary, LEDGER.previous] {
        match files::with_client(|c| c.stat_at(StatAtBase::ProcessRoot, posix::STAT_NOFOLLOW, path))
        {
            Ok(s) if s.uid == 0 && s.mode & 0o170000 == 0o100000 && s.mode & 0o077 == 0 => {}
            Err(e) if e.raw() == -2 => {}
            _ => return Err(denied()),
        }
    }
    Ok(())
}

pub(super) fn load() -> Result<model::Model, SysError> {
    validate()?;
    files::recover_policy_file(LEDGER)?;
    match files::read_file_bounded(LEDGER.current, wire::MAX_SNAPSHOT + 32) {
        Ok(bytes) => model::Model::decode(&bytes).ok_or_else(|| SysError::from_raw(-22)),
        Err(e) if e.raw() == -2 => Ok(model::Model::default()),
        Err(e) => Err(e),
    }
}

pub(super) fn save(model: &model::Model) -> Result<(), SysError> {
    validate()?;
    files::replace_policy_file(LEDGER, &model.encode(), 0o600)
}
