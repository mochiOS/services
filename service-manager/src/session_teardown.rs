use alloc::collections::BTreeMap;
use mochios_posix_client::{Client, ClientError, ObjectTransport};

use crate::native_process::NativeProcess;

/// A logout owns one ordered teardown transaction. Validate every root before
/// touching any process; request Binder's termination only after the other
/// roots have exited. The caller must also defer Binder's logout acknowledgement:
/// Binder voluntarily exits as soon as it receives that acknowledgement.
/// Only a confirmed reply advances the cursor, including across retries.
#[derive(Debug)]
pub(crate) struct SessionTeardown {
    roots: [Option<u64>; 3],
    cursor: usize,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum TeardownError {
    InvalidRoot,
    MissingOwner,
}

impl SessionTeardown {
    pub(crate) fn begin(
        linux: Option<u64>,
        workspace: u64,
        binder: u64,
        owners: &BTreeMap<u64, NativeProcess>,
    ) -> Result<Self, TeardownError> {
        let roots = [linux, Some(workspace), Some(binder)];
        for (index, root) in roots.iter().enumerate() {
            if let Some(process_id) = root {
                if *process_id == 0 || roots[..index].contains(root) {
                    return Err(TeardownError::InvalidRoot);
                }
                if !owners.contains_key(process_id) {
                    return Err(TeardownError::MissingOwner);
                }
            }
        }
        Ok(Self { roots, cursor: 0 })
    }

    /// The resident loop uses this boundary to acknowledge logout immediately
    /// before Binder's final step, not while other session roots still run.
    pub(crate) fn pending_root(&self) -> Option<u64> {
        self.roots[self.cursor..].iter().flatten().next().copied()
    }

    /// Attempt at most one root per resident-loop iteration. Errors leave the
    /// pending root intact; completed roots are never sent or closed twice.
    /// `true` is the only state in which a new login may begin.
    pub(crate) fn step<E>(
        &mut self,
        mut terminate: impl FnMut(u64) -> Result<(), E>,
    ) -> Result<bool, E> {
        while self.cursor < self.roots.len() {
            let Some(process_id) = self.roots[self.cursor] else {
                self.cursor += 1;
                continue;
            };
            terminate(process_id)?;
            self.cursor += 1;
            return Ok(self.cursor == self.roots.len());
        }
        Ok(true)
    }
}

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
