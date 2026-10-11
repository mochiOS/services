use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use mochios_posix_client::{Client, ClientError, ObjectTransport};

use crate::native_process::NativeProcess;

/// A logout owns one ordered teardown transaction. Validate every root before
/// touching any process; request Binder's termination only after the other
/// roots have exited. The caller must also defer Binder's logout acknowledgement:
/// Binder voluntarily exits as soon as it receives that acknowledgement.
/// Only a confirmed reply advances the cursor, including across retries.
#[derive(Debug)]
pub(crate) struct SessionTeardown {
    roots: Vec<u64>,
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
        Self::from_roots(
            [linux, Some(workspace), Some(binder)]
                .into_iter()
                .flatten()
                .collect(),
            owners,
        )
    }

    /// Roll back only the roots recorded by this unpublished launch, in reverse
    /// creation order. Validate the whole batch before attempting any teardown.
    pub(crate) fn begin_failed_launch(
        launched: &[u64],
        owners: &BTreeMap<u64, NativeProcess>,
    ) -> Result<Self, TeardownError> {
        Self::from_roots(launched.iter().rev().copied().collect(), owners)
    }

    fn from_roots(
        roots: Vec<u64>,
        owners: &BTreeMap<u64, NativeProcess>,
    ) -> Result<Self, TeardownError> {
        for (index, root) in roots.iter().enumerate() {
            if *root == 0 || roots[..index].contains(root) {
                return Err(TeardownError::InvalidRoot);
            }
            if !owners.contains_key(root) {
                return Err(TeardownError::MissingOwner);
            }
        }
        Ok(Self { roots, cursor: 0 })
    }

    /// The resident loop uses this boundary to acknowledge logout immediately
    /// before Binder's final step, not while other session roots still run.
    pub(crate) fn pending_root(&self) -> Option<u64> {
        self.roots.get(self.cursor).copied()
    }

    /// Attempt at most one root per resident-loop iteration. Errors leave the
    /// pending root intact; completed roots are never sent or closed twice.
    /// `true` is the only state in which a new login may begin.
    pub(crate) fn step<E>(
        &mut self,
        mut terminate: impl FnMut(u64) -> Result<(), E>,
    ) -> Result<bool, E> {
        if let Some(process_id) = self.pending_root() {
            terminate(process_id)?;
            self.cursor += 1;
            return Ok(self.cursor == self.roots.len());
        }
        Ok(true)
    }
}

/// Select only a process owner retained by this launcher. Never capture a new
/// reference by PID. A failed or delayed service reply must preserve the owner
/// for retry. Release only after confirmed tree exit and a successful (or
/// already completed) reclaim, never based on the root's native exit alone.
pub(crate) fn terminate_owned_root<T: ObjectTransport<Handle = u32>>(
    client: &Client<T>,
    owners: &mut BTreeMap<u64, NativeProcess>,
    process_id: u64,
) -> Result<(), ClientError<T::Error>> {
    let process = owners
        .get_mut(&process_id)
        .ok_or(ClientError::Remote(mochios_posix_protocol::STATUS_ESRCH))?;
    if !process.tree_exit_confirmed() {
        client.terminate_launched_tree(process.termination_attachment())?;
        process.confirm_tree_exit();
    }
    match client.reclaim_launched_tree(process.termination_attachment()) {
        Ok(()) | Err(ClientError::Remote(mochios_posix_protocol::STATUS_ESRCH)) => {}
        Err(error) => return Err(error),
    }
    owners.remove(&process_id);
    Ok(())
}
