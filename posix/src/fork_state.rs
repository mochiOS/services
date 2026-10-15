//! Service-owned fork preparation. Tokens are scoped to authenticated process
//! identity; they neither identify native objects nor grant native authority.
use super::*;

const MAX_PREPARED_FORKS: usize = 1024;
const MAX_PREPARED_FORKS_PER_PROCESS: usize = 64;

/// `status` must have been read from this exact attached object through the
/// native Handle API, never decoded from client request bytes. mnu enforces
/// the Process object type and WAIT right when producing that status.
pub fn validate_fork_child(
    object: AttachedObject<u32>,
    status: mnu_abi::ProcessStatus,
) -> Result<AuthenticatedProcess<u32>, i32> {
    if object.handle == 0
        || object.rights != mnu_abi::HANDLE_RIGHT_WAIT | mnu_abi::HANDLE_RIGHT_SIGNAL
        || status.process_id == 0
        || status.reserved != 0
    {
        return Err(STATUS_EINVAL);
    }
    if status.state != mnu_abi::PROCESS_STATE_RUNNING {
        return Err(protocol::STATUS_ESRCH);
    }
    Ok(AuthenticatedProcess {
        handle: object.handle,
        process_id: status.process_id,
    })
}

#[derive(Debug)]
pub(super) struct ForkState<H: Copy> {
    owner: u64,
    session: Session,
    directories: Option<SessionDirectories<H>>,
    group: u64,
    session_id: u64,
    groups: Vec<u32>,
    limits: Vec<(u32, protocol::ResourceLimit)>,
    signals: ProcessSignalState,
    child_options: u32,
}

impl<H: Copy> ForkState<H> {
    pub(super) fn owned_by(&self, process: u64) -> bool {
        self.owner == process
    }

    fn release<F: FilesystemBackend<H>>(self, filesystem: &mut F) {
        if let Some(directories) = self.directories {
            filesystem.release_object(directories.root);
            filesystem.release_object(directories.cwd);
        }
    }
}

impl<H: Copy> PosixService<H> {
    /// Freeze inherited process-wide POSIX policy before capturing VM state.
    /// Call under the service state lock. IPC callers must supply only the
    /// kernel-authenticated sender identity. Thread masks remain caller-local
    /// and must be restored by the runtime in the new native thread.
    pub fn prepare_fork<F: FilesystemBackend<H>>(
        &mut self,
        peer: PeerIdentity,
        filesystem: &mut F,
    ) -> Result<u64, i32> {
        let owner = peer.process_id;
        if !self.processes.contains_key(&owner) {
            return Err(protocol::STATUS_ESRCH);
        }
        if self.tree_teardown_owns(owner)
            || self
                .process_wait_states
                .get(&owner)
                .is_some_and(|state| state.exit_observed)
            || self.prepared_forks.len() >= MAX_PREPARED_FORKS
            || self
                .prepared_forks
                .iter()
                .filter(|(_, state)| state.owned_by(owner))
                .count()
                >= MAX_PREPARED_FORKS_PER_PROCESS
        {
            return Err(protocol::STATUS_EAGAIN);
        }
        let token = self.next_fork_token;
        let next = token.checked_add(1).ok_or(STATUS_EOVERFLOW)?;
        let session = *self.sessions.get(&owner).ok_or(protocol::STATUS_ESRCH)?;
        let group = *self
            .process_groups
            .get(&owner)
            .ok_or(protocol::STATUS_ESRCH)?;
        let session_id = *self.session_ids.get(&owner).ok_or(protocol::STATUS_ESRCH)?;
        let signals = self
            .signals
            .get(&owner)
            .copied()
            .ok_or(protocol::STATUS_ESRCH)?
            .fork_child();
        let child_options = self.signal_child_options.get(&owner).copied().unwrap_or(0);
        let memberships = self
            .supplementary_groups
            .get(&owner)
            .map(Vec::as_slice)
            .unwrap_or(&[]);
        let mut groups = Vec::new();
        groups
            .try_reserve_exact(memberships.len())
            .map_err(|_| -12)?;
        groups.extend_from_slice(memberships);
        let mut limits = Vec::new();
        let inherited = self.resource_limits.range((owner, 0)..=(owner, u32::MAX));
        limits
            .try_reserve_exact(inherited.clone().count())
            .map_err(|_| -12)?;
        limits.extend(inherited.map(|(&(_, resource), &limit)| (resource, limit)));
        self.prepared_forks.try_reserve(1).map_err(|_| -12)?;
        let directories = if let Some(parent) = self.directories.get(&owner).copied() {
            let root = filesystem.retain_object(parent.root)?;
            let cwd = match filesystem.retain_object(parent.cwd) {
                Ok(cwd) => cwd,
                Err(error) => {
                    filesystem.release_object(root);
                    return Err(error);
                }
            };
            Some(SessionDirectories { root, cwd })
        } else {
            None
        };
        self.prepared_forks.push((
            token,
            ForkState {
                owner,
                session,
                directories,
                group,
                session_id,
                groups,
                limits,
                signals,
                child_options,
            },
        ));
        self.next_fork_token = next;
        Ok(token)
    }

    fn fork_index(&self, peer: PeerIdentity, token: u64) -> Result<usize, i32> {
        let index = self
            .prepared_forks
            .iter()
            .position(|(key, _)| *key == token)
            .ok_or(protocol::STATUS_ESRCH)?;
        if !self.prepared_forks[index].1.owned_by(peer.process_id) {
            return Err(protocol::STATUS_EPERM);
        }
        Ok(index)
    }

    /// Release only this sender's preparation; no child exists or is resumed.
    /// Tokens are never reused, so ESRCH also denotes an already consumed token.
    pub fn cancel_fork<F: FilesystemBackend<H>>(
        &mut self,
        peer: PeerIdentity,
        token: u64,
        filesystem: &mut F,
    ) -> Result<(), i32> {
        let index = self.fork_index(peer, token)?;
        self.prepared_forks.swap_remove(index).1.release(filesystem);
        Ok(())
    }

    /// Install exactly the prepared policy on an authenticated, stopped native
    /// child. The caller validates the ProcessHandle and retains it on failure;
    /// a failed commit keeps the preparation available for retry or cancel.
    pub fn commit_fork(
        &mut self,
        peer: PeerIdentity,
        token: u64,
        process: AuthenticatedProcess<H>,
    ) -> Result<(), i32> {
        let index = self.fork_index(peer, token)?;
        if self.tree_teardown_owns(peer.process_id) {
            return Err(protocol::STATUS_EAGAIN);
        }
        if process.process_id == 0
            || process.process_id == peer.process_id
            || !self.processes.contains_key(&peer.process_id)
            || self.processes.contains_key(&process.process_id)
            || self.sessions.contains_key(&process.process_id)
        {
            return Err(STATUS_EINVAL);
        }
        if self
            .process_wait_states
            .get(&peer.process_id)
            .is_some_and(|state| state.exit_observed)
        {
            return Err(protocol::STATUS_ESRCH);
        }
        let state = self.prepared_forks.swap_remove(index).1;
        let child = process.process_id;
        self.processes.insert(child, process.handle);
        self.sessions.insert(
            child,
            Session {
                process_id: child,
                ..state.session
            },
        );
        if let Some(directories) = state.directories {
            self.directories.insert(child, directories);
        }
        self.parents.insert(child, state.owner);
        self.launch_creators.insert(child, state.owner);
        self.process_groups.insert(child, state.group);
        self.session_ids.insert(child, state.session_id);
        self.supplementary_groups.insert(child, state.groups);
        self.children.entry(state.owner).or_default().insert(child);
        self.signals.insert(child, state.signals);
        self.signal_child_options.insert(child, state.child_options);
        self.process_wait_states
            .insert(child, ProcessWaitState::default());
        for (resource, limit) in state.limits {
            self.resource_limits.insert((child, resource), limit);
        }
        Ok(())
    }

    /// Reclaim abandoned preparations only after the native owner is confirmed
    /// exited. A status failure never revokes a still-live owner's references.
    pub fn reap_abandoned_forks<F: FilesystemBackend<H>, P: ProcessBackend<H>>(
        &mut self,
        filesystem: &mut F,
        processes: &mut P,
    ) -> Result<usize, i32> {
        let mut index = 0;
        let mut reaped = 0;
        while index < self.prepared_forks.len() {
            let owner = self.prepared_forks[index].1.owner;
            let handle = *self.processes.get(&owner).ok_or(protocol::STATUS_ESRCH)?;
            if matches!(processes.status(handle)?, ProcessLifecycle::Exited { .. }) {
                self.prepared_forks.swap_remove(index).1.release(filesystem);
                reaped += 1;
            } else {
                index += 1;
            }
        }
        Ok(reaped)
    }

    pub(super) fn cancel_owned_forks<F: FilesystemBackend<H>>(
        &mut self,
        owner: u64,
        filesystem: &mut F,
    ) {
        let mut index = 0;
        while index < self.prepared_forks.len() {
            if self.prepared_forks[index].1.owned_by(owner) {
                self.prepared_forks.swap_remove(index).1.release(filesystem);
            } else {
                index += 1;
            }
        }
    }
}
