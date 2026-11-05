//! Observe foreground ownership from retained POSIX state and native objects.
use crate::*;
impl<H: Copy> PosixService<H> {
    pub fn process_has_terminal(
        &self,
        caller: PeerIdentity,
        process: AuthenticatedProcess<H>,
        mut same: impl FnMut(H, H) -> Result<bool, i32>,
    ) -> Result<bool, i32> {
        let retained = *self
            .processes
            .get(&process.process_id)
            .ok_or(protocol::STATUS_ESRCH)?;
        if !same(retained, process.handle)? {
            return Err(protocol::STATUS_EPERM);
        }
        self.inspect_process_session(caller, process)?;
        Ok(self
            .session_ids
            .get(&process.process_id)
            .is_some_and(|session| self.controlling_terminals.contains_key(session)))
    }
    /// The terminal ID is resolved by its provider from an attached master.
    /// The Process object must match the retained registration, including PID
    /// reuse. This operation observes state without acquiring new authority.
    pub fn terminal_process_foreground(
        &self,
        caller: PeerIdentity,
        process: AuthenticatedProcess<H>,
        terminal: u64,
        mut same: impl FnMut(H, H) -> Result<bool, i32>,
    ) -> Result<bool, i32> {
        let retained = *self
            .processes
            .get(&process.process_id)
            .ok_or(protocol::STATUS_ESRCH)?;
        if !same(retained, process.handle)? {
            return Err(protocol::STATUS_EPERM);
        }
        self.inspect_process_session(caller, process)?;
        match self.terminal_foreground_process_group(process.process_id, terminal) {
            Ok(group) => Ok(self.process_groups.get(&process.process_id) == Some(&group)),
            Err(protocol::STATUS_ENOTTY) => Ok(false),
            Err(error) => Err(error),
        }
    }
}
