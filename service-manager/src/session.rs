use mochi_user_platform as platform;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ActiveSession {
    pub(crate) id: u64,
    pub(crate) identity: platform::service_ready::SessionIdentity,
    pub(crate) linux_pid: Option<u64>,
    pub(crate) workspace_pid: u64,
    pub(crate) binder_pid: u64,
}

impl ActiveSession {
    /// IDs are obtained from owned native ProcessHandles, never launch threads.
    pub(crate) fn from_process_ids(
        id: u64,
        identity: platform::service_ready::SessionIdentity,
        linux_pid: Option<u64>,
        workspace_pid: u64,
        binder_pid: u64,
    ) -> Result<Self, mochi_user_syscall::SysError> {
        if workspace_pid == 0 || binder_pid == 0 || linux_pid == Some(0) {
            return Err(mochi_user_syscall::SysError::from_raw(
                mochi_user_syscall::EINVAL as i64,
            ));
        }
        Ok(Self {
            id,
            identity,
            linux_pid,
            workspace_pid,
            binder_pid,
        })
    }

    pub(crate) fn next_id(self) -> u64 {
        self.id.wrapping_add(1).max(1)
    }
}
