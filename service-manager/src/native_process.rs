use mochi_user_platform as platform;

/// Owns the reference returned by native creation, including after thread exit.
/// This is deliberately neither Copy nor Clone: a raw handle is not an owner.
#[derive(Debug)]
pub(crate) struct NativeProcess {
    handle: platform::handle::Handle,
    process_id: u64,
    tree_exit_confirmed: bool,
}

impl NativeProcess {
    /// Transfer the creation owner to rollback when setup or resume fails.
    /// Termination is only a request: rollback must retain this owner until
    /// native exit and userspace registration cleanup are confirmed. This also
    /// covers a lost registration reply. Preserve the original launch error.
    pub(crate) fn create_with_rollback(
        image: platform::handle::Handle,
        metadata: &[u8],
        setup: impl FnOnce(platform::handle::Handle) -> Result<(), platform::syscall::SysError>,
        rollback: impl FnOnce(Self),
    ) -> Result<Self, platform::syscall::SysError> {
        let (handle, process_id) = mochios_posix_client::process_creation::create_with_rollback(
            || platform::process::create_stopped(image, metadata),
            setup,
            |handle| platform::process::handle_status(handle).map(|status| status.process_id),
            platform::process::resume_handle,
            |handle| {
                let _ = platform::process::terminate_handle(handle, 127);
            },
            |handle| {
                rollback(Self {
                    handle,
                    process_id: 0,
                    tree_exit_confirmed: false,
                })
            },
        )?;
        Ok(Self {
            handle,
            process_id,
            tree_exit_confirmed: false,
        })
    }

    pub(crate) fn watch_target(&self) -> crate::process_watch::ProcessWatchTarget {
        crate::process_watch::ProcessWatchTarget::RetainedHandle(self.handle)
    }

    pub(crate) fn terminate(&self) {
        let _ = platform::process::terminate_handle(self.handle, 127);
    }

    /// Retry rollback through this retained object, never a PID lookup. A
    /// failed query or unconfirmed termination cannot discard registration.
    pub(crate) fn retry_rollback(
        &self,
        reclaim: impl FnOnce(platform::handle::Handle) -> Result<(), platform::syscall::SysError>,
    ) -> Result<(), platform::syscall::SysError> {
        let mut status = platform::process::handle_status(self.handle)?;
        if status.state != mnu_abi::PROCESS_STATE_EXITED {
            platform::process::terminate_handle(self.handle, 127)?;
            status = platform::process::handle_status(self.handle)?;
            if status.state != mnu_abi::PROCESS_STATE_EXITED {
                return Err(platform::syscall::SysError::from_raw(
                    mnu_abi::EAGAIN as i64,
                ));
            }
        }
        reclaim(self.handle)
    }

    pub(crate) fn process_id(&self) -> u64 {
        self.process_id
    }

    pub(crate) fn termination_attachment(
        &self,
    ) -> mochios_posix_client::ObjectHandleAttachment<platform::handle::Handle> {
        mochios_posix_client::ObjectHandleAttachment {
            handle: self.handle,
            rights: platform::handle::HANDLE_RIGHT_WAIT | platform::handle::HANDLE_RIGHT_SIGNAL,
        }
    }

    pub(crate) fn tree_exit_confirmed(&self) -> bool {
        self.tree_exit_confirmed
    }

    /// Record only an authenticated successful reply for this owner's root.
    /// Native root exit alone does not prove that all its descendants exited.
    pub(crate) fn confirm_tree_exit(&mut self) {
        self.tree_exit_confirmed = true;
    }
}

impl Drop for NativeProcess {
    fn drop(&mut self) {
        let _ = platform::handle::close(self.handle);
    }
}
