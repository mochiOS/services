use mochi_user_platform as platform;

/// Owns the reference returned by native creation, including after thread exit.
/// This is deliberately neither Copy nor Clone: a raw handle is not an owner.
#[derive(Debug)]
pub(crate) struct NativeProcess {
    handle: platform::handle::Handle,
    process_id: u64,
}

impl NativeProcess {
    pub(crate) fn create_and_resume(
        image: platform::handle::Handle,
        metadata: &[u8],
    ) -> Result<Self, platform::syscall::SysError> {
        Self::create_with_setup(image, metadata, |_| Ok(()))
    }

    /// Initialize userspace state before allowing the new image to execute.
    /// The callback receives this owner's creation reference, never a PID/FD
    /// lookup. Failure terminates the stopped task and releases the reference.
    pub(crate) fn create_with_setup(
        image: platform::handle::Handle,
        metadata: &[u8],
        setup: impl FnOnce(platform::handle::Handle) -> Result<(), platform::syscall::SysError>,
    ) -> Result<Self, platform::syscall::SysError> {
        Self::create_with_rollback(image, metadata, setup, |_| {})
    }

    /// Roll back userspace registration when setup or resume fails. Rollback
    /// runs after termination but before closing the owner's creation Handle,
    /// including when a registration reply was lost. Preserve the first error.
    pub(crate) fn create_with_rollback(
        image: platform::handle::Handle,
        metadata: &[u8],
        setup: impl FnOnce(platform::handle::Handle) -> Result<(), platform::syscall::SysError>,
        rollback: impl FnOnce(platform::handle::Handle),
    ) -> Result<Self, platform::syscall::SysError> {
        let mut process = Self {
            handle: platform::process::create_stopped(image, metadata)?,
            process_id: 0,
        };
        if let Err(error) = setup(process.handle) {
            process.terminate();
            rollback(process.handle);
            return Err(error);
        }
        // Resolve identity inside the launch transaction, while still stopped.
        // A status failure after resume would otherwise strand a running child
        // and its POSIX registration when the caller drops this owner.
        process.process_id = match platform::process::handle_status(process.handle) {
            Ok(status) => status.process_id,
            Err(error) => {
                process.terminate();
                rollback(process.handle);
                return Err(error);
            }
        };
        if let Err(error) = platform::process::resume_handle(process.handle) {
            // Creation published a stopped task; do not strand it on failure.
            let _ = platform::process::terminate_handle(process.handle, 127);
            rollback(process.handle);
            return Err(error);
        }
        Ok(process)
    }

    pub(crate) fn watch_target(&self) -> crate::process_watch::ProcessWatchTarget {
        crate::process_watch::ProcessWatchTarget::RetainedHandle(self.handle)
    }

    pub(crate) fn terminate(&self) {
        let _ = platform::process::terminate_handle(self.handle, 127);
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
}

impl Drop for NativeProcess {
    fn drop(&mut self) {
        let _ = platform::handle::close(self.handle);
    }
}
