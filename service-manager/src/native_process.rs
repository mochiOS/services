use mochi_user_platform as platform;

/// Owns the reference returned by native creation, including after thread exit.
/// This is deliberately neither Copy nor Clone: a raw handle is not an owner.
#[derive(Debug)]
pub(crate) struct NativeProcess {
    handle: platform::handle::Handle,
}

impl NativeProcess {
    pub(crate) fn create_and_resume(
        image: platform::handle::Handle,
        metadata: &[u8],
    ) -> Result<Self, platform::syscall::SysError> {
        let process = Self {
            handle: platform::process::create_stopped(image, metadata)?,
        };
        if let Err(error) = platform::process::resume_handle(process.handle) {
            // Creation published a stopped task; do not strand it on failure.
            let _ = platform::process::terminate_handle(process.handle, 127);
            return Err(error);
        }
        Ok(process)
    }

    pub(crate) fn watch_target(&self) -> crate::process_watch::ProcessWatchTarget {
        crate::process_watch::ProcessWatchTarget::RetainedHandle(self.handle)
    }
}

impl Drop for NativeProcess {
    fn drop(&mut self) {
        let _ = platform::handle::close(self.handle);
    }
}
