use mochi_user_platform as platform;

pub(crate) struct ProcessWatch {
    handle: platform::handle::Handle,
}

impl ProcessWatch {
    pub(crate) fn open(launch_thread: u64) -> Result<Self, mochi_user_syscall::SysError> {
        // Manifest launch returns a thread ID, not a process ID or an opaque
        // endpoint handle. Resolve its owner using capability-gated inspection.
        let context = platform::process::thread_security_context(launch_thread)?;
        let handle = platform::process::open_handle_for_process_id(
            context.process_id,
            platform::handle::HANDLE_RIGHT_WAIT,
        )?;
        Ok(Self { handle })
    }

    pub(crate) fn exit_status(&self) -> Result<Option<i32>, mochi_user_syscall::SysError> {
        let status = platform::process::handle_status(self.handle)?;
        if status.state == platform::process::PROCESS_STATE_EXITED {
            Ok(Some(status.exit_code as i32))
        } else {
            Ok(None)
        }
    }
}

impl Drop for ProcessWatch {
    fn drop(&mut self) {
        let _ = platform::handle::close(self.handle);
    }
}
