use mochi_user_platform as platform;

pub(crate) struct ProcessWatch {
    handle: platform::handle::Handle,
}

impl ProcessWatch {
    pub(crate) fn open(launch_endpoint: u64) -> Result<Self, mochi_user_syscall::SysError> {
        // Manifest launch returns the initial thread's IPC endpoint, not a
        // process ID. They diverge as soon as any service creates a thread.
        let handle = platform::process::open_handle_for_endpoint(
            launch_endpoint,
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
