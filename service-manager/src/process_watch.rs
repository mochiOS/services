use mochi_user_platform as platform;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ProcessWatchError {
    ResolveLaunchThread(u64),
    OpenProcess(u64),
    ReadStatus(u64),
}

impl ProcessWatchError {
    pub(crate) fn errno(self) -> u64 {
        match self {
            Self::ResolveLaunchThread(errno)
            | Self::OpenProcess(errno)
            | Self::ReadStatus(errno) => errno,
        }
    }
}

pub(crate) struct ProcessWatch {
    handle: platform::handle::Handle,
}

impl ProcessWatch {
    pub(crate) fn open(launch_thread: u64) -> Result<Self, ProcessWatchError> {
        // Manifest launch returns a thread ID, not a process ID or an opaque
        // endpoint handle. Resolve its owner using capability-gated inspection.
        let context = platform::process::thread_security_context(launch_thread)
            .map_err(|error| ProcessWatchError::ResolveLaunchThread(error.raw().unsigned_abs()))?;
        let handle = platform::process::open_handle_for_process_id(
            context.process_id,
            platform::handle::HANDLE_RIGHT_WAIT,
        )
        .map_err(|error| ProcessWatchError::OpenProcess(error.raw().unsigned_abs()))?;
        Ok(Self { handle })
    }

    pub(crate) fn exit_status(&self) -> Result<Option<i32>, ProcessWatchError> {
        let status = platform::process::handle_status(self.handle)
            .map_err(|error| ProcessWatchError::ReadStatus(error.raw().unsigned_abs()))?;
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
