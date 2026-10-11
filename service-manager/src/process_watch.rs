use mochi_user_platform as platform;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ProcessWatchError {
    ResolveLaunchThread(u64),
    OpenProcess(u64),
    DuplicateProcess(u64),
    ReadStatus(u64),
}

impl ProcessWatchError {
    pub(crate) fn errno(self) -> u64 {
        match self {
            Self::ResolveLaunchThread(errno)
            | Self::OpenProcess(errno)
            | Self::DuplicateProcess(errno)
            | Self::ReadStatus(errno) => errno,
        }
    }
}

pub(crate) struct ProcessWatch {
    handle: platform::handle::Handle,
}

/// Keep legacy launch thread IDs and already-retained object handles distinct.
/// A native handle must never be reinterpreted as a thread or a PID.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ProcessWatchTarget {
    LaunchThread(u64),
    RetainedHandle(platform::handle::Handle),
}

impl From<u64> for ProcessWatchTarget {
    fn from(thread: u64) -> Self {
        Self::LaunchThread(thread)
    }
}

impl ProcessWatch {
    pub(crate) fn open(target: impl Into<ProcessWatchTarget>) -> Result<Self, ProcessWatchError> {
        let launch_thread = match target.into() {
            ProcessWatchTarget::LaunchThread(thread) => thread,
            ProcessWatchTarget::RetainedHandle(source) => {
                let handle =
                    platform::handle::duplicate(source, platform::handle::HANDLE_RIGHT_WAIT)
                        .map_err(|error| {
                            ProcessWatchError::DuplicateProcess(error.raw().unsigned_abs())
                        })?;
                let watch = Self { handle };
                // Reject wrong object kinds before entering the wait loop.
                // On error, Drop releases only the new reference, not source.
                watch.exit_status()?;
                return Ok(watch);
            }
        };
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
