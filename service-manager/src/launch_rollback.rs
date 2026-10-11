use crate::native_process::NativeProcess;
use crate::spawn_support::sys_error;
use mochi_user_platform as platform;

struct FailedLaunch {
    process: NativeProcess,
    client: mochios_posix_client::Client<mochios_posix_client::SyscallEndpointTransport>,
    last_error: Option<u64>,
}

// Process-local supervisor state. Only this service's launch callbacks and
// main loop access it; no PID lookup can add authority to this queue.
static FAILED_LAUNCHES: std::sync::Mutex<alloc::collections::VecDeque<FailedLaunch>> =
    std::sync::Mutex::new(alloc::collections::VecDeque::new());

pub(crate) fn retain_failed_launch(process: NativeProcess, endpoint: platform::handle::Handle) {
    // The endpoint is the manager's POSIX endpoint, retained for its
    // entire lifetime. The queue owns the failed creation reference itself.
    FAILED_LAUNCHES.lock().unwrap().push_back(FailedLaunch {
        process,
        client: mochios_posix_client::Client::new(
            mochios_posix_client::SyscallEndpointTransport::new(endpoint),
        ),
        last_error: None,
    });
}

pub(crate) fn retry_failed_launch_cleanup() {
    // Never hold the queue lock while calling the kernel or making an RPC.
    let Some(mut pending) = FAILED_LAUNCHES.lock().unwrap().pop_front() else {
        return;
    };
    let result = pending.process.retry_rollback(|handle| {
        // ESRCH is idempotent only after this exact retained object's exit is
        // known: registration may never have happened or a reply was lost.
        match pending
            .client
            .abort_launched_child(mochios_posix_client::ObjectHandleAttachment {
                handle,
                rights: mnu_abi::HANDLE_RIGHT_WAIT,
            }) {
            Ok(()) => Ok(()),
            Err(mochios_posix_client::ClientError::Remote(status))
                if status == mochios_posix_protocol::STATUS_ESRCH =>
            {
                Ok(())
            }
            Err(mochios_posix_client::ClientError::Transport(error)) => Err(error),
            Err(mochios_posix_client::ClientError::Remote(status)) => {
                Err(sys_error(status.unsigned_abs() as u64))
            }
            Err(_) => Err(sys_error(mochi_user_syscall::EIO)),
        }
    });
    if let Err(error) = result {
        let status = crate::spawn_support::errno(error);
        if pending.last_error != Some(status) {
            platform::logln!(
                "service-manager.service: failed launch cleanup pending errno={}",
                status
            );
            pending.last_error = Some(status);
        }
        FAILED_LAUNCHES.lock().unwrap().push_back(pending);
        let _ = platform::thread::sleep_milliseconds(10);
    }
    // Successful cleanup drops only this owner's creation reference.
}

pub(crate) fn has_failed_launch_cleanup() -> bool {
    !FAILED_LAUNCHES.lock().unwrap().is_empty()
}
