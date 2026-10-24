//! Complete synchronous calls and one-way requests through their native paths.
use mochi_user_platform as platform;

pub(crate) fn send(sender: u64, bytes: &[u8]) {
    if let Err(error) = platform::ipc::reply(sender, bytes) {
        if error.native_error() == Some(mochi_user_syscall::NativeError::AccessDenied) {
            // A one-way request has no call-reply capability. Its authenticated
            // sender endpoint is the completion queue, as in the existing ABI.
            let _ = platform::ipc::send(sender, bytes);
        }
    }
}
