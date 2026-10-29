//! Capture one authenticated IPC sender, never a request-supplied PID/path.
use mochi_user_platform as p;
use p::syscall::{NativeError, SysError};

pub(crate) struct ProcessReference(pub u32);
impl Drop for ProcessReference {
    fn drop(&mut self) {
        let _ = p::handle::close(self.0);
    }
}

pub(crate) struct Peer {
    pub instance: crate::consent::Instance,
    pub context: p::syscall::ThreadSecurityContext,
    pub process: ProcessReference,
}

fn denied() -> SysError {
    SysError::from_raw(NativeError::AccessDenied.into_raw() as i64)
}

pub(crate) fn capture(endpoint: u64) -> Result<Peer, SysError> {
    if endpoint == 0 {
        return Err(denied());
    }
    let first = p::ipc::endpoint_execution_identity(endpoint)?;
    let process = ProcessReference(p::process::open_handle_for_endpoint(
        endpoint,
        p::handle::HANDLE_RIGHT_WAIT,
    )?);
    let before = p::process::image_info(Some(process.0))?;
    let context = p::process::thread_security_context(endpoint)?;
    let after = p::process::image_info(Some(process.0))?;
    let last = p::ipc::endpoint_execution_identity(endpoint)?;
    // Both process measurement reads serialize with image commit. The final
    // endpoint query also refuses a retired IPC generation. Keep the exact
    // native object owned; IDs alone must not stand in for this reference.
    if first != last
        || first.process_id == 0
        || first.thread_id == 0
        || first.process_id != before.process_id
        || before != after
        || after.digest_kind != p::syscall::PROCESS_IMAGE_DIGEST_SHA256
        || context.process_id != first.process_id
        || context.thread_id != first.thread_id
        || context.reserved0 != [0; 7]
        || context.reserved1 != 0
        || context.package_id_len as usize > context.package_id.len()
        || context.developer_id_len as usize > context.developer_id.len()
    {
        return Err(denied());
    }
    Ok(Peer {
        instance: crate::consent::Instance {
            endpoint,
            process: after.process_id,
            thread: first.thread_id,
            revision: after.image_revision,
            digest: after.digest,
        },
        context,
        process,
    })
}
