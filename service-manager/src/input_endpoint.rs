//! Acquire driver ingress from the retained input process, never a name alone.
use mochi_user_platform as p;

pub(crate) const RIGHTS: u64 = p::handle::HANDLE_RIGHT_SEND
    | p::handle::HANDLE_RIGHT_DUPLICATE
    | p::handle::HANDLE_RIGHT_TRANSFER;

pub(crate) struct Endpoint(pub u32);

impl Drop for Endpoint {
    fn drop(&mut self) {
        let _ = p::handle::close(self.0);
    }
}

fn invalid() -> p::syscall::SysError {
    p::syscall::SysError::from_raw(p::syscall::NativeError::InvalidArgument.into_raw() as i64)
}

pub(crate) fn acquire(expected_process: u64) -> Result<Endpoint, p::syscall::SysError> {
    let address = p::process::find_by_name("input.service")?;
    let before = p::ipc::endpoint_execution_identity(address)?;
    if expected_process == 0 || before.process_id != expected_process {
        return Err(invalid());
    }
    let mut handles = p::ipc::IpcObjectHandles::default();
    let mut reply = [0; 8];
    let result = p::ipc::call_object_handles(
        u32::try_from(address).map_err(|_| invalid())?,
        &p::input::RAW_ENDPOINT_REQUEST,
        &mut reply,
        &mut handles,
    );
    let result = (|| {
        let message = result?;
        if message >> 32 != address
            || message as u32 != 8
            || p::ipc::endpoint_execution_identity(address)? != before
            || !handles.is_user_delivery()
        {
            return Err(invalid());
        }
        let status = u64::from_le_bytes(reply);
        if status != 0 {
            return Err(p::syscall::SysError::from_raw(status as i64));
        }
        if handles.count != 1
            || handles.handles[0].handle == 0
            || handles.handles[0].reserved != 0
            || handles.handles[0].rights != RIGHTS
        {
            return Err(invalid());
        }
        let endpoint = Endpoint(handles.handles[0].handle);
        handles.handles[0].handle = 0;
        Ok(endpoint)
    })();
    for entry in handles.handles.iter().take(handles.count as usize) {
        if entry.handle != 0 {
            let _ = p::handle::close(entry.handle);
        }
    }
    result
}
