use std::sync::Mutex;

use mochi_user_platform as platform;
use mochios_posix_client::{
    Client, ClientError, EndpointTransport, ObjectHandleAttachment, OpenAtBase, StatAtBase,
};
use mochios_posix_protocol as posix;

type PosixClient = Client<EndpointTransport>;

static POSIX_CLIENT: Mutex<Option<PosixClient>> = Mutex::new(None);

fn sys_error(errno: u64) -> mochi_user_syscall::SysError {
    mochi_user_syscall::SysError::from_raw(errno as i64)
}

fn client_error(error: ClientError<mochi_user_syscall::SysError>) -> mochi_user_syscall::SysError {
    match error {
        ClientError::Transport(error) => error,
        ClientError::Remote(status) => mochi_user_syscall::SysError::from_raw(status as i64),
        ClientError::Protocol(_)
        | ClientError::RequestTooLarge
        | ClientError::ResponseTooLarge
        | ClientError::MismatchedResponse => sys_error(mochi_user_syscall::EIO),
    }
}

fn with_client<T>(
    operation: impl FnOnce(&PosixClient) -> Result<T, ClientError<mochi_user_syscall::SysError>>,
) -> Result<T, mochi_user_syscall::SysError> {
    let installed = POSIX_CLIENT
        .lock()
        .map_err(|_| sys_error(mochi_user_syscall::EIO))?;
    let client = installed
        .as_ref()
        .ok_or_else(|| sys_error(mochi_user_syscall::EAGAIN))?;
    operation(client).map_err(client_error)
}

pub fn install_endpoint(
    endpoint: platform::handle::Handle,
) -> Result<(), mochi_user_syscall::SysError> {
    let client = Client::new(EndpointTransport::new(endpoint));
    if let Err(error) = client.register_session() {
        let _ = platform::handle::close(endpoint);
        return Err(client_error(error));
    }
    let mut installed = POSIX_CLIENT
        .lock()
        .map_err(|_| sys_error(mochi_user_syscall::EIO))?;
    if let Some(previous) = installed.replace(client) {
        let _ = platform::handle::close(previous.into_transport().endpoint());
    }
    Ok(())
}

pub fn ensure_directory(path: &str, mode: u32) -> Result<(), mochi_user_syscall::SysError> {
    const FILE_TYPE_MASK: u32 = 0xf000;
    const DIRECTORY: u32 = 0x4000;
    match with_client(|client| client.stat_at(StatAtBase::ProcessRoot, 0, path)) {
        Ok(status) if status.mode & FILE_TYPE_MASK == DIRECTORY => Ok(()),
        Ok(_) => Err(sys_error(mochi_user_syscall::ENOTDIR)),
        Err(error) if error.errno() == Some(mochi_user_syscall::ENOENT) => {
            with_client(|client| client.mkdir_at(OpenAtBase::ProcessRoot, mode, path))
        }
        Err(error) => Err(error),
    }
}

pub fn append_and_sync(
    path: &str,
    line: &[u8],
    mode: u32,
) -> Result<(), mochi_user_syscall::SysError> {
    let file = with_client(|client| {
        client.open_at(
            OpenAtBase::ProcessRoot,
            posix::OPEN_WRITE | posix::OPEN_CREATE | posix::OPEN_APPEND,
            mode,
            path,
        )
    })?;
    let mut offset = 0usize;
    while offset < line.len() {
        match platform::handle::write(file.handle, &line[offset..]) {
            Ok(0) => {
                let _ = platform::handle::close(file.handle);
                return Err(sys_error(mochi_user_syscall::EIO));
            }
            Ok(written) => offset += written,
            Err(error) => {
                let _ = platform::handle::close(file.handle);
                return Err(error);
            }
        }
    }
    let sync = with_client(|client| {
        client.fsync(ObjectHandleAttachment {
            handle: file.handle,
            rights: platform::handle::HANDLE_RIGHT_TRANSFER,
        })
    });
    let close = platform::handle::close(file.handle);
    sync?;
    close
}
