use alloc::string::{String, ToString};
use alloc::vec::Vec;
use std::sync::Mutex;

use mochi_user_platform as platform;
use mochios_posix_client::directory::DirectoryEntries;
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

fn attachment(
    handle: platform::handle::Handle,
) -> ObjectHandleAttachment<platform::handle::Handle> {
    ObjectHandleAttachment {
        handle,
        rights: platform::handle::HANDLE_RIGHT_TRANSFER,
    }
}

fn translate_open_flags(flags: u64) -> Result<u32, mochi_user_syscall::SysError> {
    const O_ACCMODE: u64 = 0o3;
    const O_WRONLY: u64 = 0o1;
    const O_RDWR: u64 = 0o2;
    const O_CREAT: u64 = 0o100;
    const O_EXCL: u64 = 0o200;
    const O_TRUNC: u64 = 0o1000;
    const SUPPORTED: u64 = O_ACCMODE | O_CREAT | O_EXCL | O_TRUNC;
    if flags & !SUPPORTED != 0 {
        return Err(sys_error(mochi_user_syscall::EINVAL));
    }
    let mut options = match flags & O_ACCMODE {
        0 => posix::OPEN_READ,
        O_WRONLY => posix::OPEN_WRITE,
        O_RDWR => posix::OPEN_READ | posix::OPEN_WRITE,
        _ => return Err(sys_error(mochi_user_syscall::EINVAL)),
    };
    if flags & O_CREAT != 0 {
        options |= posix::OPEN_CREATE;
    }
    if flags & O_EXCL != 0 {
        options |= posix::OPEN_EXCLUSIVE;
    }
    if flags & O_TRUNC != 0 {
        options |= posix::OPEN_TRUNCATE;
    }
    Ok(options)
}

pub fn open_path(
    path: &str,
    flags: u64,
    mode: u64,
) -> Result<platform::handle::Handle, mochi_user_syscall::SysError> {
    let options = translate_open_flags(flags)?;
    let mode = u32::try_from(mode).map_err(|_| sys_error(mochi_user_syscall::EINVAL))?;
    with_client(|client| client.open_at(OpenAtBase::ProcessRoot, options, mode, path))
        .map(|opened| opened.handle)
}

pub fn close(handle: platform::handle::Handle) -> Result<(), mochi_user_syscall::SysError> {
    platform::handle::close(handle)
}

pub fn sync(handle: platform::handle::Handle) -> Result<(), mochi_user_syscall::SysError> {
    with_client(|client| client.fsync(attachment(handle)))
}

pub fn create_dir(path: &str, mode: u64) -> Result<(), mochi_user_syscall::SysError> {
    let mode = u32::try_from(mode).map_err(|_| sys_error(mochi_user_syscall::EINVAL))?;
    with_client(|client| client.mkdir_at(OpenAtBase::ProcessRoot, mode, path))
}

pub fn remove(path: &str) -> Result<(), mochi_user_syscall::SysError> {
    with_client(|client| client.unlink_at(StatAtBase::ProcessRoot, 0, path))
}

pub fn rename(old_path: &str, new_path: &str) -> Result<(), mochi_user_syscall::SysError> {
    with_client(|client| {
        client.rename_at(
            StatAtBase::ProcessRoot,
            old_path,
            StatAtBase::ProcessRoot,
            new_path,
        )
    })
}

pub fn path_exists(path: &str) -> Result<bool, mochi_user_syscall::SysError> {
    match with_client(|client| client.stat_at(StatAtBase::ProcessRoot, 0, path)) {
        Ok(_) => Ok(true),
        Err(error) if error.errno() == Some(mochi_user_syscall::ENOENT) => Ok(false),
        Err(error) => Err(error),
    }
}

pub fn read_to_end_path(path: &str) -> Result<Vec<u8>, mochi_user_syscall::SysError> {
    let handle = open_path(path, 0, 0)?;
    let mut output = Vec::new();
    let mut buffer = [0u8; 4096];
    loop {
        match platform::handle::read(handle, &mut buffer) {
            Ok(0) => break,
            Ok(length) => output.extend_from_slice(&buffer[..length]),
            Err(error) => {
                let _ = close(handle);
                return Err(error);
            }
        }
    }
    close(handle)?;
    Ok(output)
}

pub fn read_dir_names(path: &str) -> Result<Vec<String>, mochi_user_syscall::SysError> {
    let handle = with_client(|client| {
        client.open_at(
            OpenAtBase::ProcessRoot,
            posix::OPEN_READ | posix::OPEN_DIRECTORY,
            0,
            path,
        )
    })?
    .handle;
    let mut output = Vec::new();
    let mut buffer = [0u8; 4096];
    loop {
        let length = match platform::handle::read(handle, &mut buffer) {
            Ok(length) => length,
            Err(error) => {
                let _ = close(handle);
                return Err(error);
            }
        };
        if length == 0 {
            break;
        }
        for entry in DirectoryEntries::new(&buffer[..length]) {
            let entry = match entry {
                Ok(entry) => entry,
                Err(_) => {
                    let _ = close(handle);
                    return Err(sys_error(mochi_user_syscall::EIO));
                }
            };
            if entry.name != "." && entry.name != ".." {
                output.push(entry.name.to_string());
            }
        }
    }
    close(handle)?;
    Ok(output)
}

pub fn index_mpkg(
    path: &str,
) -> Result<platform::package::MpkgIndex, mochi_user_syscall::SysError> {
    let handle = open_path(path, 0, 0)?;
    let result = platform::package::index_mpkg_reader(
        &mut platform::package::NativeMpkgReader::from_borrowed_handle(handle),
    );
    let close_result = close(handle);
    match result {
        Ok(index) => {
            close_result?;
            Ok(index)
        }
        Err(error) => Err(error),
    }
}

pub fn read_mpkg_range(
    path: &str,
    offset: u64,
    size: u64,
) -> Result<Vec<u8>, mochi_user_syscall::SysError> {
    let handle = open_path(path, 0, 0)?;
    let result = platform::package::read_mpkg_range_reader(
        &mut platform::package::NativeMpkgReader::from_borrowed_handle(handle),
        offset,
        size,
    );
    let close_result = close(handle);
    match result {
        Ok(bytes) => {
            close_result?;
            Ok(bytes)
        }
        Err(error) => Err(error),
    }
}
