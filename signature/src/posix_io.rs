use mochi_user_platform as platform;
use mochios_posix_client::{Client, ClientError, EndpointTransport, OpenAtBase};
use mochios_posix_protocol::{OPEN_READ, STATUS_ERANGE};
use platform::package::{MpkgReader, NativeMpkgReader};
use platform::syscall::{EAGAIN, EIO, ENOMEM, SysError};
use std::sync::Mutex;

static CLIENT: Mutex<Option<Client<EndpointTransport>>> = Mutex::new(None);

pub(crate) fn install_launch_endpoint() -> Result<(), SysError> {
    let client = Client::<EndpointTransport>::from_launch_context().map_err(client_error)?;
    let mut installed = CLIENT.lock().map_err(|_| SysError::from_raw(EIO as i64))?;
    *installed = Some(client);
    Ok(())
}

fn client_error(error: ClientError<SysError>) -> SysError {
    match error {
        ClientError::Transport(error) => error,
        ClientError::Remote(status) => SysError::from_raw(status as i64),
        _ => SysError::from_raw(EIO as i64),
    }
}

/// Consumes the endpoint, including when registration fails.
pub(crate) fn install_endpoint(endpoint: platform::handle::Handle) -> Result<(), SysError> {
    let client = Client::new(EndpointTransport::new(endpoint));
    let result = (|| {
        client.register_session().map_err(client_error)?;
        let mut installed = CLIENT.lock().map_err(|_| SysError::from_raw(EIO as i64))?;
        if let Some(previous) = installed.replace(client) {
            let _ = platform::handle::close(previous.into_transport().endpoint());
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = platform::handle::close(endpoint);
    }
    result
}

fn file_length(handle: platform::handle::Handle) -> Result<u64, SysError> {
    let installed = CLIENT.lock().map_err(|_| SysError::from_raw(EIO as i64))?;
    let client = installed
        .as_ref()
        .ok_or_else(|| SysError::from_raw(EAGAIN as i64))?;
    let status = client
        .fstat(mochios_posix_client::ObjectHandleAttachment {
            handle,
            rights: platform::handle::HANDLE_RIGHT_TRANSFER,
        })
        .map_err(client_error)?;
    u64::try_from(status.size).map_err(|_| SysError::from_raw(EIO as i64))
}

pub(crate) fn with_reader<T>(
    path: &str,
    operation: impl FnOnce(&mut NativeMpkgReader) -> Result<T, SysError>,
) -> Result<T, SysError> {
    let file = {
        let installed = CLIENT.lock().map_err(|_| SysError::from_raw(EIO as i64))?;
        let client = installed
            .as_ref()
            .ok_or_else(|| SysError::from_raw(EAGAIN as i64))?;
        client
            .open_at(OpenAtBase::ProcessRoot, OPEN_READ, 0, path)
            .map_err(client_error)?
    };
    let result = operation(&mut NativeMpkgReader::from_borrowed_handle(
        file.handle,
        file_length,
    ));
    let closed = platform::handle::close(file.handle);
    let value = result?;
    closed?;
    Ok(value)
}

pub(crate) fn read_file(path: &str, limit: usize) -> Result<Vec<u8>, SysError> {
    with_reader(path, |reader| {
        let size = usize::try_from(reader.len()?)
            .map_err(|_| SysError::from_raw(i64::from(STATUS_ERANGE)))?;
        if size > limit {
            return Err(SysError::from_raw(i64::from(STATUS_ERANGE)));
        }
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(size)
            .map_err(|_| SysError::from_raw(ENOMEM as i64))?;
        bytes.resize(size, 0);
        reader.read_exact_at(0, &mut bytes)?;
        Ok(bytes)
    })
}

/// Read-only database access through the installed endpoint, never old syscalls.
pub(crate) struct DatabaseBackend;

impl mochios_certificate_database::storage::StorageBackend for DatabaseBackend {
    fn read(
        &mut self,
        path: &str,
    ) -> Result<Option<Vec<u8>>, mochios_certificate_database::storage::StorageError> {
        use mochios_certificate_database::storage::{
            REVOCATIONS_A_PATH, REVOCATIONS_B_PATH, STATE_PATH, StorageError, TRUST_A_PATH,
            TRUST_B_PATH,
        };
        let limit = match path {
            STATE_PATH => mochios_certificate_database::STATE_LEN,
            TRUST_A_PATH | TRUST_B_PATH | REVOCATIONS_A_PATH | REVOCATIONS_B_PATH => {
                4 * 1024 * 1024
            }
            _ => return Err(StorageError::Backend),
        };
        match read_file(path, limit) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(error) if error.raw() == platform::syscall::ENOENT as i64 => Ok(None),
            Err(error) if error.raw() == i64::from(STATUS_ERANGE) => {
                Err(StorageError::InvalidSnapshot)
            }
            Err(_) => Err(StorageError::Backend),
        }
    }

    fn write_sync(
        &mut self,
        _path: &str,
        _bytes: &[u8],
    ) -> Result<(), mochios_certificate_database::storage::StorageError> {
        Err(mochios_certificate_database::storage::StorageError::Backend)
    }
}
