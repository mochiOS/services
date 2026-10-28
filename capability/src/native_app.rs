use alloc::{string::String, vec, vec::Vec};
use mochi_user_platform as platform;
use mochios_posix_client::launch_arguments::ENVIRONMENT_PREFIX;
use mochios_posix_client::{ObjectHandleAttachment, OpenAtBase};

type Error = platform::syscall::SysError;
fn invalid() -> Error {
    Error::from_raw(platform::syscall::EINVAL as i64)
}

/// Remote argv can provide environment values, but never source Handle numbers
/// or authorization metadata. The sole inherited object is already attached,
/// authenticated and owned in this process's Handle table.
pub(crate) fn metadata(
    path: &str,
    items: &[String],
    endpoint: u32,
    random: [u8; 16],
) -> Result<Vec<u8>, Error> {
    metadata_for_process(
        path,
        items,
        endpoint,
        random,
        mochios_posix_client::process_image::Process::default(),
    )
}

/// The prepared process data is local loader output. Remote launcher items
/// retain their existing argv/environment-only contract and cannot set it.
pub(crate) fn metadata_for_process(
    path: &str,
    items: &[String],
    endpoint: u32,
    random: [u8; 16],
    process: mochios_posix_client::process_image::Process<'_>,
) -> Result<Vec<u8>, Error> {
    use mnu_abi::process_create::{self, HandleGrant};
    let mut arguments = vec![path.as_bytes()];
    let mut environment = Vec::new();
    for item in items {
        if item.as_bytes().contains(&0) {
            return Err(invalid());
        }
        if let Some(entry) = item.strip_prefix(ENVIRONMENT_PREFIX) {
            let (name, _) = entry.split_once('=').ok_or_else(invalid)?;
            if name.is_empty() {
                return Err(invalid());
            }
            environment.push(entry.as_bytes());
        } else if item.starts_with("__MNU_EXEC_") {
            return Err(invalid());
        } else {
            arguments.push(item.as_bytes());
        }
    }
    let mut startup = vec![0; process_create::MAX_REQUEST_BYTES];
    let length = mochios_posix_client::process_image::encode_initial_stack_for_process(
        &arguments,
        &environment,
        path.as_bytes(),
        random,
        &[],
        process,
        &mut startup,
    )
    .map_err(|_| invalid())?;
    let mut result = vec![0; process_create::MAX_REQUEST_BYTES];
    // Native labels are bounded display hints, never executable identity. Keep
    // the full path as identity; an application's bundle name labels its task.
    let label = path
        .rsplit('/')
        .find(|part| part.ends_with(".app"))
        .or_else(|| path.rsplit('/').find(|part| !part.is_empty()))
        .ok_or_else(invalid)?;
    let mut label_length = label.len().min(process_create::MAX_LABEL_BYTES);
    while !label.is_char_boundary(label_length) {
        label_length -= 1;
    }
    let length = process_create::encode(
        path,
        &label[..label_length],
        &startup[..length],
        &[HandleGrant {
            key: mochios_posix_protocol::CONTROL_HANDLE_KEY,
            source: endpoint,
            target: 0,
            rights: mnu_abi::HANDLE_RIGHT_SEND
                | mnu_abi::HANDLE_RIGHT_DUPLICATE
                | mnu_abi::HANDLE_RIGHT_TRANSFER,
        }],
        &[],
        &mut result,
    )
    .map_err(|_| invalid())?;
    result.truncate(length);
    Ok(result)
}

struct Reference(u32);
impl Drop for Reference {
    fn drop(&mut self) {
        let _ = platform::handle::close(self.0);
    }
}

pub(crate) fn launch(
    path: &str,
    items: &[String],
    endpoint: u32,
    sender: u64,
    expected_requester: u64,
) -> Result<u64, Error> {
    let mut random = [0; 16];
    if platform::syscall::call2(
        platform::syscall::SyscallNumber::RandomFill,
        random.as_mut_ptr() as u64,
        random.len() as u64,
    )? != random.len() as u64
    {
        return Err(Error::from_raw(platform::syscall::EIO as i64));
    }
    let metadata = metadata(path, items, endpoint, random)?;
    let image = Reference(
        crate::persistent_grant::with_client(|client| {
            client.open_at(
                OpenAtBase::ProcessRoot,
                mochios_posix_protocol::OPEN_READ,
                0,
                path,
            )
        })?
        .handle,
    );
    let requester = Reference(platform::process::open_handle_for_endpoint(
        sender,
        mnu_abi::HANDLE_RIGHT_WAIT | mnu_abi::HANDLE_RIGHT_TRANSFER,
    )?);
    if platform::process::handle_status(requester.0)?.process_id != expected_requester {
        return Err(Error::from_raw(platform::syscall::EACCES as i64));
    }
    let process = Reference(platform::process::create_stopped(image.0, &metadata)?);
    let result = (|| {
        let id = platform::process::handle_status(process.0)?.process_id;
        crate::persistent_grant::with_client(|client| {
            client.register_launched_child(
                ObjectHandleAttachment {
                    handle: requester.0,
                    rights: mnu_abi::HANDLE_RIGHT_WAIT,
                },
                ObjectHandleAttachment {
                    handle: process.0,
                    rights: mnu_abi::HANDLE_RIGHT_WAIT | mnu_abi::HANDLE_RIGHT_SIGNAL,
                },
            )
        })?;
        platform::process::resume_handle(process.0)?;
        Ok(id)
    })();
    if result.is_err() {
        let _ = platform::process::terminate_handle(process.0, 127);
        // Registration may have succeeded even when its reply was lost. Ask
        // the service to reclaim our own launch; never use an arbitrary PID.
        if let Err(error) = crate::persistent_grant::with_client(|client| {
            client.abort_launched_child(ObjectHandleAttachment {
                handle: process.0,
                rights: mnu_abi::HANDLE_RIGHT_WAIT,
            })
        }) {
            if error.raw() != mochios_posix_protocol::STATUS_EPERM as i64 {
                platform::logln!("capability.service: failed launch cleanup: {error:?}");
            }
        }
    }
    result
}
