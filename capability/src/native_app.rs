use crate::{app_image, image_catalog::Catalog, resolver::VerifiedManifest};
use alloc::{string::String, vec, vec::Vec};
use mochi_user_platform as platform;
use mochios_posix_client::image_preparation::{
    self, Environment, Preparation, Source, scoped::Scoped,
};
use mochios_posix_client::launch_arguments::ENVIRONMENT_PREFIX;
use mochios_posix_client::{Client, EndpointTransport, ObjectHandleAttachment};

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
    scope: ObjectHandleAttachment<u32>,
    verified: VerifiedManifest,
    capabilities: &[String],
    load_library: impl FnMut(&str) -> Result<VerifiedManifest, Error>,
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
    let requester = Reference(platform::process::open_handle_for_endpoint(
        sender,
        mnu_abi::HANDLE_RIGHT_WAIT | mnu_abi::HANDLE_RIGHT_TRANSFER,
    )?);
    if platform::process::handle_status(requester.0)?.process_id != expected_requester {
        return Err(Error::from_raw(platform::syscall::EACCES as i64));
    }
    let client = Client::new(EndpointTransport::new(endpoint));
    let root = client
        .read_scope_open_executable(scope, true, path)
        .map_err(app_image::remote)
        .map_err(app_image::status)?;
    let root = Reference(root.handle);
    let bytes = app_image::capture(root.0)?;
    let bound_root = !verified.manifest.files.is_empty()
        || verified
            .manifest
            .binary(path)
            .is_some_and(|binary| binary.file.is_some());
    let catalog = if bound_root {
        Catalog::resolve(verified, path, load_library)?
    } else {
        Catalog::for_static(verified, path, &crate::persistent_grant::read_file(path)?)?
    };
    catalog.validate(Source::Root, &bytes)?;
    let dynamic = image_preparation::needs_preparation_bytes(&bytes).map_err(app_image::status)?;
    let source = app_image::readonly(&bytes)?;
    let mechanisms = app_image::Mechanisms(&catalog);
    let reader =
        Scoped::new(&client, scope, &mechanisms, app_image::remote).map_err(app_image::status)?;
    let mut owner = Preparation::default();
    let prepared = if dynamic {
        let environment = |name: &str| {
            items.iter().find_map(|item| {
                item.strip_prefix(ENVIRONMENT_PREFIX)?
                    .strip_prefix(name)?
                    .strip_prefix('=')
                    .map(str::as_bytes)
            })
        };
        Some(
            reader
                .prepare(
                    &mut owner,
                    source.handle(),
                    Environment {
                        library_path: environment("LD_LIBRARY_PATH"),
                        preload: environment("LD_PRELOAD"),
                        audit: environment("LD_AUDIT"),
                    },
                )
                .map_err(app_image::status)?,
        )
    } else {
        None
    };
    let image = prepared
        .as_ref()
        .map(|image| image.image)
        .unwrap_or(source.handle());
    let output = prepared.as_ref().map(|image| image.bytes).unwrap_or(&bytes);
    let metadata = metadata_for_process(
        path,
        items,
        endpoint,
        random,
        mochios_posix_client::process_image::Process {
            image: prepared.as_ref().and_then(|image| image.executable),
            identity: reader.identity(),
            lifecycle: prepared
                .as_ref()
                .map(|image| image.lifecycle)
                .unwrap_or(&[]),
            tls: prepared.as_ref().map(|image| image.tls).unwrap_or(&[]),
            indirect: prepared
                .as_ref()
                .map(|image| image.indirect)
                .unwrap_or(&[]),
        },
    )?;
    crate::resolver::authorize_spawn_image(
        0,
        path,
        catalog.identity(),
        capabilities,
        platform::service::ExecutionClass::Unprivileged,
        output,
    )?;
    let process = Reference(platform::process::create_stopped(image, &metadata)?);
    let result = (|| {
        let id = platform::process::handle_status(process.0)?.process_id;
        crate::persistent_grant::with_client(|client| {
            client.register_launched_child_in_scope(
                scope,
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
