//! Initial trusted launch before a POSIX endpoint exists. Package and image
//! authorization remain with the caller; mnu receives only objects/metadata.

use mochi_user_platform as platform;
use mochios_posix_client::image_preparation::{Environment, Preparation};
use platform::syscall::{EINVAL, SysError};

fn failed(path: &str, stage: &str, error: impl core::fmt::Debug) {
    let _ = platform::logger::write_status_fmt(format_args!(
        "capability.service: native bootstrap {stage} failed path={path} error={error:?}\n"
    ));
}

pub(crate) fn spawn(
    path: &str,
    arguments: &[String],
    catalog: &crate::image_catalog::Catalog,
    trusted_images: &crate::trusted_images::TrustedImages,
    authorize: impl FnOnce(&[u8]) -> Result<(), SysError>,
) -> Result<u64, SysError> {
    let bytes = crate::bootstrap_file::read_image(path)?;
    let label = path
        .rsplit('/')
        .next()
        .filter(|s| !s.is_empty())
        .ok_or(SysError::from_raw(EINVAL as i64))?;
    let handle = create_stopped(
        path,
        label,
        arguments,
        &bytes,
        catalog,
        trusted_images,
        authorize,
    )?;
    let (handle, pid) = mochios_posix_client::process_creation::create_with_rollback(
        || Ok(handle),
        |_| Ok(()),
        |handle| platform::process::handle_status(handle).map(|status| status.process_id),
        platform::process::resume_handle,
        |handle| {
            let _ = platform::process::terminate_handle(handle, 127);
        },
        reap_failed_launch,
    )?;
    let _ = platform::handle::close(handle);
    Ok(pid)
}

/// Return an attested stopped owner. The system launcher registers its POSIX
/// environment before resume; no caller-asserted loader output is accepted.
pub(crate) fn create_stopped(
    path: &str,
    label: &str,
    arguments: &[String],
    bytes: &[u8],
    catalog: &crate::image_catalog::Catalog,
    trusted_images: &crate::trusted_images::TrustedImages,
    authorize: impl FnOnce(&[u8]) -> Result<(), SysError>,
) -> Result<u32, SysError> {
    let source = crate::app_image::readonly(&bytes)?;
    let mechanisms = crate::app_image::Mechanisms(catalog);
    let mut owner = Preparation::default();
    let prepared = owner
        .prepare(
            &mechanisms,
            source.handle(),
            Environment::default(),
            Default::default(),
        )
        .inspect_err(|error| failed(path, "preparation", error))
        .map_err(crate::app_image::status)?;
    let mut random = [0; 16];
    platform::random::fill(&mut random)?;
    let mut metadata_owner = mochios_posix_client::startup_metadata::Owner::default();
    let metadata = mochios_posix_client::launch_arguments::encode_native_launch_with_metadata(
        path,
        label,
        arguments,
        random,
        mochios_posix_client::process_image::Process {
            image: prepared.executable,
            lifecycle: prepared.lifecycle,
            tls: prepared.tls,
            indirect: prepared.indirect,
            loaded_objects: prepared.loaded_objects,
            ..Default::default()
        },
        &mut metadata_owner,
        &mechanisms,
    )
    .inspect_err(|error| failed(path, "metadata", error))
    .map_err(|error| match error {
        mochios_posix_client::launch_arguments::EncodeError::Metadata(status) => {
            crate::app_image::status(status)
        }
        _ => SysError::from_raw(EINVAL as i64),
    })?;
    authorize(prepared.bytes).inspect_err(|error| failed(path, "authorization", error))?;
    let handle = platform::process::create_stopped(prepared.image, &metadata)
        .inspect_err(|error| failed(path, "creation", error))?;
    if let Err(error) = trusted_images.record_created(
        catalog.identity(),
        catalog.manifest_digest(),
        bytes,
        prepared.bytes,
        handle,
    ) {
        failed(path, "measurement", error);
        let _ = platform::process::terminate_handle(handle, 127);
        reap_failed_launch(handle);
        return Err(error);
    }
    Ok(handle)
}

pub(crate) fn discard_stopped(handle: u32) {
    let _ = platform::process::terminate_handle(handle, 127);
    reap_failed_launch(handle);
}

fn reap_failed_launch(handle: u32) {
    let _ = platform::write_fmt(
        platform::io::STDERR,
        format_args!(
            "capability.service: retaining failed native launch handle={handle} until exit\n",
        ),
    );
    loop {
        if platform::process::handle_status(handle)
            .is_ok_and(|status| status.state == mnu_abi::PROCESS_STATE_EXITED)
        {
            let _ = platform::handle::close(handle);
            return;
        }
        let _ = platform::process::terminate_handle(handle, 127);
        let _ = platform::thread::sleep_milliseconds(1);
    }
}
