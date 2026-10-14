//! Initial trusted launch before a POSIX endpoint exists. Package and image
//! authorization remain with the caller; mnu receives only objects/metadata.

use mochi_user_platform as platform;
use platform::syscall::{EINVAL, EIO, SysError};

pub(crate) fn spawn(
    path: &str,
    arguments: &[String],
    authorize: impl FnOnce(&[u8]) -> Result<(), SysError>,
) -> Result<u64, SysError> {
    let bytes = crate::bootstrap_file::read_image(path)?;
    let mut random = [0; 16];
    platform::random::fill(&mut random)?;
    let label = path
        .rsplit('/')
        .next()
        .filter(|label| !label.is_empty())
        .ok_or(SysError::from_raw(EINVAL as i64))?;
    let metadata = mochios_posix_client::launch_arguments::encode_native_launch(
        path, label, arguments, random,
    )
    .map_err(|_| SysError::from_raw(EINVAL as i64))?;
    let image = platform::memory_object::MemoryObject::create_resizable(bytes.len() as u64)?;
    let mut written = 0;
    while written < bytes.len() {
        let count = platform::handle::write_at(image.handle(), &bytes[written..], written as u64)?;
        if count == 0 || count > bytes.len() - written {
            return Err(SysError::from_raw(EIO as i64));
        }
        written += count;
    }
    authorize(&bytes)?;
    let (handle, pid) = mochios_posix_client::process_creation::create_with_rollback(
        || platform::process::create_stopped(image.handle(), &metadata),
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
