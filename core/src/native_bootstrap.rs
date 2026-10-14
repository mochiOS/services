use mochi_user_platform as platform;
use mochi_user_syscall::{EINVAL, EIO, SysError};

fn stage<T>(path: &str, operation: &str, result: Result<T, SysError>) -> Result<T, SysError> {
    result.inspect_err(|error| {
        let _ = platform::write_fmt(
            platform::io::STDERR,
            format_args!(
                "core.service: native launch {operation} failed path={path} errno={}\n",
                error.errno().unwrap_or(5),
            ),
        );
    })
}

/// The caller has verified the built-in installation record and capability
/// list. Hash exactly the immutable bytes copied into the owned image object.
pub(super) fn spawn(
    path: &str,
    identity: &[String],
    capabilities: &[String],
    arguments: &[String],
) -> Result<u64, SysError> {
    let bytes = stage(path, "read image", crate::boot_files::read_image(path))?;
    let mut random = [0; 16];
    platform::random::fill(&mut random)?;
    let plan = crate::bootstrap_plan::prepare(path, identity, arguments, &bytes, random)
        .map_err(|_| SysError::from_raw(EINVAL as i64))?;
    let image = stage(
        path,
        "allocate image",
        platform::memory_object::MemoryObject::create_resizable(bytes.len() as u64),
    )?;
    let mut written = 0;
    while written < bytes.len() {
        let count = platform::handle::write_at(image.handle(), &bytes[written..], written as u64)?;
        if count == 0 || count > bytes.len() - written {
            return Err(SysError::from_raw(EIO as i64));
        }
        written += count;
    }
    stage(
        path,
        "authorize image",
        platform::service::authorize_exec_for_requester(
            0,
            path,
            &plan.authorization,
            &crate::encode_nul_list(capabilities),
        ),
    )?;
    let (handle, pid) = mochios_posix_client::process_creation::create_with_rollback(
        || {
            stage(
                path,
                "create process",
                platform::process::create_stopped(image.handle(), &plan.creation),
            )
        },
        |_| Ok(()),
        |handle| {
            stage(
                path,
                "identify process",
                platform::process::handle_status(handle),
            )
            .map(|status| status.process_id)
        },
        |handle| {
            stage(
                path,
                "resume process",
                platform::process::resume_handle(handle),
            )
        },
        |handle| {
            let _ = platform::process::terminate_handle(handle, 127);
        },
        reap_failed_launch,
    )?;
    let _ = platform::handle::close(handle);
    Ok(pid)
}

/// Startup must not discard an unconfirmed child after a failed resume/query.
/// Retain its exact creation reference until exit, even if termination retries.
fn reap_failed_launch(handle: u32) {
    let _ = platform::write_fmt(
        platform::io::STDERR,
        format_args!("core.service: retaining failed native launch handle={handle} until exit\n",),
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
