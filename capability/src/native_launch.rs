//! Policy for stopped creation by measured system launchers. The broker owns
//! preparation and attestation; the requester retains POSIX setup and resume.
use mochi_user_platform as p;
use mochios_posix_client::launch_arguments::{
    ENVIRONMENT_PREFIX, INHERITED_HANDLE_PREFIX, INHERITED_VALUE_PREFIX,
};
use p::capability::native_launch as wire;
use p::syscall::{EACCES, EINVAL, SysError};

pub(crate) fn create(
    state: &crate::state::CapabilityServiceState,
    sender: u64,
    bytes: &[u8],
    handles: &p::ipc::IpcObjectHandles,
    read: crate::resolver::FileReader,
) -> Result<u32, SysError> {
    let invalid = || SysError::from_raw(EINVAL as i64);
    let request = wire::decode(bytes).map_err(|_| invalid())?;
    if !handles.is_user_delivery() || handles.count as usize != request.bindings().count() {
        return Err(invalid());
    }
    let path = request.text.path;
    let plan = crate::broker_launch::select(
        &state.package_index,
        &state.trusted_images,
        sender,
        request.class,
        path,
        read,
    )?;
    let mut argv = request.text.arguments.iter();
    let label = argv.next().filter(|s| !s.is_empty()).ok_or_else(invalid)?;
    let mut arguments = alloc::vec::Vec::new();
    for arg in argv {
        // Ordinary argv cannot inject a local launch convention or Handle ID.
        if arg.starts_with("__MNU_EXEC_") {
            return Err(invalid());
        }
        arguments.push(alloc::string::String::from(arg));
    }
    for env in request.text.environment.iter() {
        arguments.push(alloc::format!("{ENVIRONMENT_PREFIX}{env}"));
    }
    for (binding, handle) in request.bindings().zip(&handles.handles) {
        if binding.rights & !p::handle::HANDLE_RIGHT_ALL != 0
            || handle.handle == 0
            || handle.reserved != 0
            || handle.rights != binding.rights | p::handle::HANDLE_RIGHT_TRANSFER
        {
            return Err(invalid());
        }
        if binding.key == mochios_posix_protocol::CONTROL_HANDLE_KEY {
            crate::persistent_grant::validate_posix_endpoint(handle.handle)?;
        }
        arguments.push(alloc::format!(
            "{INHERITED_HANDLE_PREFIX}{}:{}:{}",
            binding.key,
            handle.handle,
            binding.rights
        ));
    }
    for value in request.values() {
        arguments.push(alloc::format!(
            "{INHERITED_VALUE_PREFIX}{}:{}",
            value.key,
            value.value
        ));
    }
    let image = plan.verified.read_image(path, read)?;
    let catalog = crate::image_catalog::Catalog::bootstrap_service(plan.verified.clone(), path)?;
    let process = crate::native_bootstrap::create_stopped(
        path,
        label,
        &arguments,
        &image,
        &catalog,
        &state.trusted_images,
        |output| {
            plan.recheck(&state.trusted_images, sender)?;
            crate::resolver::authorize_spawn_image(
                0,
                path,
                &plan.verified.identity,
                &plan.caps,
                plan.class,
                output,
            )
        },
    )?;
    if plan.recheck(&state.trusted_images, sender).is_err() {
        crate::native_bootstrap::discard_stopped(process);
        return Err(SysError::from_raw(EACCES as i64));
    }
    Ok(process)
}
