//! Authenticate original code and replay linking before measuring its output.
//! The serialized broker reads only bounded native RAM, never caller Providers.
use crate::{app_image, image_catalog::Catalog};
use mochi_user_platform as p;
use mochi_user_syscall::{EACCES, EINVAL, SysError};
use mochios_posix_client::{
    ObjectHandleAttachment,
    image_preparation::{Preparation, replay},
};
use sha2::{Digest, Sha256};
fn denied() -> SysError {
    SysError::from_raw(EACCES as i64)
}

pub(crate) fn length(bytes: &[u8]) -> Result<u64, SysError> {
    p::capability::prepared_exec::decode(bytes)
        .map(|(_, n, _)| n)
        .map_err(|_| SysError::from_raw(EINVAL as i64))
}

pub(crate) fn authorize(
    state: &crate::state::CapabilityServiceState,
    sender: u64,
    request: &[u8],
    attached: &p::ipc::IpcObjectHandles,
) -> Result<(), SysError> {
    let (key, length, expected) = p::capability::prepared_exec::decode(request)
        .map_err(|_| SysError::from_raw(EINVAL as i64))?;
    if !attached.is_user_delivery() || attached.count != 1 {
        return Err(denied());
    }
    let object = attached.handles[0];
    if object.handle == 0
        || object.reserved != 0
        || object.rights != p::handle::HANDLE_RIGHT_READ
        || p::capability::check_thread(sender, "process.spawn")? != 1
    {
        return Err(denied());
    }
    let before = p::execution_peer::capture(sender)?;
    let session_process =
        p::execution_peer::ProcessReference(p::process::open_handle_for_endpoint(
            sender,
            p::handle::HANDLE_RIGHT_WAIT | p::handle::HANDLE_RIGHT_TRANSFER,
        )?);
    if p::process::handle_status(session_process.0)?.process_id != before.image.process_id {
        return Err(denied());
    }
    let credentials = crate::persistent_grant::with_client(|client| {
        client.process_session_info(ObjectHandleAttachment {
            handle: session_process.0,
            rights: p::handle::HANDLE_RIGHT_WAIT,
        })
    })?;
    let record = crate::signed_image::capture(object.handle, length)?;
    let source = replay::original(&record).map_err(app_image::status)?;
    let original_digest = Sha256::digest(source).into();
    let selection = crate::installed_image::select(
        &state.package_index,
        &original_digest,
        source.len() as u64,
        crate::persistent_grant::read_file,
    )?
    .ok_or_else(denied)?;
    let (verified, path, capabilities) =
        selection.for_preparation(&state.app_prompt_policy, &before.context)?;
    // Never turn source authentication into additional authority. The native
    // replacement mechanism repeats attenuation at permit publication/commit.
    for name in &capabilities {
        if p::capability::check_thread(sender, name)? != 1 {
            return Err(denied());
        }
    }
    let catalog = Catalog::resolve(verified, &path, |id| {
        let record = state.package_index.by_package.get(id).ok_or_else(denied)?;
        crate::resolver::verified_manifest(
            &record.manifest_path,
            crate::persistent_grant::read_file,
        )
    })?;
    let mechanisms = app_image::Mechanisms(&catalog);
    let reader = replay::Replay::new(&mechanisms, &record).map_err(app_image::status)?;
    let root = app_image::readonly(reader.root())?;
    let mut preparation = Preparation::default();
    let prepared = preparation
        .prepare(
            &reader,
            root.handle(),
            reader.environment(),
            credentials.into(),
        )
        .map_err(app_image::status)?;
    reader.finish().map_err(app_image::status)?;
    let digest: [u8; 32] = Sha256::digest(prepared.bytes).into();
    if &digest != expected {
        return Err(denied());
    }
    let after = p::execution_peer::capture(sender)?;
    let current = crate::persistent_grant::with_client(|client| {
        client.process_session_info(ObjectHandleAttachment {
            handle: session_process.0,
            rights: p::handle::HANDLE_RIGHT_WAIT,
        })
    })?;
    if before.image != after.image || before.context != after.context || credentials != current {
        return Err(denied());
    }
    crate::resolver::authorize_image_digest(
        sender,
        key,
        catalog.identity(),
        &capabilities,
        p::service::ExecutionClass::Unprivileged,
        &digest,
        mnu_abi::exec::EXEC_AUTHORIZATION_KIND_IMAGE_REPLACE,
    )?;
    if let Some(revision) = before.image.image_revision.checked_add(1) {
        if let Err(error) = crate::image_diagnostics::publish(
            session_process.0, revision, &catalog, source, prepared.bytes, prepared.loaded_objects,
            prepared.executable.map(|image| image.load_bias).unwrap_or(0),
            credentials.real_uid,
        ) {
            p::logln!("capability.service: exec diagnostic metadata unavailable: {:?}", error);
        }
    }
    Ok(())
}
