//! Retain pathname anchors under the state lock, then perform backend RPC
//! without it. A device provider may itself need POSIX state for job control.
use super::*;
use std::sync::Mutex;

/// Incoming directory and admission-ticket references remain borrowed from the
/// IPC receive. Only service-owned root/cwd anchors are duplicated here.
pub fn execute<H: Copy, F: FilesystemBackend<H>>(
    state: &Mutex<PosixService<H>>,
    peer: PeerIdentity,
    header: protocol::Header,
    payload: &[u8],
    handles: &[AttachedObject<H>],
    filesystem: &mut F,
) -> ObjectResponse<H> {
    let result = (|| {
        let envelope = mutation_admission::Request::decode(header, handles)?;
        if envelope.header.opcode != protocol::OP_OPEN_AT
            || envelope.header.flags != 0
            || envelope.header.status != 0
            || header.payload_len as usize != payload.len()
        {
            return Err(STATUS_EINVAL);
        }
        path_request::with_paths(
            state,
            peer,
            envelope.sources,
            filesystem,
            |service| {
                let prepared = service.prepare_open_at(peer, payload, envelope.sources.len())?;
                let base = prepared.base;
                Ok((prepared, base))
            },
            |prepared, paths, filesystem| {
                dispatch(
                    header.request_id,
                    prepared,
                    paths,
                    envelope.admission,
                    filesystem,
                )
            },
        )
    })();
    result.unwrap_or_else(|status| object_error(header.request_id, status))
}

pub(crate) fn dispatch<H: Copy, F: FilesystemBackend<H>>(
    request_id: u64,
    prepared: &PreparedOpen,
    paths: PathObjects<H>,
    admission: Option<Option<AttachedObject<H>>>,
    filesystem: &mut F,
) -> ObjectResponse<H> {
    let result = match admission {
        Some(ticket) => filesystem.open_at_admitted(prepared, paths, ticket),
        None => filesystem
            .open_at(prepared, paths)
            .map_err(MutationError::Failed),
    };
    match result {
        Ok(opened) => ObjectResponse {
            response: status_response(request_id, protocol::STATUS_OK),
            handles: vec![opened],
        },
        Err(error) => object_mutation_error(request_id, error, admission.is_some(), filesystem),
    }
}

/// Validate native execution-image provenance before handing any newly opened
/// object (including a mutation ticket) to the caller. Validation itself stays
/// with the runtime's authenticated native identity observation. Rejecting a
/// response cannot roll back a namespace mutation already committed by FS.
pub fn finish<H: Copy, F: FilesystemBackend<H>>(
    mut response: ObjectResponse<H>,
    image_validation: Result<(), i32>,
    filesystem: &mut F,
) -> ObjectResponse<H> {
    if let Err(status) = image_validation {
        for object in response.handles.drain(..) {
            filesystem.release_object(AttachedObject {
                handle: object.handle,
                rights: object.rights,
            });
        }
        response.response = status_response(response.response.header.request_id, status);
    }
    response
}
