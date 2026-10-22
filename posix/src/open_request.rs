//! Retain pathname anchors under the state lock, then perform backend RPC
//! without it. A device provider may itself need POSIX state for job control.
use super::*;
use std::sync::Mutex;

struct References<'a, H: Copy, F: FilesystemBackend<H>> {
    filesystem: &'a mut F,
    owned: Vec<AttachedObject<H>>,
}

impl<H: Copy, F: FilesystemBackend<H>> References<'_, H, F> {
    fn retain(&mut self, source: AttachedObject<H>) -> Result<AttachedObject<H>, i32> {
        // retain_object must be a local native reference operation, not RPC.
        let retained = self.filesystem.retain_object(source)?;
        self.owned.push(retained);
        // Do not silently weaken the root/cwd used by pathname resolution.
        if retained.rights != source.rights {
            return Err(protocol::STATUS_EIO);
        }
        Ok(retained)
    }
}

impl<H: Copy, F: FilesystemBackend<H>> Drop for References<'_, H, F> {
    fn drop(&mut self) {
        for object in self.owned.drain(..) {
            self.filesystem.release_object(object);
        }
    }
}

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
        let mut references = References {
            filesystem,
            owned: Vec::new(),
        };
        // At most two not-yet-installed roots and two retained anchors.
        references.owned.try_reserve_exact(4).map_err(|_| -12)?;
        let initial = {
            let service = state.lock().map_err(|_| protocol::STATUS_EIO)?;
            let prepared = service.prepare_open_at(peer, payload, envelope.sources.len())?;
            (!service.directories.contains_key(&peer.process_id)).then_some(prepared)
        };
        if let Some(initial) = initial {
            let roots = references.filesystem.open_session_root(
                initial.effective_uid,
                initial.effective_gid,
                &initial.supplementary_groups,
            )?;
            references.owned.extend([roots.root, roots.cwd]);
            let mut service = state.lock().map_err(|_| protocol::STATUS_EIO)?;
            let current = service.prepare_open_at(peer, payload, envelope.sources.len())?;
            // Never install roots authorized with stale credentials/umask.
            // No path mutation has occurred, so retrying this error is safe.
            if current != initial {
                return Err(protocol::STATUS_EAGAIN);
            }
            if let std::collections::btree_map::Entry::Vacant(entry) =
                service.directories.entry(peer.process_id)
            {
                entry.insert(roots);
                references.owned.clear(); // ownership moved into the session
            }
        }
        let (prepared, paths) = {
            let service = state.lock().map_err(|_| protocol::STATUS_EIO)?;
            let prepared = service.prepare_open_at(peer, payload, envelope.sources.len())?;
            let mut paths =
                service.path_objects(peer.process_id, prepared.base, envelope.sources)?;
            paths.root = references.retain(paths.root)?;
            if prepared.base == protocol::OpenBase::ProcessCwd {
                paths.base = Some(references.retain(paths.base.ok_or(protocol::STATUS_EIO)?)?);
            }
            (prepared, paths)
        };
        Ok(dispatch(
            header.request_id,
            &prepared,
            paths,
            envelope.admission,
            references.filesystem,
        ))
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
