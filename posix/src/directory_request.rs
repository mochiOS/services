//! Directory lookup and context installation are separate phases. The runtime
//! validates native image provenance before committing the prepared change.
use super::*;
use std::sync::Mutex;

#[derive(Clone, Copy)]
enum Target {
    Cwd,
    Root,
}

#[must_use = "finish must install or release the owned directory reference"]
pub struct Pending<H> {
    request_id: u64,
    process_id: u64,
    result: Result<(Target, PreparedStat, OpenedObject<H>), i32>,
}

pub fn supports(opcode: u16) -> bool {
    matches!(opcode, protocol::OP_CHDIR_AT | protocol::OP_CHROOT_AT)
}

fn target(opcode: u16) -> Result<Target, i32> {
    match opcode {
        protocol::OP_CHDIR_AT => Ok(Target::Cwd),
        protocol::OP_CHROOT_AT => Ok(Target::Root),
        _ => Err(protocol::STATUS_ENOSYS),
    }
}

fn prepare<H: Copy>(
    service: &PosixService<H>,
    peer: PeerIdentity,
    target: Target,
    payload: &[u8],
    count: usize,
) -> Result<PreparedStat, i32> {
    let prepared = service.prepare_stat_at(peer, payload, count)?;
    if prepared.flags != 0 {
        return Err(STATUS_EINVAL);
    }
    if matches!(target, Target::Root) && prepared.effective_uid != 0 {
        return Err(protocol::STATUS_EPERM);
    }
    Ok(prepared)
}

pub fn execute<H: Copy, F: FilesystemBackend<H>>(
    state: &Mutex<PosixService<H>>,
    peer: PeerIdentity,
    header: protocol::Header,
    payload: &[u8],
    handles: &[AttachedObject<H>],
    filesystem: &mut F,
) -> Pending<H> {
    let result = (|| {
        if header.flags != 0 || header.status != 0 || header.payload_len as usize != payload.len() {
            return Err(STATUS_EINVAL);
        }
        let target = target(header.opcode)?;
        path_request::with_paths(
            state,
            peer,
            handles,
            filesystem,
            |service| {
                let prepared = prepare(service, peer, target, payload, handles.len())?;
                let base = prepared.base;
                Ok((prepared, base))
            },
            |prepared, paths, filesystem| {
                let policy = prepared.clone();
                filesystem
                    .open_directory_at(prepared, paths)
                    .map(|opened| (target, policy, opened))
            },
        )?
    })();
    Pending {
        request_id: header.request_id,
        process_id: peer.process_id,
        result,
    }
}

/// Must run under the POSIX state lock. No filesystem RPC is allowed here:
/// release_object only discards a local native reference.
pub fn finish<H: Copy, F: FilesystemBackend<H>>(
    service: &mut PosixService<H>,
    peer: PeerIdentity,
    pending: Pending<H>,
    image_validation: Result<(), i32>,
    filesystem: &mut F,
) -> ObjectResponse<H> {
    let image_validation = if pending.process_id != peer.process_id {
        Err(protocol::STATUS_EPERM)
    } else {
        image_validation
    };
    let result = match pending.result {
        Ok((target, policy, opened)) => {
            let validation = image_validation.and_then(|()| {
                let session = service
                    .sessions
                    .get(&peer.process_id)
                    .ok_or(protocol::STATUS_ESRCH)?;
                if !service.directories.contains_key(&peer.process_id) {
                    return Err(protocol::STATUS_ESRCH);
                }
                let groups = service
                    .supplementary_groups
                    .get(&peer.process_id)
                    .map(Vec::as_slice)
                    .unwrap_or(&[]);
                if session.effective_uid != policy.effective_uid
                    || session.effective_gid != policy.effective_gid
                    || groups != policy.supplementary_groups
                {
                    return Err(protocol::STATUS_EAGAIN);
                }
                Ok(())
            });
            let object = AttachedObject {
                handle: opened.handle,
                rights: opened.rights,
            };
            match validation {
                Ok(()) => {
                    match target {
                        Target::Cwd => service.replace_cwd(peer.process_id, object, filesystem),
                        Target::Root => service.replace_root(peer.process_id, object, filesystem),
                    }
                    Ok(())
                }
                Err(status) => {
                    filesystem.release_object(object);
                    Err(status)
                }
            }
        }
        Err(status) => image_validation.and(Err(status)),
    };
    object_error(
        pending.request_id,
        result.err().unwrap_or(protocol::STATUS_OK),
    )
}

pub(crate) fn dispatch<H: Copy, F: FilesystemBackend<H>>(
    service: &mut PosixService<H>,
    peer: PeerIdentity,
    header: protocol::Header,
    payload: &[u8],
    handles: &[AttachedObject<H>],
    filesystem: &mut F,
) -> ObjectResponse<H> {
    let result = (|| {
        let target = target(header.opcode)?;
        let prepared = prepare(service, peer, target, payload, handles.len())?;
        let paths = service.path_objects(peer.process_id, prepared.base, handles)?;
        filesystem
            .open_directory_at(&prepared, paths)
            .map(|opened| (target, prepared, opened))
    })();
    finish(
        service,
        peer,
        Pending {
            request_id: header.request_id,
            process_id: peer.process_id,
            result,
        },
        Ok(()),
        filesystem,
    )
}
