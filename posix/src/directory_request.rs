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
    matches!(
        opcode,
        protocol::OP_CHDIR_AT | protocol::OP_CHROOT_AT | protocol::OP_FCHDIR
    )
}

fn target(opcode: u16) -> Result<Target, i32> {
    match opcode {
        protocol::OP_CHDIR_AT | protocol::OP_FCHDIR => Ok(Target::Cwd),
        protocol::OP_CHROOT_AT => Ok(Target::Root),
        _ => Err(protocol::STATUS_ENOSYS),
    }
}

fn prepare<H: Copy>(
    service: &PosixService<H>,
    peer: PeerIdentity,
    target: Target,
    opcode: u16,
    payload: &[u8],
    count: usize,
) -> Result<PreparedStat, i32> {
    if opcode == protocol::OP_FCHDIR {
        if !payload.is_empty() || count != 1 {
            return Err(STATUS_EINVAL);
        }
        let session = service
            .sessions
            .get(&peer.process_id)
            .ok_or(protocol::STATUS_ESRCH)?;
        // This is a policy snapshot only: no path is resolved for fchdir.
        return Ok(PreparedStat {
            base: protocol::OpenBase::ProcessRoot,
            flags: 0,
            path: Vec::new(),
            effective_uid: session.effective_uid,
            effective_gid: session.effective_gid,
            supplementary_groups: service
                .supplementary_groups
                .get(&peer.process_id)
                .cloned()
                .unwrap_or_default(),
        });
    }
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
        validate_source(header.opcode, handles)?;
        path_request::with_paths(
            state,
            peer,
            handles,
            filesystem,
            |service| {
                let prepared =
                    prepare(service, peer, target, header.opcode, payload, handles.len())?;
                let base = prepared.base;
                Ok((prepared, base))
            },
            |prepared, paths, filesystem| {
                let policy = prepared.clone();
                lookup(header.opcode, prepared, paths, handles, filesystem)
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
        validate_source(header.opcode, handles)?;
        let prepared = prepare(service, peer, target, header.opcode, payload, handles.len())?;
        let paths = service.path_objects(peer.process_id, prepared.base, handles)?;
        lookup(header.opcode, &prepared, paths, handles, filesystem)
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

fn validate_source<H>(opcode: u16, handles: &[AttachedObject<H>]) -> Result<(), i32> {
    if opcode == protocol::OP_FCHDIR {
        let [source] = handles else {
            return Err(STATUS_EINVAL);
        };
        let required = mnu_abi::HANDLE_RIGHT_DUPLICATE | mnu_abi::HANDLE_RIGHT_TRANSFER;
        if source.rights & required != required {
            return Err(-13);
        }
    }
    Ok(())
}

fn lookup<H: Copy, F: FilesystemBackend<H>>(
    opcode: u16,
    policy: &PreparedStat,
    paths: PathObjects<H>,
    handles: &[AttachedObject<H>],
    filesystem: &mut F,
) -> Result<OpenedObject<H>, i32> {
    if opcode != protocol::OP_FCHDIR {
        return filesystem.open_directory_at(policy, paths);
    }
    let source = handles[0]; // validated before any backend operation
    let status = filesystem.fstat(source)?;
    if status.mode & 0o170000 != 0o040000 {
        return Err(-20);
    }
    // Directory search uses the matching owner/group class, never a union.
    // UID zero bypasses POSIX DAC only, not the native source rights above.
    let shift = if policy.effective_uid == status.uid {
        6
    } else if policy.effective_gid == status.gid
        || policy.supplementary_groups.contains(&status.gid)
    {
        3
    } else {
        0
    };
    if policy.effective_uid != 0 && (status.mode >> shift) & 1 == 0 {
        return Err(-13);
    }
    // The incoming IPC reference pins identity throughout metadata lookup and
    // local retain, even across rename/unlink. No pathname/second inode lookup.
    let retained = filesystem.retain_object(source)?;
    if retained.rights != source.rights {
        filesystem.release_object(retained);
        return Err(protocol::STATUS_EIO);
    }
    Ok(OpenedObject {
        handle: retained.handle,
        rights: retained.rights,
    })
}
