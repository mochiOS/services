//! Open-description operations borrow explicit IPC references. Capture POSIX
//! credentials/limits under state, then release it before filesystem RPC.
use super::*;
use std::sync::Mutex;

struct Credentials {
    uid: u32,
    gid: u32,
    groups: Vec<u32>,
}

enum Operation {
    Truncate { length: u64, ceiling: u64 },
    Times(protocol::file_time::Update, Credentials),
    Chmod(u32, Credentials),
    Chown(u32, u32, Credentials),
    Sync,
    Executable(Credentials),
}

pub fn supports(opcode: u16) -> bool {
    matches!(
        opcode,
        protocol::OP_FTRUNCATE
            | protocol::OP_FUTIMENS
            | protocol::OP_FCHMOD
            | protocol::OP_FCHOWN
            | protocol::OP_FSYNC
            | protocol::OP_CHECK_EXECUTABLE
    )
}

fn prepare<H: Copy>(
    service: &PosixService<H>,
    peer: PeerIdentity,
    opcode: u16,
    payload: &[u8],
    handles: &[AttachedObject<H>],
) -> Result<Operation, i32> {
    if !supports(opcode) {
        return Err(protocol::STATUS_ENOSYS);
    }
    let [file] = handles else {
        return Err(STATUS_EINVAL);
    };
    let required = if opcode == protocol::OP_CHECK_EXECUTABLE {
        protocol::CHECK_EXECUTABLE_RIGHTS
    } else {
        protocol::file_mutation_rights(opcode).unwrap_or(mnu_abi::HANDLE_RIGHT_TRANSFER)
    };
    if file.rights & required != required {
        return Err(-13);
    }
    let session = service
        .sessions
        .get(&peer.process_id)
        .ok_or(protocol::STATUS_ESRCH)?;
    let credentials = || Credentials {
        uid: session.effective_uid,
        gid: session.effective_gid,
        groups: service
            .supplementary_groups
            .get(&peer.process_id)
            .cloned()
            .unwrap_or_default(),
    };
    match opcode {
        protocol::OP_FTRUNCATE => {
            let length = protocol::decode_file_length(payload).map_err(|_| STATUS_EINVAL)?;
            let ceiling = service
                .resource_limits
                .get(&(peer.process_id, protocol::RLIMIT_FSIZE))
                .copied()
                .unwrap_or_default()
                .soft;
            Ok(Operation::Truncate { length, ceiling })
        }
        protocol::OP_FUTIMENS => Ok(Operation::Times(
            protocol::file_time::decode(payload).map_err(|_| STATUS_EINVAL)?,
            credentials(),
        )),
        protocol::OP_FCHMOD => {
            let mode = u32::from_le_bytes(payload.try_into().map_err(|_| STATUS_EINVAL)?);
            if mode & !0o7777 != 0 {
                return Err(STATUS_EINVAL);
            }
            Ok(Operation::Chmod(mode, credentials()))
        }
        protocol::OP_FCHOWN => {
            let (uid, gid) = protocol::decode_file_owner(payload).map_err(|_| STATUS_EINVAL)?;
            Ok(Operation::Chown(uid, gid, credentials()))
        }
        protocol::OP_FSYNC => {
            if !payload.is_empty() {
                return Err(STATUS_EINVAL);
            }
            Ok(Operation::Sync)
        }
        protocol::OP_CHECK_EXECUTABLE => {
            if !payload.is_empty() {
                return Err(STATUS_EINVAL);
            }
            Ok(Operation::Executable(credentials()))
        }
        _ => unreachable!(),
    }
}

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
        if envelope.header.flags != 0
            || header.status != 0
            || header.payload_len as usize != payload.len()
        {
            return Err(STATUS_EINVAL);
        }
        let operation = {
            let service = state.lock().map_err(|_| protocol::STATUS_EIO)?;
            prepare(&service, peer, header.opcode, payload, envelope.sources)?
        };
        Ok(run(
            header.request_id,
            operation,
            envelope.sources[0],
            envelope.admission,
            filesystem,
        ))
    })();
    result.unwrap_or_else(|status| object_error(header.request_id, status))
}

pub(crate) fn dispatch<H: Copy, F: FilesystemBackend<H>>(
    service: &PosixService<H>,
    peer: PeerIdentity,
    header: protocol::Header,
    payload: &[u8],
    handles: &[AttachedObject<H>],
    admission: Option<Option<AttachedObject<H>>>,
    filesystem: &mut F,
) -> ObjectResponse<H> {
    match prepare(service, peer, header.opcode, payload, handles) {
        Ok(operation) => run(
            header.request_id,
            operation,
            handles[0],
            admission,
            filesystem,
        ),
        Err(status) => object_error(header.request_id, status),
    }
}

fn run<H: Copy, F: FilesystemBackend<H>>(
    request_id: u64,
    operation: Operation,
    file: AttachedObject<H>,
    admission: Option<Option<AttachedObject<H>>>,
    filesystem: &mut F,
) -> ObjectResponse<H> {
    let result = match operation {
        Operation::Truncate { length, ceiling } => {
            let result = match admission {
                Some(ticket) => filesystem.ftruncate_admitted(file, length, ceiling, ticket),
                None => filesystem
                    .ftruncate(file, length, ceiling)
                    .map_err(MutationError::Failed),
            };
            return match result {
                Ok(()) => object_error(request_id, protocol::STATUS_OK),
                Err(error) => {
                    object_mutation_error(request_id, error, admission.is_some(), filesystem)
                }
            };
        }
        Operation::Times(times, c) => filesystem.futimens(file, times, c.uid, c.gid, &c.groups),
        Operation::Chmod(mode, c) => filesystem.fchmod(file, mode, c.uid, c.gid, &c.groups),
        Operation::Chown(uid, gid, c) => filesystem.fchown(file, uid, gid, c.uid, c.gid, &c.groups),
        Operation::Sync => filesystem.fsync(file),
        Operation::Executable(c) => filesystem.fstat(file).and_then(|status| {
            // Metadata comes from the retained object, never a pathname or an
            // open-time mode snapshot. A directory's search bit is not execute
            // permission for an image. Root also needs an execute bit on files.
            let bits = if c.uid == 0 {
                status.mode & 0o111
            } else if c.uid == status.uid {
                status.mode & 0o100
            } else if c.gid == status.gid || c.groups.contains(&status.gid) {
                status.mode & 0o010
            } else {
                status.mode & 0o001
            };
            if status.mode & 0o170000 == 0o100000 && bits != 0 {
                Ok(())
            } else {
                Err(-13)
            }
        }),
    };
    object_error(request_id, result.err().unwrap_or(protocol::STATUS_OK))
}
