//! Read-only pathname requests use retained anchors, not a global state lock
//! spanning filesystem IPC. Policy decoding remains in PosixService.
use super::*;
use std::sync::Mutex;

#[derive(PartialEq, Eq)]
enum Query {
    Cwd,
    Stat(PreparedStat),
    Canonical(PreparedStat),
    Access(PreparedAccess),
    Readlink(PreparedReadlink),
}

pub fn supports(opcode: u16) -> bool {
    matches!(
        opcode,
        protocol::OP_STAT_AT
            | protocol::OP_GETCWD
            | protocol::OP_CANONICAL_PATH_AT
            | protocol::OP_ACCESS_AT
            | protocol::OP_READLINK_AT
    )
}

fn prepare<H: Copy>(
    service: &PosixService<H>,
    peer: PeerIdentity,
    opcode: u16,
    payload: &[u8],
    count: usize,
) -> Result<(Query, protocol::OpenBase), i32> {
    match opcode {
        protocol::OP_GETCWD => {
            if !payload.is_empty() || count != 0 {
                return Err(STATUS_EINVAL);
            }
            if !service.sessions.contains_key(&peer.process_id) {
                return Err(protocol::STATUS_ESRCH);
            }
            Ok((Query::Cwd, protocol::OpenBase::ProcessCwd))
        }
        protocol::OP_STAT_AT | protocol::OP_CANONICAL_PATH_AT => {
            let prepared = service.prepare_stat_at(peer, payload, count)?;
            let base = prepared.base;
            let query = if opcode == protocol::OP_CANONICAL_PATH_AT {
                if prepared.flags != 0 {
                    return Err(STATUS_EINVAL);
                }
                Query::Canonical(prepared)
            } else {
                Query::Stat(prepared)
            };
            Ok((query, base))
        }
        protocol::OP_ACCESS_AT => {
            let prepared = service.prepare_access_at(peer, payload, count)?;
            let base = prepared.base;
            Ok((Query::Access(prepared), base))
        }
        protocol::OP_READLINK_AT => {
            let prepared = service.prepare_readlink_at(peer, payload, count)?;
            let base = prepared.base;
            Ok((Query::Readlink(prepared), base))
        }
        _ => Err(protocol::STATUS_ENOSYS),
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
    if header.flags != 0 || header.status != 0 || header.payload_len as usize != payload.len() {
        return object_error(header.request_id, STATUS_EINVAL);
    }
    let result = path_request::with_paths(
        state,
        peer,
        handles,
        filesystem,
        |service| prepare(service, peer, header.opcode, payload, handles.len()),
        |query, paths, filesystem| run(header.request_id, query, paths, filesystem),
    );
    result
        .and_then(|response| response)
        .unwrap_or_else(|status| object_error(header.request_id, status))
}

pub(crate) fn dispatch<H: Copy, F: FilesystemBackend<H>>(
    service: &PosixService<H>,
    peer: PeerIdentity,
    header: protocol::Header,
    payload: &[u8],
    handles: &[AttachedObject<H>],
    filesystem: &mut F,
) -> ObjectResponse<H> {
    let result =
        prepare(service, peer, header.opcode, payload, handles.len()).and_then(|(query, base)| {
            let paths = service.path_objects(peer.process_id, base, handles)?;
            run(header.request_id, &query, paths, filesystem)
        });
    result.unwrap_or_else(|status| object_error(header.request_id, status))
}

fn run<H: Copy, F: FilesystemBackend<H>>(
    request_id: u64,
    query: &Query,
    paths: PathObjects<H>,
    filesystem: &mut F,
) -> Result<ObjectResponse<H>, i32> {
    match query {
        Query::Cwd => filesystem
            .directory_path(paths.root, paths.base.ok_or(protocol::STATUS_EIO)?)
            .map(|path| object_payload(request_id, path)),
        Query::Stat(prepared) => filesystem
            .stat_at(prepared, paths)
            .map(|status| object_status(request_id, status)),
        Query::Canonical(prepared) => filesystem
            .canonical_path_at(prepared, paths)
            .map(|path| object_payload(request_id, path)),
        Query::Access(prepared) => filesystem
            .access_at(prepared, paths)
            .map(|()| object_error(request_id, protocol::STATUS_OK)),
        Query::Readlink(prepared) => filesystem
            .readlink_at(prepared, paths)
            .map(|target| object_payload(request_id, target)),
    }
}
