//! Two-path mutations use one retained root/cwd snapshot and one FS operation.
use super::*;
use std::sync::Mutex;

#[derive(PartialEq, Eq)]
enum Pair {
    Rename(PreparedRename),
    Link(PreparedLink),
}

pub fn supports(opcode: u16) -> bool {
    matches!(opcode, protocol::OP_RENAME_AT | protocol::OP_LINK_AT)
}

fn prepare<H: Copy>(
    service: &PosixService<H>,
    peer: PeerIdentity,
    opcode: u16,
    payload: &[u8],
    count: usize,
) -> Result<(Pair, [protocol::OpenBase; 2]), i32> {
    match opcode {
        protocol::OP_RENAME_AT => {
            let p = service.prepare_rename_at(peer, payload, count)?;
            let bases = [p.old_base, p.new_base];
            Ok((Pair::Rename(p), bases))
        }
        protocol::OP_LINK_AT => {
            let p = service.prepare_link_at(peer, payload, count)?;
            let bases = [p.old_base, p.new_base];
            Ok((Pair::Link(p), bases))
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
    path_request::with_two_paths(
        state,
        peer,
        handles,
        filesystem,
        |service| prepare(service, peer, header.opcode, payload, handles.len()),
        |pair, paths, filesystem| run(header.request_id, pair, paths, filesystem),
    )
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
    let result = prepare(service, peer, header.opcode, payload, handles.len()).and_then(
        |(pair, [old_base, new_base])| {
            let paths =
                service.rename_path_objects(peer.process_id, old_base, new_base, handles)?;
            Ok(run(header.request_id, &pair, paths, filesystem))
        },
    );
    result.unwrap_or_else(|status| object_error(header.request_id, status))
}

fn run<H: Copy, F: FilesystemBackend<H>>(
    request_id: u64,
    pair: &Pair,
    paths: RenamePathObjects<H>,
    filesystem: &mut F,
) -> ObjectResponse<H> {
    let result = match pair {
        Pair::Rename(p) => filesystem.rename_at(p, paths),
        Pair::Link(p) => filesystem.link_at(p, paths),
    };
    match result {
        Ok(()) => object_error(request_id, protocol::STATUS_OK),
        Err(status) => object_error(request_id, status),
    }
}
