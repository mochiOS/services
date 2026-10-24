//! Single-path mutations retain root/cwd locally and perform one filesystem
//! transaction outside POSIX state. Namespace atomicity remains with FS.
use super::*;
use std::sync::Mutex;

#[derive(PartialEq, Eq)]
enum Mutation {
    Mkdir(PreparedNodeCreation),
    Fifo(PreparedNodeCreation),
    Unlink(PreparedUnlink),
    Truncate(PreparedTruncate),
    Symlink(PreparedSymlink),
    Times(PreparedFileTimes),
    Chmod(PreparedChmod),
    Chown(PreparedChown),
}

pub fn supports(opcode: u16) -> bool {
    matches!(
        opcode,
        protocol::OP_MKDIR_AT
            | protocol::OP_MKFIFO_AT
            | protocol::OP_UNLINK_AT
            | protocol::OP_TRUNCATE_AT
            | protocol::OP_SYMLINK_AT
            | protocol::OP_UTIMENS_AT
            | protocol::OP_CHMOD_AT
            | protocol::OP_CHOWN_AT
    )
}

fn prepare<H: Copy>(
    service: &PosixService<H>,
    peer: PeerIdentity,
    opcode: u16,
    payload: &[u8],
    count: usize,
) -> Result<(Mutation, protocol::OpenBase), i32> {
    let mutation = match opcode {
        protocol::OP_MKDIR_AT => {
            Mutation::Mkdir(service.prepare_node_creation(peer, payload, count)?)
        }
        protocol::OP_MKFIFO_AT => {
            Mutation::Fifo(service.prepare_node_creation(peer, payload, count)?)
        }
        protocol::OP_UNLINK_AT => {
            Mutation::Unlink(service.prepare_unlink_at(peer, payload, count)?)
        }
        protocol::OP_TRUNCATE_AT => {
            Mutation::Truncate(service.prepare_truncate_at(peer, payload, count)?)
        }
        protocol::OP_SYMLINK_AT => {
            Mutation::Symlink(service.prepare_symlink_at(peer, payload, count)?)
        }
        protocol::OP_UTIMENS_AT => {
            Mutation::Times(service.prepare_utimens_at(peer, payload, count)?)
        }
        protocol::OP_CHMOD_AT => Mutation::Chmod(service.prepare_chmod_at(peer, payload, count)?),
        protocol::OP_CHOWN_AT => Mutation::Chown(service.prepare_chown_at(peer, payload, count)?),
        _ => return Err(protocol::STATUS_ENOSYS),
    };
    let base = match &mutation {
        Mutation::Mkdir(p) | Mutation::Fifo(p) => p.base,
        Mutation::Unlink(p) => p.base,
        Mutation::Truncate(p) => p.base,
        Mutation::Symlink(p) => p.base,
        Mutation::Times(p) => p.target.base,
        Mutation::Chmod(p) => p.base,
        Mutation::Chown(p) => p.base,
    };
    Ok((mutation, base))
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
        path_request::with_paths(
            state,
            peer,
            envelope.sources,
            filesystem,
            |service| {
                prepare(
                    service,
                    peer,
                    header.opcode,
                    payload,
                    envelope.sources.len(),
                )
            },
            |mutation, paths, filesystem| {
                run(
                    header.request_id,
                    mutation,
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
    service: &PosixService<H>,
    peer: PeerIdentity,
    header: protocol::Header,
    payload: &[u8],
    handles: &[AttachedObject<H>],
    admission: Option<Option<AttachedObject<H>>>,
    filesystem: &mut F,
) -> ObjectResponse<H> {
    let result = prepare(service, peer, header.opcode, payload, handles.len()).and_then(
        |(mutation, base)| {
            let paths = service.path_objects(peer.process_id, base, handles)?;
            Ok(run(
                header.request_id,
                &mutation,
                paths,
                admission,
                filesystem,
            ))
        },
    );
    result.unwrap_or_else(|status| object_error(header.request_id, status))
}

fn run<H: Copy, F: FilesystemBackend<H>>(
    request_id: u64,
    mutation: &Mutation,
    paths: PathObjects<H>,
    admission: Option<Option<AttachedObject<H>>>,
    filesystem: &mut F,
) -> ObjectResponse<H> {
    let result = match mutation {
        Mutation::Mkdir(p) => filesystem.mkdir_at(p, paths).map_err(MutationError::Failed),
        Mutation::Fifo(p) => filesystem
            .mkfifo_at(p, paths)
            .map_err(MutationError::Failed),
        Mutation::Unlink(p) => filesystem
            .unlink_at(p, paths)
            .map_err(MutationError::Failed),
        Mutation::Truncate(p) => match admission {
            Some(ticket) => filesystem.truncate_at_admitted(p, paths, ticket),
            None => filesystem
                .truncate_at(p, paths)
                .map_err(MutationError::Failed),
        },
        Mutation::Symlink(p) => filesystem
            .symlink_at(p, paths)
            .map_err(MutationError::Failed),
        Mutation::Times(p) => filesystem
            .utimens_at(p, paths)
            .map_err(MutationError::Failed),
        Mutation::Chmod(p) => filesystem.chmod_at(p, paths).map_err(MutationError::Failed),
        Mutation::Chown(p) => filesystem.chown_at(p, paths).map_err(MutationError::Failed),
    };
    match result {
        Ok(()) => object_error(request_id, protocol::STATUS_OK),
        Err(error) => object_mutation_error(request_id, error, admission.is_some(), filesystem),
    }
}
