//! Decode the retained-inode/ordinary-open union after successful native FS
//! IPC. Input references stay caller-owned until a validated result takes them.
use crate::{
    MutationError, OpenCompletion, OpenedObject, PreparedOpen,
    fifo::Access,
    filesystem_transport::{MutationReply, mutation_status},
};
use mnu_abi::IpcObjectHandles;
use mochios_filesystem_protocol as fs;
use mochios_posix_protocol as posix;

pub fn finish(
    header: fs::Header,
    request_id: u64,
    payload: &[u8],
    objects: &mut IpcObjectHandles,
    request: &PreparedOpen,
    register: impl FnOnce(
        fs::Header,
        &[u8],
        IpcObjectHandles,
        Access,
        bool,
    ) -> Result<OpenCompletion<u32>, i32>,
) -> Result<OpenCompletion<u32>, MutationError<u32>> {
    if objects.delivery_flags != 0 {
        return Err((-5).into());
    }
    if header.flags == fs::OPEN_REPLY_FIFO {
        crate::fifo_inode::validate_reply(header, request_id, payload, objects)?;
        let access = match request.options & (posix::OPEN_READ | posix::OPEN_WRITE) {
            posix::OPEN_READ => Access::Read,
            posix::OPEN_WRITE => Access::Write,
            _ => return Err((-22).into()),
        };
        let owned = std::mem::take(objects);
        return register(
            header,
            payload,
            owned,
            access,
            request.options & posix::OPEN_NONBLOCK != 0,
        )
        .map_err(Into::into);
    }
    let kind = mutation_status(header, request_id, payload, objects, 1)?;
    let object = objects.handles[0];
    let opened = OpenedObject {
        handle: object.handle,
        rights: object.rights,
    };
    *objects = Default::default();
    match kind {
        MutationReply::Ready => Ok(OpenCompletion::Ready(opened)),
        MutationReply::Wait => Err(MutationError::Wait(opened)),
    }
}
