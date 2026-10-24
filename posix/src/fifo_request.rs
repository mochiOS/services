//! Authenticated dispatcher preflight; no state lock may span the worker RPC.
use crate::{AttachedObject, ObjectResponse, OpenedObject};
use mochios_posix_protocol as wire;
pub fn execute<H: Copy>(
    header: wire::Header,
    payload: &[u8],
    sources: &[AttachedObject<H>],
    query: impl FnOnce(AttachedObject<H>, wire::fifo::WaitCondition) -> Result<OpenedObject<H>, i32>,
    mut close: impl FnMut(H),
) -> ObjectResponse<H> {
    let result = (|| {
        if header.opcode != wire::OP_FIFO_WAIT {
            return Err(wire::STATUS_ENOSYS);
        }
        if header.flags != 0
            || header.status != 0
            || header.payload_len as usize != payload.len()
            || sources.len() != 1
        {
            return Err(-22);
        }
        let condition = wire::fifo::WaitCondition::decode(payload).map_err(|_| -22)?;
        let source = sources[0];
        let rights =
            condition.source_direction(source.rights).ok_or(-13)? | mnu_abi::HANDLE_RIGHT_TRANSFER;
        if source.rights != rights {
            return Err(-13);
        }
        let opened = query(source, condition)?;
        if opened.rights != wire::fifo::NOTIFICATION_RIGHTS {
            close(opened.handle);
            return Err(-5);
        }
        Ok(opened)
    })();
    match result {
        Ok(opened) => ObjectResponse {
            response: crate::status_response(header.request_id, 0),
            handles: vec![opened],
        },
        Err(status) => crate::object_error(header.request_id, status),
    }
}
