//! Validate the complete request before allocating terminal objects.
use super::*;

pub fn execute<H: Copy>(
    header: protocol::Header,
    payload: &[u8],
    handles: &[AttachedObject<H>],
    open: impl FnOnce() -> ObjectResponse<H>,
) -> ObjectResponse<H> {
    if header.opcode != protocol::OP_PTY_OPEN
        || header.flags != 0
        || header.status != 0
        || header.payload_len != 0
        || !payload.is_empty()
        || !handles.is_empty()
    {
        return object_error(header.request_id, STATUS_EINVAL);
    }
    open()
}
