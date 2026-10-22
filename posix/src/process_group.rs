//! Process-group changes use retained native image metadata, not exec claims.
use super::*;

impl<H: Copy> PosixService<H> {
    pub fn handle_process_group_request<P: ProcessBackend<H>>(
        &mut self,
        peer: PeerIdentity,
        header: protocol::Header,
        payload: &[u8],
        handles: &[AttachedObject<H>],
        processes: &mut P,
    ) -> ObjectResponse<H> {
        let result = if header.opcode != protocol::OP_SET_PROCESS_GROUP {
            Err(protocol::STATUS_ENOSYS)
        } else if header.flags != 0 || header.status != 0 || !handles.is_empty() {
            Err(STATUS_EINVAL)
        } else {
            // A PID here selects only self or an already registered direct
            // child. The client cannot supply the observed ProcessHandle.
            self.set_process_group(peer.process_id, payload, |handle| {
                processes.image_status(handle)
            })
        };
        object_error(
            header.request_id,
            result.err().unwrap_or(protocol::STATUS_OK),
        )
    }
}
