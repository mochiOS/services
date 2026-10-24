//! Boot authority is the process selected by the inherited bootstrap Handle,
//! never a claimed PID, UID 0 alone, or a service-name lookup.
use crate::{AttachedObject, PeerIdentity, PosixService};
use mochios_posix_protocol as protocol;
pub fn install<H: Copy + Default + Eq>(
    service: &mut PosixService<H>,
    peer: PeerIdentity,
    header: protocol::Header,
    payload: &[u8],
    attachments: &[AttachedObject<H>],
) -> Result<(), i32> {
    if header.opcode != protocol::OP_NETWORK_ENDPOINT_INSTALL
        || header.flags != 0
        || header.status != 0
        || !payload.is_empty()
        || attachments.len() != 1
    {
        return Err(-22);
    }
    if service.bootstrap_process_id != Some(peer.process_id)
        || !service
            .sessions
            .get(&peer.process_id)
            .is_some_and(|s| s.effective_uid == 0)
    {
        return Err(-1);
    }
    let endpoint = attachments[0];
    if endpoint.handle == H::default() || endpoint.rights != protocol::network::endpoint_rights() {
        return Err(-13);
    }
    if service.network_endpoint.is_some() {
        return Err(-17);
    }
    service.network_endpoint = Some(endpoint.handle);
    Ok(())
}
impl<H: Copy> PosixService<H> {
    /// Borrowed reference owned by service lifetime. It is not per-process
    /// socket authority: clients must still attach their own factory Handle.
    pub fn network_endpoint(&self) -> Option<H> {
        self.network_endpoint
    }
}
