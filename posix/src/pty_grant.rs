//! POSIX real-ID policy; provider/FS RPC runs without the POSIX state lock.
use crate::{
    AttachedObject, ObjectResponse, PeerIdentity, PosixService, terminal_publication::Name,
};
use mnu_abi::{HANDLE_RIGHT_CONTROL as C, HANDLE_RIGHT_TRANSFER as T, HANDLE_RIGHT_WRITE as W};
use mochios_posix_protocol as protocol;
use std::sync::Mutex;

pub const RIGHTS: u64 = W | C | T;

pub fn execute(
    state: &Mutex<PosixService<u32>>,
    peer: PeerIdentity,
    header: protocol::Header,
    payload: &[u8],
    objects: &[AttachedObject<u32>],
    identify: impl FnOnce(AttachedObject<u32>) -> Result<Name, i32>,
    grant: impl FnOnce(&Name, u32, u32) -> Result<(), i32>,
) -> ObjectResponse<u32> {
    let result = (|| {
        if header.opcode != protocol::OP_PTY_GRANT_MASTER
            || header.flags != 0
            || header.status != 0
            || header.payload_len != 0
            || !payload.is_empty()
            || objects.len() != 1
        {
            return Err(crate::STATUS_EINVAL);
        }
        let source = objects[0];
        if source.handle == 0 || source.rights & RIGHTS != RIGHTS {
            return Err(-13);
        }
        let (uid, gid) = {
            let state = state.lock().map_err(|_| protocol::STATUS_EIO)?;
            if state.registered_peer(peer.process_id) != Some(peer) {
                return Err(protocol::STATUS_EPERM);
            }
            let session = state
                .session(peer.process_id)
                .ok_or(protocol::STATUS_ESRCH)?;
            (session.real_uid, session.real_gid)
        };
        // Query our retained owner endpoint. Never trust identity bytes from
        // HandleControl on an arbitrary caller-controlled provider.
        let name = identify(AttachedObject {
            rights: RIGHTS,
            ..source
        })?;
        grant(&name, uid, gid)
    })();
    ObjectResponse {
        response: crate::status_response(header.request_id, result.err().unwrap_or(0)),
        handles: Vec::new(),
    }
}
