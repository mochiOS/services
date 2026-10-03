use std::collections::BTreeMap;

use mochios_posix_protocol as protocol;

pub const STATUS_EINVAL: i32 = -22;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PeerIdentity {
    pub process_id: u64,
    pub effective_uid: u32,
    pub effective_gid: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Session {
    pub process_id: u64,
    pub real_uid: u32,
    pub effective_uid: u32,
    pub real_gid: u32,
    pub effective_gid: u32,
    pub umask: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Response {
    pub header: protocol::Header,
    pub payload: Vec<u8>,
}

#[derive(Debug, Default)]
pub struct PosixService {
    sessions: BTreeMap<u64, Session>,
}

impl PosixService {
    pub const fn new() -> Self {
        Self {
            sessions: BTreeMap::new(),
        }
    }

    pub fn session(&self, process_id: u64) -> Option<&Session> {
        self.sessions.get(&process_id)
    }

    pub fn handle(
        &mut self,
        peer: PeerIdentity,
        header: protocol::Header,
        payload: &[u8],
    ) -> Response {
        let status = match header.opcode {
            protocol::OP_PING if payload.is_empty() => protocol::STATUS_OK,
            protocol::OP_SESSION_REGISTER if payload.is_empty() => {
                self.sessions.entry(peer.process_id).or_insert(Session {
                    process_id: peer.process_id,
                    real_uid: peer.effective_uid,
                    effective_uid: peer.effective_uid,
                    real_gid: peer.effective_gid,
                    effective_gid: peer.effective_gid,
                    umask: 0o022,
                });
                protocol::STATUS_OK
            }
            protocol::OP_PING | protocol::OP_SESSION_REGISTER => STATUS_EINVAL,
            _ => protocol::STATUS_ENOSYS,
        };
        Response {
            header: protocol::Header {
                opcode: protocol::OP_STATUS,
                request_id: header.request_id,
                flags: 0,
                payload_len: 0,
                status,
            },
            payload: Vec::new(),
        }
    }
}
