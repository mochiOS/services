use std::collections::BTreeMap;
use std::string::String;

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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedOpen {
    pub base: protocol::OpenBase,
    pub options: u32,
    pub mode: u32,
    pub path: String,
    pub effective_uid: u32,
    pub effective_gid: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AttachedObject<H> {
    pub handle: H,
    pub rights: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OpenedObject<H> {
    pub handle: H,
    pub rights: u64,
}

pub trait FilesystemBackend<H: Copy> {
    /// Executes path resolution, optional creation, exclusivity checks and
    /// opening as one backend operation.
    fn open_at(
        &mut self,
        request: &PreparedOpen,
        directory: Option<AttachedObject<H>>,
    ) -> Result<OpenedObject<H>, i32>;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObjectResponse<H> {
    pub response: Response,
    pub handles: Vec<OpenedObject<H>>,
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
        let result = match header.opcode {
            protocol::OP_PING if header.flags == 0 && payload.is_empty() => Ok(Vec::new()),
            protocol::OP_SESSION_REGISTER if header.flags == 0 && payload.is_empty() => {
                self.sessions.entry(peer.process_id).or_insert(Session {
                    process_id: peer.process_id,
                    real_uid: peer.effective_uid,
                    effective_uid: peer.effective_uid,
                    real_gid: peer.effective_gid,
                    effective_gid: peer.effective_gid,
                    umask: 0o022,
                });
                Ok(Vec::new())
            }
            protocol::OP_SESSION_INFO if header.flags == 0 && payload.is_empty() => {
                self.session_info(peer.process_id)
            }
            protocol::OP_UMASK_SET if header.flags == 0 => {
                self.set_umask(peer.process_id, payload)
            }
            protocol::OP_PING
            | protocol::OP_SESSION_REGISTER
            | protocol::OP_SESSION_INFO
            | protocol::OP_UMASK_SET
            | protocol::OP_OPEN_AT => Err(STATUS_EINVAL),
            _ => Err(protocol::STATUS_ENOSYS),
        };
        let (status, payload) = match result {
            Ok(payload) => (protocol::STATUS_OK, payload),
            Err(status) => (status, Vec::new()),
        };
        Response {
            header: protocol::Header {
                opcode: protocol::OP_STATUS,
                request_id: header.request_id,
                flags: 0,
                payload_len: payload.len() as u32,
                status,
            },
            payload,
        }
    }

    pub fn handle_objects<H: Copy, F: FilesystemBackend<H>>(
        &mut self,
        peer: PeerIdentity,
        header: protocol::Header,
        payload: &[u8],
        handles: &[AttachedObject<H>],
        filesystem: &mut F,
    ) -> ObjectResponse<H> {
        if header.opcode != protocol::OP_OPEN_AT {
            let response = if handles.is_empty() {
                self.handle(peer, header, payload)
            } else {
                status_response(header.request_id, STATUS_EINVAL)
            };
            return ObjectResponse {
                response,
                handles: Vec::new(),
            };
        }
        if header.flags != 0 {
            return ObjectResponse {
                response: status_response(header.request_id, STATUS_EINVAL),
                handles: Vec::new(),
            };
        }
        let prepared = match self.prepare_open_at(peer, payload, handles.len()) {
            Ok(prepared) => prepared,
            Err(status) => {
                return ObjectResponse {
                    response: status_response(header.request_id, status),
                    handles: Vec::new(),
                };
            }
        };
        let directory = (prepared.base == protocol::OpenBase::AttachedDirectory)
            .then(|| handles.first().copied())
            .flatten();
        match filesystem.open_at(&prepared, directory) {
            Ok(opened) => ObjectResponse {
                response: status_response(header.request_id, protocol::STATUS_OK),
                handles: vec![opened],
            },
            Err(status) => ObjectResponse {
                response: status_response(header.request_id, status),
                handles: Vec::new(),
            },
        }
    }


    pub fn prepare_open_at(
        &self,
        peer: PeerIdentity,
        payload: &[u8],
        attached_handles: usize,
    ) -> Result<PreparedOpen, i32> {
        let session = self
            .sessions
            .get(&peer.process_id)
            .ok_or(protocol::STATUS_ESRCH)?;
        let request = protocol::decode_open_at(payload).map_err(|_| STATUS_EINVAL)?;
        let expected_handles = usize::from(request.base == protocol::OpenBase::AttachedDirectory);
        if attached_handles != expected_handles {
            return Err(STATUS_EINVAL);
        }
        let access = request.options & (protocol::OPEN_READ | protocol::OPEN_WRITE);
        if access == 0
            || request.options & protocol::OPEN_EXCLUSIVE != 0
                && request.options & protocol::OPEN_CREATE == 0
            || request.options & (protocol::OPEN_TRUNCATE | protocol::OPEN_APPEND) != 0
                && request.options & protocol::OPEN_WRITE == 0
        {
            return Err(STATUS_EINVAL);
        }
        Ok(PreparedOpen {
            base: request.base,
            options: request.options,
            mode: (request.mode & 0o7777) & !(session.umask & 0o777),
            path: request.path.to_owned(),
            effective_uid: session.effective_uid,
            effective_gid: session.effective_gid,
        })
    }

    fn session_info(&self, process_id: u64) -> Result<Vec<u8>, i32> {
        let session = self
            .sessions
            .get(&process_id)
            .ok_or(protocol::STATUS_ESRCH)?;
        let mut payload = vec![0u8; protocol::SESSION_INFO_LEN];
        protocol::encode_session_info(
            protocol::SessionInfo {
                real_uid: session.real_uid,
                effective_uid: session.effective_uid,
                real_gid: session.real_gid,
                effective_gid: session.effective_gid,
                umask: session.umask,
            },
            &mut payload,
        )
        .map_err(|_| STATUS_EINVAL)?;
        Ok(payload)
    }

    fn set_umask(&mut self, process_id: u64, payload: &[u8]) -> Result<Vec<u8>, i32> {
        let requested = protocol::decode_umask(payload).map_err(|_| STATUS_EINVAL)?;
        let session = self
            .sessions
            .get_mut(&process_id)
            .ok_or(protocol::STATUS_ESRCH)?;
        let previous = session.umask;
        session.umask = requested & 0o777;
        let mut response = vec![0u8; protocol::UMASK_PAYLOAD_LEN];
        protocol::encode_umask(previous, &mut response).map_err(|_| STATUS_EINVAL)?;
        Ok(response)
    }
}

fn status_response(request_id: u64, status: i32) -> Response {
    Response {
        header: protocol::Header {
            opcode: protocol::OP_STATUS,
            request_id,
            status,
            ..protocol::Header::default()
        },
        payload: Vec::new(),
    }
}
