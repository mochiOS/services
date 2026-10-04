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
    pub saved_uid: u32,
    pub real_gid: u32,
    pub effective_gid: u32,
    pub saved_gid: u32,
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedStat {
    pub base: protocol::OpenBase,
    pub flags: u32,
    pub path: String,
    pub effective_uid: u32,
    pub effective_gid: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedAccess {
    pub base: protocol::OpenBase,
    pub flags: u32,
    pub modes: u32,
    pub path: String,
    pub uid: u32,
    pub gid: u32,
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PathObjects<H> {
    pub root: AttachedObject<H>,
    pub base: Option<AttachedObject<H>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SessionDirectories<H> {
    pub root: AttachedObject<H>,
    pub cwd: AttachedObject<H>,
}

pub trait FilesystemBackend<H: Copy> {
    /// Opens two independently-owned handles for the filesystem root. They
    /// become the initial process root and current working directory.
    fn open_session_root(
        &mut self,
        effective_uid: u32,
        effective_gid: u32,
    ) -> Result<SessionDirectories<H>, i32>;

    /// Executes path resolution, optional creation, exclusivity checks and
    /// opening as one backend operation.
    fn open_at(
        &mut self,
        request: &PreparedOpen,
        paths: PathObjects<H>,
    ) -> Result<OpenedObject<H>, i32>;

    /// Resolves and reads metadata in one backend operation.
    fn stat_at(
        &mut self,
        request: &PreparedStat,
        paths: PathObjects<H>,
    ) -> Result<protocol::FileStatus, i32>;

    /// Reads metadata from the open file description identified by `file`.
    fn fstat(&mut self, file: AttachedObject<H>) -> Result<protocol::FileStatus, i32>;

    fn ftruncate(&mut self, file: AttachedObject<H>, length: u64) -> Result<(), i32>;

    fn fsync(&mut self, file: AttachedObject<H>) -> Result<(), i32>;

    /// Resolves a path and checks access using the supplied authenticated
    /// POSIX credentials as one backend operation.
    fn access_at(&mut self, request: &PreparedAccess, paths: PathObjects<H>) -> Result<(), i32>;

    /// Retains an attached object beyond the lifetime of the current IPC
    /// request, monotonically preserving or reducing its rights.
    fn retain_object(&mut self, object: AttachedObject<H>) -> Result<AttachedObject<H>, i32>;

    /// Releases one service-owned object reference.
    fn release_object(&mut self, object: AttachedObject<H>);

    /// Returns the live path of `directory` relative to `root`.
    fn directory_path(
        &mut self,
        root: AttachedObject<H>,
        directory: AttachedObject<H>,
    ) -> Result<Vec<u8>, i32>;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObjectResponse<H> {
    pub response: Response,
    pub handles: Vec<OpenedObject<H>>,
}

#[derive(Debug, Default)]
pub struct PosixService<H: Copy = u32> {
    sessions: BTreeMap<u64, Session>,
    directories: BTreeMap<u64, SessionDirectories<H>>,
}

impl PosixService<u32> {
    pub const fn new() -> Self {
        Self {
            sessions: BTreeMap::new(),
            directories: BTreeMap::new(),
        }
    }
}

impl<H: Copy> PosixService<H> {
    pub fn session(&self, process_id: u64) -> Option<&Session> {
        self.sessions.get(&process_id)
    }

    pub fn session_directories(&self, process_id: u64) -> Option<&SessionDirectories<H>> {
        self.directories.get(&process_id)
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
                    saved_uid: peer.effective_uid,
                    real_gid: peer.effective_gid,
                    effective_gid: peer.effective_gid,
                    saved_gid: peer.effective_gid,
                    umask: 0o022,
                });
                Ok(Vec::new())
            }
            protocol::OP_SESSION_INFO if header.flags == 0 && payload.is_empty() => {
                self.session_info(peer.process_id)
            }
            protocol::OP_UMASK_SET if header.flags == 0 => self.set_umask(peer.process_id, payload),
            protocol::OP_SET_UID if header.flags == 0 => {
                self.set_uid(peer.process_id, payload).map(|_| Vec::new())
            }
            protocol::OP_SET_GID if header.flags == 0 => {
                self.set_gid(peer.process_id, payload).map(|_| Vec::new())
            }
            protocol::OP_PING
            | protocol::OP_SESSION_REGISTER
            | protocol::OP_SESSION_INFO
            | protocol::OP_UMASK_SET
            | protocol::OP_OPEN_AT
            | protocol::OP_STAT_AT
            | protocol::OP_FSTAT
            | protocol::OP_ACCESS_AT
            | protocol::OP_CHDIR_AT
            | protocol::OP_FCHDIR
            | protocol::OP_GETCWD => Err(STATUS_EINVAL),
            protocol::OP_SET_UID
            | protocol::OP_SET_GID
            | protocol::OP_FTRUNCATE
            | protocol::OP_FSYNC => Err(STATUS_EINVAL),
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

    pub fn handle_objects<F: FilesystemBackend<H>>(
        &mut self,
        peer: PeerIdentity,
        header: protocol::Header,
        payload: &[u8],
        handles: &[AttachedObject<H>],
        filesystem: &mut F,
    ) -> ObjectResponse<H> {
        if !matches!(
            header.opcode,
            protocol::OP_OPEN_AT
                | protocol::OP_STAT_AT
                | protocol::OP_FSTAT
                | protocol::OP_ACCESS_AT
                | protocol::OP_CHDIR_AT
                | protocol::OP_FCHDIR
                | protocol::OP_GETCWD
                | protocol::OP_FTRUNCATE
                | protocol::OP_FSYNC
        ) {
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
        if matches!(
            header.opcode,
            protocol::OP_OPEN_AT
                | protocol::OP_STAT_AT
                | protocol::OP_ACCESS_AT
                | protocol::OP_CHDIR_AT
                | protocol::OP_FCHDIR
                | protocol::OP_GETCWD
        ) {
            if let Err(status) = self.ensure_session_directories(peer.process_id, filesystem) {
                return object_error(header.request_id, status);
            }
        }
        match header.opcode {
            protocol::OP_OPEN_AT => {
                let prepared = match self.prepare_open_at(peer, payload, handles.len()) {
                    Ok(prepared) => prepared,
                    Err(status) => return object_error(header.request_id, status),
                };
                let paths = match self.path_objects(peer.process_id, prepared.base, handles) {
                    Ok(paths) => paths,
                    Err(status) => return object_error(header.request_id, status),
                };
                match filesystem.open_at(&prepared, paths) {
                    Ok(opened) => ObjectResponse {
                        response: status_response(header.request_id, protocol::STATUS_OK),
                        handles: vec![opened],
                    },
                    Err(status) => object_error(header.request_id, status),
                }
            }
            protocol::OP_STAT_AT => {
                let prepared = match self.prepare_stat_at(peer, payload, handles.len()) {
                    Ok(prepared) => prepared,
                    Err(status) => return object_error(header.request_id, status),
                };
                let paths = match self.path_objects(peer.process_id, prepared.base, handles) {
                    Ok(paths) => paths,
                    Err(status) => return object_error(header.request_id, status),
                };
                match filesystem.stat_at(&prepared, paths) {
                    Ok(status) => object_status(header.request_id, status),
                    Err(status) => object_error(header.request_id, status),
                }
            }
            protocol::OP_FSTAT => {
                if !payload.is_empty() || handles.len() != 1 {
                    return object_error(header.request_id, STATUS_EINVAL);
                }
                if !self.sessions.contains_key(&peer.process_id) {
                    return object_error(header.request_id, protocol::STATUS_ESRCH);
                }
                match filesystem.fstat(handles[0]) {
                    Ok(status) => object_status(header.request_id, status),
                    Err(status) => object_error(header.request_id, status),
                }
            }
            protocol::OP_ACCESS_AT => {
                let prepared = match self.prepare_access_at(peer, payload, handles.len()) {
                    Ok(prepared) => prepared,
                    Err(status) => return object_error(header.request_id, status),
                };
                let paths = match self.path_objects(peer.process_id, prepared.base, handles) {
                    Ok(paths) => paths,
                    Err(status) => return object_error(header.request_id, status),
                };
                match filesystem.access_at(&prepared, paths) {
                    Ok(()) => object_error(header.request_id, protocol::STATUS_OK),
                    Err(status) => object_error(header.request_id, status),
                }
            }
            protocol::OP_CHDIR_AT => {
                let prepared = match self.prepare_stat_at(peer, payload, handles.len()) {
                    Ok(prepared) if prepared.flags == 0 => prepared,
                    Ok(_) => return object_error(header.request_id, STATUS_EINVAL),
                    Err(status) => return object_error(header.request_id, status),
                };
                let paths = match self.path_objects(peer.process_id, prepared.base, handles) {
                    Ok(paths) => paths,
                    Err(status) => return object_error(header.request_id, status),
                };
                let open = PreparedOpen {
                    base: prepared.base,
                    options: protocol::OPEN_READ | protocol::OPEN_DIRECTORY,
                    mode: 0,
                    path: prepared.path,
                    effective_uid: prepared.effective_uid,
                    effective_gid: prepared.effective_gid,
                };
                match filesystem.open_at(&open, paths) {
                    Ok(opened) => {
                        self.replace_cwd(
                            peer.process_id,
                            AttachedObject {
                                handle: opened.handle,
                                rights: opened.rights,
                            },
                            filesystem,
                        );
                        object_error(header.request_id, protocol::STATUS_OK)
                    }
                    Err(status) => object_error(header.request_id, status),
                }
            }
            protocol::OP_FCHDIR => {
                if !payload.is_empty() || handles.len() != 1 {
                    return object_error(header.request_id, STATUS_EINVAL);
                }
                let directory = handles[0];
                let status = match filesystem.fstat(directory) {
                    Ok(status) => status,
                    Err(status) => return object_error(header.request_id, status),
                };
                if status.mode & 0o170000 != 0o040000 {
                    return object_error(header.request_id, -20);
                }
                let retained = match filesystem.retain_object(directory) {
                    Ok(retained) => retained,
                    Err(status) => return object_error(header.request_id, status),
                };
                self.replace_cwd(peer.process_id, retained, filesystem);
                object_error(header.request_id, protocol::STATUS_OK)
            }
            protocol::OP_GETCWD => {
                if !payload.is_empty() || !handles.is_empty() {
                    return object_error(header.request_id, STATUS_EINVAL);
                }
                let directories = match self.directories.get(&peer.process_id) {
                    Some(directories) => *directories,
                    None => return object_error(header.request_id, protocol::STATUS_ESRCH),
                };
                match filesystem.directory_path(directories.root, directories.cwd) {
                    Ok(path) => object_payload(header.request_id, path),
                    Err(status) => object_error(header.request_id, status),
                }
            }
            protocol::OP_FTRUNCATE => {
                if handles.len() != 1 {
                    return object_error(header.request_id, STATUS_EINVAL);
                }
                if !self.sessions.contains_key(&peer.process_id) {
                    return object_error(header.request_id, protocol::STATUS_ESRCH);
                }
                let length = match protocol::decode_file_length(payload) {
                    Ok(length) => length,
                    Err(_) => return object_error(header.request_id, STATUS_EINVAL),
                };
                match filesystem.ftruncate(handles[0], length) {
                    Ok(()) => object_error(header.request_id, protocol::STATUS_OK),
                    Err(status) => object_error(header.request_id, status),
                }
            }
            protocol::OP_FSYNC => {
                if !payload.is_empty() || handles.len() != 1 {
                    return object_error(header.request_id, STATUS_EINVAL);
                }
                if !self.sessions.contains_key(&peer.process_id) {
                    return object_error(header.request_id, protocol::STATUS_ESRCH);
                }
                match filesystem.fsync(handles[0]) {
                    Ok(()) => object_error(header.request_id, protocol::STATUS_OK),
                    Err(status) => object_error(header.request_id, status),
                }
            }
            _ => unreachable!(),
        }
    }

    fn replace_cwd<F: FilesystemBackend<H>>(
        &mut self,
        process_id: u64,
        cwd: AttachedObject<H>,
        filesystem: &mut F,
    ) {
        if let Some(directories) = self.directories.get_mut(&process_id) {
            let previous = core::mem::replace(&mut directories.cwd, cwd);
            filesystem.release_object(previous);
        }
    }

    fn ensure_session_directories<F: FilesystemBackend<H>>(
        &mut self,
        process_id: u64,
        filesystem: &mut F,
    ) -> Result<(), i32> {
        if self.directories.contains_key(&process_id) {
            return Ok(());
        }
        let session = self
            .sessions
            .get(&process_id)
            .ok_or(protocol::STATUS_ESRCH)?;
        let directories =
            filesystem.open_session_root(session.effective_uid, session.effective_gid)?;
        self.directories.insert(process_id, directories);
        Ok(())
    }

    fn path_objects(
        &self,
        process_id: u64,
        base: protocol::OpenBase,
        handles: &[AttachedObject<H>],
    ) -> Result<PathObjects<H>, i32> {
        let directories = self
            .directories
            .get(&process_id)
            .ok_or(protocol::STATUS_ESRCH)?;
        let base = match base {
            protocol::OpenBase::ProcessRoot => None,
            protocol::OpenBase::ProcessCwd => Some(directories.cwd),
            protocol::OpenBase::AttachedDirectory => handles.first().copied(),
        };
        Ok(PathObjects {
            root: directories.root,
            base,
        })
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

    pub fn prepare_stat_at(
        &self,
        peer: PeerIdentity,
        payload: &[u8],
        attached_handles: usize,
    ) -> Result<PreparedStat, i32> {
        let session = self
            .sessions
            .get(&peer.process_id)
            .ok_or(protocol::STATUS_ESRCH)?;
        let request = protocol::decode_stat_at(payload).map_err(|_| STATUS_EINVAL)?;
        let expected_handles = usize::from(request.base == protocol::OpenBase::AttachedDirectory);
        if attached_handles != expected_handles {
            return Err(STATUS_EINVAL);
        }
        Ok(PreparedStat {
            base: request.base,
            flags: request.flags,
            path: request.path.to_owned(),
            effective_uid: session.effective_uid,
            effective_gid: session.effective_gid,
        })
    }

    pub fn prepare_access_at(
        &self,
        peer: PeerIdentity,
        payload: &[u8],
        attached_handles: usize,
    ) -> Result<PreparedAccess, i32> {
        let session = self
            .sessions
            .get(&peer.process_id)
            .ok_or(protocol::STATUS_ESRCH)?;
        let request = protocol::decode_access_at(payload).map_err(|_| STATUS_EINVAL)?;
        let expected_handles = usize::from(request.base == protocol::OpenBase::AttachedDirectory);
        if attached_handles != expected_handles {
            return Err(STATUS_EINVAL);
        }
        let effective = request.flags & protocol::ACCESS_EFFECTIVE_IDS != 0;
        Ok(PreparedAccess {
            base: request.base,
            flags: request.flags,
            modes: request.modes,
            path: request.path.to_owned(),
            uid: if effective {
                session.effective_uid
            } else {
                session.real_uid
            },
            gid: if effective {
                session.effective_gid
            } else {
                session.real_gid
            },
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

    fn set_uid(&mut self, process_id: u64, payload: &[u8]) -> Result<(), i32> {
        let requested =
            protocol::decode_credential_id(payload).map_err(|_| STATUS_EINVAL)?;
        let session = self
            .sessions
            .get_mut(&process_id)
            .ok_or(protocol::STATUS_ESRCH)?;
        if session.effective_uid == 0 {
            session.real_uid = requested;
            session.effective_uid = requested;
            session.saved_uid = requested;
            return Ok(());
        }
        if requested != session.real_uid && requested != session.saved_uid {
            return Err(-1);
        }
        session.effective_uid = requested;
        Ok(())
    }

    fn set_gid(&mut self, process_id: u64, payload: &[u8]) -> Result<(), i32> {
        let requested =
            protocol::decode_credential_id(payload).map_err(|_| STATUS_EINVAL)?;
        let session = self
            .sessions
            .get_mut(&process_id)
            .ok_or(protocol::STATUS_ESRCH)?;
        if session.effective_uid == 0 {
            session.real_gid = requested;
            session.effective_gid = requested;
            session.saved_gid = requested;
            return Ok(());
        }
        if requested != session.real_gid && requested != session.saved_gid {
            return Err(-1);
        }
        session.effective_gid = requested;
        Ok(())
    }
}

fn object_error<H>(request_id: u64, status: i32) -> ObjectResponse<H> {
    ObjectResponse {
        response: status_response(request_id, status),
        handles: Vec::new(),
    }
}

fn object_payload<H>(request_id: u64, payload: Vec<u8>) -> ObjectResponse<H> {
    ObjectResponse {
        response: Response {
            header: protocol::Header {
                opcode: protocol::OP_STATUS,
                request_id,
                payload_len: payload.len() as u32,
                status: protocol::STATUS_OK,
                ..protocol::Header::default()
            },
            payload,
        },
        handles: Vec::new(),
    }
}

fn object_status<H>(request_id: u64, status: protocol::FileStatus) -> ObjectResponse<H> {
    let mut payload = vec![0u8; protocol::FILE_STATUS_LEN];
    if protocol::encode_file_status(status, &mut payload).is_err() {
        return object_error(request_id, STATUS_EINVAL);
    }
    ObjectResponse {
        response: Response {
            header: protocol::Header {
                opcode: protocol::OP_STATUS,
                request_id,
                payload_len: payload.len() as u32,
                status: protocol::STATUS_OK,
                ..protocol::Header::default()
            },
            payload,
        },
        handles: Vec::new(),
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
