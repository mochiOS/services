use std::collections::{BTreeMap, BTreeSet};
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
pub struct PreparedMkdir {
    pub base: protocol::OpenBase,
    pub mode: u32,
    pub path: String,
    pub effective_uid: u32,
    pub effective_gid: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedUnlink {
    pub base: protocol::OpenBase,
    pub flags: u32,
    pub path: String,
    pub effective_uid: u32,
    pub effective_gid: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedRename {
    pub old_base: protocol::OpenBase,
    pub new_base: protocol::OpenBase,
    pub old_path: String,
    pub new_path: String,
    pub effective_uid: u32,
    pub effective_gid: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedTruncate {
    pub base: protocol::OpenBase,
    pub path: String,
    pub length: u64,
    pub effective_uid: u32,
    pub effective_gid: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedSymlink {
    pub base: protocol::OpenBase,
    pub target: String,
    pub link_path: String,
    pub effective_uid: u32,
    pub effective_gid: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedReadlink {
    pub base: protocol::OpenBase,
    pub path: String,
    pub effective_uid: u32,
    pub effective_gid: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedChmod {
    pub base: protocol::OpenBase,
    pub path: String,
    pub mode: u32,
    pub effective_uid: u32,
    pub effective_gid: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedChown {
    pub base: protocol::OpenBase,
    pub path: String,
    pub flags: u32,
    pub uid: u32,
    pub gid: u32,
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
pub struct RenamePathObjects<H> {
    pub root: AttachedObject<H>,
    pub old_base: Option<AttachedObject<H>>,
    pub new_base: Option<AttachedObject<H>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SessionDirectories<H> {
    pub root: AttachedObject<H>,
    pub cwd: AttachedObject<H>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuthenticatedProcess<H> {
    pub handle: H,
    pub process_id: u64,
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

    fn fchmod(
        &mut self,
        file: AttachedObject<H>,
        mode: u32,
        effective_uid: u32,
        effective_gid: u32,
    ) -> Result<(), i32>;

    fn fchown(
        &mut self,
        file: AttachedObject<H>,
        uid: u32,
        gid: u32,
        effective_uid: u32,
        effective_gid: u32,
    ) -> Result<(), i32>;

    fn fsync(&mut self, file: AttachedObject<H>) -> Result<(), i32>;

    fn get_status_flags(&mut self, file: AttachedObject<H>) -> Result<u32, i32>;

    fn set_status_flags(&mut self, file: AttachedObject<H>, flags: u32) -> Result<(), i32>;

    fn mkdir_at(&mut self, request: &PreparedMkdir, paths: PathObjects<H>) -> Result<(), i32>;

    fn unlink_at(&mut self, request: &PreparedUnlink, paths: PathObjects<H>) -> Result<(), i32>;

    fn rename_at(
        &mut self,
        request: &PreparedRename,
        paths: RenamePathObjects<H>,
    ) -> Result<(), i32>;

    fn truncate_at(&mut self, request: &PreparedTruncate, paths: PathObjects<H>) -> Result<(), i32>;

    fn symlink_at(&mut self, request: &PreparedSymlink, paths: PathObjects<H>) -> Result<(), i32>;

    fn readlink_at(
        &mut self,
        request: &PreparedReadlink,
        paths: PathObjects<H>,
    ) -> Result<Vec<u8>, i32>;

    fn chmod_at(&mut self, request: &PreparedChmod, paths: PathObjects<H>) -> Result<(), i32>;

    fn chown_at(&mut self, request: &PreparedChown, paths: PathObjects<H>) -> Result<(), i32>;

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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProcessLifecycle {
    Running,
    Exited { exit_code: u64 },
}

pub trait ProcessBackend<H: Copy> {
    fn status(&mut self, process: H) -> Result<ProcessLifecycle, i32>;
    fn release(&mut self, process: H);
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
    processes: BTreeMap<u64, H>,
    parents: BTreeMap<u64, u64>,
    children: BTreeMap<u64, BTreeSet<u64>>,
    process_groups: BTreeMap<u64, u64>,
    session_ids: BTreeMap<u64, u64>,
    resource_limits: BTreeMap<(u64, u32), protocol::ResourceLimit>,
}

impl PosixService<u32> {
    pub const fn new() -> Self {
        Self {
            sessions: BTreeMap::new(),
            directories: BTreeMap::new(),
            processes: BTreeMap::new(),
            parents: BTreeMap::new(),
            children: BTreeMap::new(),
            process_groups: BTreeMap::new(),
            session_ids: BTreeMap::new(),
            resource_limits: BTreeMap::new(),
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

    pub fn process_handle(&self, process_id: u64) -> Option<H> {
        self.processes.get(&process_id).copied()
    }

    pub fn parent_id(&self, process_id: u64) -> Option<u64> {
        self.parents.get(&process_id).copied()
    }

    pub fn is_child(&self, parent_id: u64, process_id: u64) -> bool {
        self.children
            .get(&parent_id)
            .is_some_and(|children| children.contains(&process_id))
    }

    /// Binds service state to a kernel-authenticated process object. The
    /// caller retains ownership when this returns `Ok(false)`.
    pub fn bind_process(
        &mut self,
        peer: PeerIdentity,
        process: AuthenticatedProcess<H>,
    ) -> Result<bool, i32> {
        if process.process_id != peer.process_id {
            return Err(STATUS_EINVAL);
        }
        if self.processes.contains_key(&peer.process_id) {
            return Ok(false);
        }
        self.processes.insert(peer.process_id, process.handle);
        self.process_groups.insert(peer.process_id, peer.process_id);
        self.session_ids.insert(peer.process_id, peer.process_id);
        Ok(true)
    }

    /// Installs POSIX state for a native process cloned by `peer`. Directory
    /// capabilities are retained so parent and child own independent service
    /// references to the same live filesystem objects.
    pub fn adopt_child<F: FilesystemBackend<H>>(
        &mut self,
        peer: PeerIdentity,
        process: AuthenticatedProcess<H>,
        filesystem: &mut F,
    ) -> Result<(), i32> {
        if process.process_id == peer.process_id
            || !self.processes.contains_key(&peer.process_id)
            || self.processes.contains_key(&process.process_id)
        {
            return Err(STATUS_EINVAL);
        }
        let parent_session = self
            .sessions
            .get(&peer.process_id)
            .copied()
            .ok_or(protocol::STATUS_ESRCH)?;
        let child_directories = if let Some(parent) = self.directories.get(&peer.process_id).copied()
        {
            let root = filesystem.retain_object(parent.root)?;
            let cwd = match filesystem.retain_object(parent.cwd) {
                Ok(cwd) => cwd,
                Err(error) => {
                    filesystem.release_object(root);
                    return Err(error);
                }
            };
            Some(SessionDirectories { root, cwd })
        } else {
            None
        };
        let child_id = process.process_id;
        let inherited_limits: Vec<(u32, protocol::ResourceLimit)> = self
            .resource_limits
            .iter()
            .filter_map(|(&(process_id, resource), &limit)| {
                (process_id == peer.process_id).then_some((resource, limit))
            })
            .collect();
        self.processes.insert(child_id, process.handle);
        self.sessions.insert(
            child_id,
            Session {
                process_id: child_id,
                ..parent_session
            },
        );
        if let Some(directories) = child_directories {
            self.directories.insert(child_id, directories);
        }
        self.parents.insert(child_id, peer.process_id);
        self.process_groups.insert(
            child_id,
            self.process_groups
                .get(&peer.process_id)
                .copied()
                .unwrap_or(peer.process_id),
        );
        self.session_ids.insert(
            child_id,
            self.session_ids
                .get(&peer.process_id)
                .copied()
                .unwrap_or(peer.process_id),
        );
        self.children
            .entry(peer.process_id)
            .or_default()
            .insert(child_id);
        for (resource, limit) in inherited_limits {
            self.resource_limits.insert((child_id, resource), limit);
        }
        Ok(())
    }

    pub fn wait_child<F: FilesystemBackend<H>, P: ProcessBackend<H>>(
        &mut self,
        peer: PeerIdentity,
        request: protocol::WaitRequest,
        filesystem: &mut F,
        processes: &mut P,
    ) -> Result<protocol::WaitResult, i32> {
        let candidates = self.matching_child_ids(peer, request)?;
        for child in candidates {
            let handle = self
                .processes
                .get(&child)
                .copied()
                .ok_or(protocol::STATUS_ESRCH)?;
            if let ProcessLifecycle::Exited { exit_code } = processes.status(handle)? {
                let status = ((exit_code & 0xff) as u32) << 8;
                self.reap_child(peer.process_id, child, filesystem, processes);
                return Ok(protocol::WaitResult {
                    process_id: child,
                    status,
                });
            }
        }
        if request.options & protocol::WAIT_NOHANG != 0 {
            Ok(protocol::WaitResult::default())
        } else {
            Err(protocol::STATUS_EAGAIN)
        }
    }

    /// Returns the native process handles whose lifecycle can satisfy a
    /// blocking wait request. The caller may wait on these together with its
    /// IPC endpoint without importing POSIX child semantics into the kernel.
    pub fn wait_handles(
        &self,
        peer: PeerIdentity,
        request: protocol::WaitRequest,
    ) -> Result<Vec<H>, i32> {
        self.matching_child_ids(peer, request)?
            .into_iter()
            .map(|child| {
                self.processes
                    .get(&child)
                    .copied()
                    .ok_or(protocol::STATUS_ESRCH)
            })
            .collect()
    }

    fn matching_child_ids(
        &self,
        peer: PeerIdentity,
        request: protocol::WaitRequest,
    ) -> Result<Vec<u64>, i32> {
        if request.options & !protocol::WAIT_OPTIONS_ALL != 0 {
            return Err(STATUS_EINVAL);
        }
        let caller_group = self
            .process_groups
            .get(&peer.process_id)
            .copied()
            .ok_or(protocol::STATUS_ESRCH)?;
        let children = self
            .children
            .get(&peer.process_id)
            .ok_or(protocol::STATUS_ECHILD)?;
        let requested_group = if request.selector < -1 {
            request.selector.checked_neg().map(|value| value as u64)
        } else {
            None
        };
        if request.selector < -1 && requested_group.is_none() {
            return Err(STATUS_EINVAL);
        }
        let candidates: Vec<u64> = children
            .iter()
            .copied()
            .filter(|child| match request.selector {
                selector if selector > 0 => *child == selector as u64,
                -1 => true,
                0 => self.process_groups.get(child).copied() == Some(caller_group),
                _ => self.process_groups.get(child).copied() == requested_group,
            })
            .collect();
        if candidates.is_empty() {
            return Err(protocol::STATUS_ECHILD);
        }
        Ok(candidates)
    }

    fn reap_child<F: FilesystemBackend<H>, P: ProcessBackend<H>>(
        &mut self,
        parent_id: u64,
        child_id: u64,
        filesystem: &mut F,
        processes: &mut P,
    ) {
        if let Some(children) = self.children.get_mut(&parent_id) {
            children.remove(&child_id);
            if children.is_empty() {
                self.children.remove(&parent_id);
            }
        }
        self.parents.remove(&child_id);
        self.process_groups.remove(&child_id);
        self.session_ids.remove(&child_id);
        self.resource_limits
            .retain(|(process_id, _), _| *process_id != child_id);
        self.sessions.remove(&child_id);
        if let Some(directories) = self.directories.remove(&child_id) {
            filesystem.release_object(directories.root);
            filesystem.release_object(directories.cwd);
        }
        if let Some(handle) = self.processes.remove(&child_id) {
            processes.release(handle);
        }
    }

    fn process_info_payload(&self, caller_id: u64, payload: &[u8]) -> Result<Vec<u8>, i32> {
        let requested = protocol::decode_process_id_request(payload).map_err(|_| STATUS_EINVAL)?;
        let process_id = match requested {
            0 => caller_id,
            value if value > 0 => value as u64,
            _ => return Err(STATUS_EINVAL),
        };
        let caller_session = self
            .session_ids
            .get(&caller_id)
            .copied()
            .ok_or(protocol::STATUS_ESRCH)?;
        if self.session_ids.get(&process_id).copied() != Some(caller_session) {
            return Err(protocol::STATUS_ESRCH);
        }
        encode_process_info_payload(self.process_info_for(process_id)?)
    }

    fn process_info_for(&self, process_id: u64) -> Result<protocol::ProcessInfo, i32> {
        Ok(protocol::ProcessInfo {
            process_id,
            parent_id: self.parents.get(&process_id).copied().unwrap_or(0),
            process_group_id: self
                .process_groups
                .get(&process_id)
                .copied()
                .ok_or(protocol::STATUS_ESRCH)?,
            session_id: self
                .session_ids
                .get(&process_id)
                .copied()
                .ok_or(protocol::STATUS_ESRCH)?,
        })
    }

    fn set_process_group(&mut self, caller_id: u64, payload: &[u8]) -> Result<(), i32> {
        let (process_id, process_group_id) =
            protocol::decode_process_group_request(payload).map_err(|_| STATUS_EINVAL)?;
        if process_id < 0 || process_group_id < 0 {
            return Err(STATUS_EINVAL);
        }
        let target = if process_id == 0 {
            caller_id
        } else {
            process_id as u64
        };
        if target != caller_id && self.parents.get(&target).copied() != Some(caller_id) {
            return Err(protocol::STATUS_ESRCH);
        }
        let caller_session = self
            .session_ids
            .get(&caller_id)
            .copied()
            .ok_or(protocol::STATUS_ESRCH)?;
        if self.session_ids.get(&target).copied() != Some(caller_session) {
            return Err(protocol::STATUS_EPERM);
        }
        if self.session_ids.get(&target).copied() == Some(target) {
            return Err(protocol::STATUS_EPERM);
        }
        let group = if process_group_id == 0 {
            target
        } else {
            process_group_id as u64
        };
        if group != target
            && !self.process_groups.iter().any(|(process, candidate)| {
                *candidate == group
                    && self.session_ids.get(process).copied() == Some(caller_session)
            })
        {
            return Err(protocol::STATUS_EPERM);
        }
        self.process_groups.insert(target, group);
        Ok(())
    }

    fn create_session(&mut self, process_id: u64) -> Result<protocol::ProcessInfo, i32> {
        if self
            .process_groups
            .values()
            .any(|group| *group == process_id)
        {
            return Err(protocol::STATUS_EPERM);
        }
        if !self.processes.contains_key(&process_id) {
            return Err(protocol::STATUS_ESRCH);
        }
        self.process_groups.insert(process_id, process_id);
        self.session_ids.insert(process_id, process_id);
        self.process_info_for(process_id)
    }

    fn resource_limit_payload(
        &mut self,
        caller_id: u64,
        payload: &[u8],
    ) -> Result<Vec<u8>, i32> {
        let request =
            protocol::decode_resource_limit_request(payload).map_err(|_| STATUS_EINVAL)?;
        if request.process_id < 0 || request.resource >= protocol::RLIMIT_COUNT {
            return Err(STATUS_EINVAL);
        }
        let target_id = if request.process_id == 0 {
            caller_id
        } else {
            request.process_id as u64
        };
        let caller = self
            .sessions
            .get(&caller_id)
            .copied()
            .ok_or(protocol::STATUS_ESRCH)?;
        let target = self
            .sessions
            .get(&target_id)
            .copied()
            .ok_or(protocol::STATUS_ESRCH)?;
        let same_credentials = caller.real_uid == target.real_uid
            && caller.real_uid == target.effective_uid
            && caller.real_uid == target.saved_uid
            && caller.real_gid == target.real_gid
            && caller.real_gid == target.effective_gid
            && caller.real_gid == target.saved_gid;
        if target_id != caller_id && caller.effective_uid != 0 && !same_credentials {
            return Err(protocol::STATUS_EPERM);
        }

        let key = (target_id, request.resource);
        let previous = self
            .resource_limits
            .get(&key)
            .copied()
            .unwrap_or_default();
        if request.flags & protocol::RESOURCE_LIMIT_SET != 0 {
            if request.limit.soft > request.limit.hard {
                return Err(STATUS_EINVAL);
            }
            if request.limit.hard > previous.hard && caller.effective_uid != 0 {
                return Err(protocol::STATUS_EPERM);
            }
            self.resource_limits.insert(key, request.limit);
        }

        let mut output = vec![0; protocol::RESOURCE_LIMIT_LEN];
        protocol::encode_resource_limit(previous, &mut output).map_err(|_| STATUS_EINVAL)?;
        Ok(output)
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
                if !self.processes.contains_key(&peer.process_id) {
                    return status_response(header.request_id, STATUS_EINVAL);
                }
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
            protocol::OP_PROCESS_INFO if header.flags == 0 => {
                self.process_info_payload(peer.process_id, payload)
            }
            protocol::OP_SET_PROCESS_GROUP if header.flags == 0 => self
                .set_process_group(peer.process_id, payload)
                .map(|_| Vec::new()),
            protocol::OP_CREATE_SESSION if header.flags == 0 && payload.is_empty() => self
                .create_session(peer.process_id)
                .and_then(encode_process_info_payload),
            protocol::OP_RESOURCE_LIMIT if header.flags == 0 => {
                self.resource_limit_payload(peer.process_id, payload)
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
            | protocol::OP_PROCESS_FORKED
            | protocol::OP_WAIT_CHILD
            | protocol::OP_PROCESS_INFO
            | protocol::OP_SET_PROCESS_GROUP
            | protocol::OP_CREATE_SESSION
            | protocol::OP_RESOURCE_LIMIT
            | protocol::OP_FTRUNCATE
            | protocol::OP_FSYNC
            | protocol::OP_FGETFL
            | protocol::OP_FSETFL
            | protocol::OP_MKDIR_AT
            | protocol::OP_UNLINK_AT
            | protocol::OP_RENAME_AT
            | protocol::OP_TRUNCATE_AT
            | protocol::OP_SYMLINK_AT
            | protocol::OP_READLINK_AT
            | protocol::OP_CHMOD_AT
            | protocol::OP_CHOWN_AT
            | protocol::OP_FCHMOD
            | protocol::OP_FCHOWN => Err(STATUS_EINVAL),
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
                | protocol::OP_FGETFL
                | protocol::OP_FSETFL
                | protocol::OP_MKDIR_AT
                | protocol::OP_UNLINK_AT
                | protocol::OP_RENAME_AT
                | protocol::OP_TRUNCATE_AT
                | protocol::OP_SYMLINK_AT
                | protocol::OP_READLINK_AT
                | protocol::OP_CHMOD_AT
                | protocol::OP_CHOWN_AT
                | protocol::OP_FCHMOD
                | protocol::OP_FCHOWN
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
                | protocol::OP_MKDIR_AT
                | protocol::OP_UNLINK_AT
                | protocol::OP_RENAME_AT
                | protocol::OP_TRUNCATE_AT
                | protocol::OP_SYMLINK_AT
                | protocol::OP_READLINK_AT
                | protocol::OP_CHMOD_AT
                | protocol::OP_CHOWN_AT
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
            protocol::OP_FCHMOD => {
                if handles.len() != 1 || payload.len() != 4 {
                    return object_error(header.request_id, STATUS_EINVAL);
                }
                let session = match self.sessions.get(&peer.process_id) {
                    Some(session) => *session,
                    None => return object_error(header.request_id, protocol::STATUS_ESRCH),
                };
                let mode = u32::from_le_bytes(payload.try_into().unwrap());
                if mode & !0o7777 != 0 {
                    return object_error(header.request_id, STATUS_EINVAL);
                }
                match filesystem.fchmod(
                    handles[0],
                    mode,
                    session.effective_uid,
                    session.effective_gid,
                ) {
                    Ok(()) => object_error(header.request_id, protocol::STATUS_OK),
                    Err(status) => object_error(header.request_id, status),
                }
            }
            protocol::OP_FCHOWN => {
                if handles.len() != 1 {
                    return object_error(header.request_id, STATUS_EINVAL);
                }
                let session = match self.sessions.get(&peer.process_id) {
                    Some(session) => *session,
                    None => return object_error(header.request_id, protocol::STATUS_ESRCH),
                };
                let (uid, gid) = match protocol::decode_file_owner(payload) {
                    Ok(owner) => owner,
                    Err(_) => return object_error(header.request_id, STATUS_EINVAL),
                };
                match filesystem.fchown(
                    handles[0],
                    uid,
                    gid,
                    session.effective_uid,
                    session.effective_gid,
                ) {
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
            protocol::OP_FGETFL => {
                if !payload.is_empty() || handles.len() != 1 {
                    return object_error(header.request_id, STATUS_EINVAL);
                }
                if !self.sessions.contains_key(&peer.process_id) {
                    return object_error(header.request_id, protocol::STATUS_ESRCH);
                }
                match filesystem.get_status_flags(handles[0]) {
                    Ok(flags) => {
                        let mut payload = vec![0; protocol::FILE_FLAGS_PAYLOAD_LEN];
                        if protocol::encode_file_flags(flags, &mut payload).is_err() {
                            return object_error(header.request_id, STATUS_EINVAL);
                        }
                        object_payload(header.request_id, payload)
                    }
                    Err(status) => object_error(header.request_id, status),
                }
            }
            protocol::OP_FSETFL => {
                if handles.len() != 1 {
                    return object_error(header.request_id, STATUS_EINVAL);
                }
                if !self.sessions.contains_key(&peer.process_id) {
                    return object_error(header.request_id, protocol::STATUS_ESRCH);
                }
                let flags = match protocol::decode_file_flags(payload) {
                    Ok(flags) if flags & !protocol::MUTABLE_STATUS_FLAGS == 0 => flags,
                    _ => return object_error(header.request_id, STATUS_EINVAL),
                };
                match filesystem.set_status_flags(handles[0], flags) {
                    Ok(()) => object_error(header.request_id, protocol::STATUS_OK),
                    Err(status) => object_error(header.request_id, status),
                }
            }
            protocol::OP_MKDIR_AT => {
                let prepared = match self.prepare_mkdir_at(peer, payload, handles.len()) {
                    Ok(prepared) => prepared,
                    Err(status) => return object_error(header.request_id, status),
                };
                let paths = match self.path_objects(peer.process_id, prepared.base, handles) {
                    Ok(paths) => paths,
                    Err(status) => return object_error(header.request_id, status),
                };
                match filesystem.mkdir_at(&prepared, paths) {
                    Ok(()) => object_error(header.request_id, protocol::STATUS_OK),
                    Err(status) => object_error(header.request_id, status),
                }
            }
            protocol::OP_UNLINK_AT => {
                let prepared = match self.prepare_unlink_at(peer, payload, handles.len()) {
                    Ok(prepared) => prepared,
                    Err(status) => return object_error(header.request_id, status),
                };
                let paths = match self.path_objects(peer.process_id, prepared.base, handles) {
                    Ok(paths) => paths,
                    Err(status) => return object_error(header.request_id, status),
                };
                match filesystem.unlink_at(&prepared, paths) {
                    Ok(()) => object_error(header.request_id, protocol::STATUS_OK),
                    Err(status) => object_error(header.request_id, status),
                }
            }
            protocol::OP_RENAME_AT => {
                let prepared = match self.prepare_rename_at(peer, payload, handles.len()) {
                    Ok(prepared) => prepared,
                    Err(status) => return object_error(header.request_id, status),
                };
                let paths = match self.rename_path_objects(
                    peer.process_id,
                    prepared.old_base,
                    prepared.new_base,
                    handles,
                ) {
                    Ok(paths) => paths,
                    Err(status) => return object_error(header.request_id, status),
                };
                match filesystem.rename_at(&prepared, paths) {
                    Ok(()) => object_error(header.request_id, protocol::STATUS_OK),
                    Err(status) => object_error(header.request_id, status),
                }
            }
            protocol::OP_TRUNCATE_AT => {
                let prepared = match self.prepare_truncate_at(peer, payload, handles.len()) {
                    Ok(prepared) => prepared,
                    Err(status) => return object_error(header.request_id, status),
                };
                let paths = match self.path_objects(peer.process_id, prepared.base, handles) {
                    Ok(paths) => paths,
                    Err(status) => return object_error(header.request_id, status),
                };
                match filesystem.truncate_at(&prepared, paths) {
                    Ok(()) => object_error(header.request_id, protocol::STATUS_OK),
                    Err(status) => object_error(header.request_id, status),
                }
            }
            protocol::OP_SYMLINK_AT => {
                let prepared = match self.prepare_symlink_at(peer, payload, handles.len()) {
                    Ok(prepared) => prepared,
                    Err(status) => return object_error(header.request_id, status),
                };
                let paths = match self.path_objects(peer.process_id, prepared.base, handles) {
                    Ok(paths) => paths,
                    Err(status) => return object_error(header.request_id, status),
                };
                match filesystem.symlink_at(&prepared, paths) {
                    Ok(()) => object_error(header.request_id, protocol::STATUS_OK),
                    Err(status) => object_error(header.request_id, status),
                }
            }
            protocol::OP_READLINK_AT => {
                let prepared = match self.prepare_readlink_at(peer, payload, handles.len()) {
                    Ok(prepared) => prepared,
                    Err(status) => return object_error(header.request_id, status),
                };
                let paths = match self.path_objects(peer.process_id, prepared.base, handles) {
                    Ok(paths) => paths,
                    Err(status) => return object_error(header.request_id, status),
                };
                match filesystem.readlink_at(&prepared, paths) {
                    Ok(target) => object_payload(header.request_id, target),
                    Err(status) => object_error(header.request_id, status),
                }
            }
            protocol::OP_CHMOD_AT => {
                let prepared = match self.prepare_chmod_at(peer, payload, handles.len()) {
                    Ok(prepared) => prepared,
                    Err(status) => return object_error(header.request_id, status),
                };
                let paths = match self.path_objects(peer.process_id, prepared.base, handles) {
                    Ok(paths) => paths,
                    Err(status) => return object_error(header.request_id, status),
                };
                match filesystem.chmod_at(&prepared, paths) {
                    Ok(()) => object_error(header.request_id, protocol::STATUS_OK),
                    Err(status) => object_error(header.request_id, status),
                }
            }
            protocol::OP_CHOWN_AT => {
                let prepared = match self.prepare_chown_at(peer, payload, handles.len()) {
                    Ok(prepared) => prepared,
                    Err(status) => return object_error(header.request_id, status),
                };
                let paths = match self.path_objects(peer.process_id, prepared.base, handles) {
                    Ok(paths) => paths,
                    Err(status) => return object_error(header.request_id, status),
                };
                match filesystem.chown_at(&prepared, paths) {
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

    fn rename_path_objects(
        &self,
        process_id: u64,
        old_base: protocol::OpenBase,
        new_base: protocol::OpenBase,
        handles: &[AttachedObject<H>],
    ) -> Result<RenamePathObjects<H>, i32> {
        let directories = self
            .directories
            .get(&process_id)
            .ok_or(protocol::STATUS_ESRCH)?;
        let mut next = 0usize;
        let mut resolve = |base| -> Result<Option<AttachedObject<H>>, i32> {
            match base {
                protocol::OpenBase::ProcessRoot => Ok(None),
                protocol::OpenBase::ProcessCwd => Ok(Some(directories.cwd)),
                protocol::OpenBase::AttachedDirectory => {
                    let object = handles.get(next).copied().ok_or(STATUS_EINVAL)?;
                    next += 1;
                    Ok(Some(object))
                }
            }
        };
        let old_base = resolve(old_base)?;
        let new_base = resolve(new_base)?;
        if next != handles.len() {
            return Err(STATUS_EINVAL);
        }
        Ok(RenamePathObjects {
            root: directories.root,
            old_base,
            new_base,
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

    pub fn prepare_mkdir_at(
        &self,
        peer: PeerIdentity,
        payload: &[u8],
        attached_handles: usize,
    ) -> Result<PreparedMkdir, i32> {
        let session = self
            .sessions
            .get(&peer.process_id)
            .ok_or(protocol::STATUS_ESRCH)?;
        let request = protocol::decode_open_at(payload).map_err(|_| STATUS_EINVAL)?;
        let expected_handles = usize::from(request.base == protocol::OpenBase::AttachedDirectory);
        if attached_handles != expected_handles || request.options != 0 {
            return Err(STATUS_EINVAL);
        }
        Ok(PreparedMkdir {
            base: request.base,
            mode: (request.mode & 0o7777) & !(session.umask & 0o777),
            path: request.path.to_owned(),
            effective_uid: session.effective_uid,
            effective_gid: session.effective_gid,
        })
    }

    pub fn prepare_unlink_at(
        &self,
        peer: PeerIdentity,
        payload: &[u8],
        attached_handles: usize,
    ) -> Result<PreparedUnlink, i32> {
        let session = self
            .sessions
            .get(&peer.process_id)
            .ok_or(protocol::STATUS_ESRCH)?;
        let request = protocol::decode_stat_at(payload).map_err(|_| STATUS_EINVAL)?;
        let expected_handles = usize::from(request.base == protocol::OpenBase::AttachedDirectory);
        if attached_handles != expected_handles || request.flags & !protocol::UNLINK_FLAGS_ALL != 0 {
            return Err(STATUS_EINVAL);
        }
        Ok(PreparedUnlink {
            base: request.base,
            flags: request.flags,
            path: request.path.to_owned(),
            effective_uid: session.effective_uid,
            effective_gid: session.effective_gid,
        })
    }

    pub fn prepare_rename_at(
        &self,
        peer: PeerIdentity,
        payload: &[u8],
        attached_handles: usize,
    ) -> Result<PreparedRename, i32> {
        let session = self
            .sessions
            .get(&peer.process_id)
            .ok_or(protocol::STATUS_ESRCH)?;
        let request = protocol::decode_rename_at(payload).map_err(|_| STATUS_EINVAL)?;
        let expected_handles = usize::from(request.old_base == protocol::OpenBase::AttachedDirectory)
            + usize::from(request.new_base == protocol::OpenBase::AttachedDirectory);
        if attached_handles != expected_handles {
            return Err(STATUS_EINVAL);
        }
        Ok(PreparedRename {
            old_base: request.old_base,
            new_base: request.new_base,
            old_path: request.old_path.to_owned(),
            new_path: request.new_path.to_owned(),
            effective_uid: session.effective_uid,
            effective_gid: session.effective_gid,
        })
    }

    pub fn prepare_truncate_at(
        &self,
        peer: PeerIdentity,
        payload: &[u8],
        attached_handles: usize,
    ) -> Result<PreparedTruncate, i32> {
        let session = self
            .sessions
            .get(&peer.process_id)
            .ok_or(protocol::STATUS_ESRCH)?;
        let request = protocol::decode_truncate_at(payload).map_err(|_| STATUS_EINVAL)?;
        let expected_handles = usize::from(request.base == protocol::OpenBase::AttachedDirectory);
        if attached_handles != expected_handles {
            return Err(STATUS_EINVAL);
        }
        Ok(PreparedTruncate {
            base: request.base,
            path: request.path.to_owned(),
            length: request.length,
            effective_uid: session.effective_uid,
            effective_gid: session.effective_gid,
        })
    }

    pub fn prepare_symlink_at(
        &self,
        peer: PeerIdentity,
        payload: &[u8],
        attached_handles: usize,
    ) -> Result<PreparedSymlink, i32> {
        let session = self
            .sessions
            .get(&peer.process_id)
            .ok_or(protocol::STATUS_ESRCH)?;
        let request = protocol::decode_symlink_at(payload).map_err(|_| STATUS_EINVAL)?;
        let expected_handles = usize::from(request.base == protocol::OpenBase::AttachedDirectory);
        if attached_handles != expected_handles {
            return Err(STATUS_EINVAL);
        }
        Ok(PreparedSymlink {
            base: request.base,
            target: request.target.to_owned(),
            link_path: request.link_path.to_owned(),
            effective_uid: session.effective_uid,
            effective_gid: session.effective_gid,
        })
    }

    pub fn prepare_readlink_at(
        &self,
        peer: PeerIdentity,
        payload: &[u8],
        attached_handles: usize,
    ) -> Result<PreparedReadlink, i32> {
        let session = self
            .sessions
            .get(&peer.process_id)
            .ok_or(protocol::STATUS_ESRCH)?;
        let request = protocol::decode_stat_at(payload).map_err(|_| STATUS_EINVAL)?;
        let expected_handles = usize::from(request.base == protocol::OpenBase::AttachedDirectory);
        if attached_handles != expected_handles || request.flags != 0 {
            return Err(STATUS_EINVAL);
        }
        Ok(PreparedReadlink {
            base: request.base,
            path: request.path.to_owned(),
            effective_uid: session.effective_uid,
            effective_gid: session.effective_gid,
        })
    }

    pub fn prepare_chmod_at(
        &self,
        peer: PeerIdentity,
        payload: &[u8],
        attached_handles: usize,
    ) -> Result<PreparedChmod, i32> {
        let session = self
            .sessions
            .get(&peer.process_id)
            .ok_or(protocol::STATUS_ESRCH)?;
        let request = protocol::decode_open_at(payload).map_err(|_| STATUS_EINVAL)?;
        let expected_handles = usize::from(request.base == protocol::OpenBase::AttachedDirectory);
        if attached_handles != expected_handles || request.options != 0 || request.mode & !0o7777 != 0 {
            return Err(STATUS_EINVAL);
        }
        Ok(PreparedChmod {
            base: request.base,
            path: request.path.to_owned(),
            mode: request.mode,
            effective_uid: session.effective_uid,
            effective_gid: session.effective_gid,
        })
    }

    pub fn prepare_chown_at(
        &self,
        peer: PeerIdentity,
        payload: &[u8],
        attached_handles: usize,
    ) -> Result<PreparedChown, i32> {
        let session = self
            .sessions
            .get(&peer.process_id)
            .ok_or(protocol::STATUS_ESRCH)?;
        let request = protocol::decode_chown_at(payload).map_err(|_| STATUS_EINVAL)?;
        let expected_handles = usize::from(request.base == protocol::OpenBase::AttachedDirectory);
        if attached_handles != expected_handles {
            return Err(STATUS_EINVAL);
        }
        Ok(PreparedChown {
            base: request.base,
            path: request.path.to_owned(),
            flags: request.flags,
            uid: request.uid,
            gid: request.gid,
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

fn encode_process_info_payload(info: protocol::ProcessInfo) -> Result<Vec<u8>, i32> {
    let mut payload = vec![0u8; protocol::PROCESS_INFO_LEN];
    protocol::encode_process_info(info, &mut payload).map_err(|_| STATUS_EINVAL)?;
    Ok(payload)
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
