use std::collections::HashMap;
use std::time::Duration;

use crate::namespace::{Namespace, Node};
use crate::open_table::{DeviceOpen, OpenTable};
use crate::path_walk;
use ext4plus::dir::Dir;
use ext4plus::error::Ext4Error;
use ext4plus::file::File;
use ext4plus::inode::{Inode, InodeCreationOptions, InodeFlags, InodeMode};
use ext4plus::path::PathBuf;
use ext4plus::{DirEntryName, Ext4, FileType, FollowSymlinks, Metadata};
use mochios_filesystem_protocol as protocol;
type Resolution = path_walk::Resolution<Inode>;

#[path = "device_operations.rs"]
mod device_operations;
#[path = "removed_directories.rs"]
mod removed_directories;
#[path = "canonical_path.rs"]
mod canonical_path;
#[path = "inode_time.rs"]
mod inode_time;
#[path = "timestamp_operations.rs"]
mod timestamp_operations;

const EIO: i32 = 5;
const EXDEV: i32 = 18;
const EPERM: i32 = 1;
const ENOENT: i32 = 2;
const EBADF: i32 = 9;
const ENOMEM: i32 = 12;
const EBUSY: i32 = 16;
const EACCES: i32 = 13;
const EEXIST: i32 = 17;
const EINVAL: i32 = 22;
const ENOSPC: i32 = 28;
const EROFS: i32 = 30;
const ENAMETOOLONG: i32 = 36;
const EISDIR: i32 = 21;
const ENOTDIR: i32 = 20;
const ENOSYS: i32 = 38;
const ENOTSUP: i32 = 95;
const ENOTEMPTY: i32 = 39;
const EFBIG: i32 = 27;
const ELOOP: i32 = 40;

pub struct Response {
    pub header: protocol::Header,
    pub payload: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PathAnchors {
    pub root_open_id: Option<u64>,
    pub base_open_id: Option<u64>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RenameAnchors {
    pub root_open_id: Option<u64>,
    pub old_base_open_id: Option<u64>,
    pub new_base_open_id: Option<u64>,
}

pub struct FilesystemService {
    fs: Ext4,
    clock: crate::clock::Clock,
    namespace: Option<Namespace>,
    nodes: HashMap<u64, String>,
    node_ids: HashMap<String, u64>,
    opens: OpenTable,
    orphans: HashMap<u64, Orphan>,
    removed_directories: HashMap<u64, removed_directories::RetainedDirectory>,
    next_open_id: u64,
    memory_updates: Option<Box<dyn crate::memory_updates::MemoryUpdates>>,
    memory_admission: Option<crate::memory_updates::AdmissionScope>,
}

pub(crate) struct OpenFile {
    node_id: u64,
    volume: u32,
    filesystem: Ext4,
    // Stable while any description retains this inode, but never reused after
    // the last close. An inode number alone can alias a recycled cache key.
    memory_object_id: u64,
    /// The opened inode is the identity of this open file description.
    ///
    /// Keep it independently of the path cache: an open directory or file
    /// must remain usable after its directory entry is renamed or removed.
    inode: Inode,
    file: Option<File>,
    offset: u64,
    status_flags: u32,
    cursor_records: bool,
}

#[derive(Clone)]
struct Orphan {
    parent: Inode,
    name: String,
}

impl FilesystemService {
    pub fn new(fs: Ext4) -> Self {
        Self::new_with_clock(fs, crate::clock::realtime_timestamp)
    }

    /// The embedding owner selects the trusted clock before serving requests.
    /// No IPC field can replace it or confer clock-read authority.
    pub fn new_with_clock(fs: Ext4, clock: crate::clock::Clock) -> Self {
        let mut nodes = HashMap::new();
        let mut node_ids = HashMap::new();
        // ext4 reserves inode 2 for the filesystem root.
        nodes.insert(2, "/".to_owned());
        node_ids.insert("/".to_owned(), 2);
        Self {
            fs,
            clock,
            namespace: None,
            nodes,
            node_ids,
            opens: OpenTable::default(),
            orphans: HashMap::new(),
            removed_directories: HashMap::new(),
            next_open_id: 1,
            memory_updates: None,
            memory_admission: None,
        }
    }

    /// Install the provider owner's update mechanism before opening resources.
    /// Without it, mutations affecting existing opens fail before storage I/O.
    /// Standalone image users may explicitly install their own coordinator.
    pub fn configure_memory_updates(
        &mut self,
        updates: Box<dyn crate::memory_updates::MemoryUpdates>,
    ) -> Result<(), i32> {
        if self.next_open_id != 1 {
            return Err(EBUSY);
        }
        self.memory_updates = Some(updates);
        Ok(())
    }

    fn with_memory_admission<T>(
        &mut self,
        incoming: Option<mochi_user_platform::handle::Handle>,
        operation: impl FnOnce(&mut Self) -> Result<T, i32>,
    ) -> crate::memory_updates::MutationResult<T> {
        use crate::memory_updates::{AdmissionScope, MutationResult};
        if self.memory_admission.is_some() {
            return MutationResult::Complete(Err(EBUSY));
        }
        self.memory_admission = Some(AdmissionScope {
            incoming,
            waiting: None,
        });
        let result = operation(self);
        // Always clear request-local state, including permission and storage
        // failures. A subsequent request must never inherit another's ticket.
        let waiting = self.memory_admission.take().and_then(|scope| scope.waiting);
        match (result, waiting) {
            (Err(protocol::ERROR_MEMORY_ADMISSION_BUSY), Some(ticket)) => {
                MutationResult::Wait(ticket)
            }
            (Err(protocol::ERROR_MEMORY_ADMISSION_BUSY), None) => {
                MutationResult::Complete(Err(EIO))
            }
            (result, None) => MutationResult::Complete(result),
            // A queued response cannot accompany successful or uncertain I/O.
            (_, Some(_)) => MutationResult::Complete(Err(EIO)),
        }
    }

    pub fn open_at_admitted(
        &mut self,
        request: protocol::Header,
        payload: &[u8],
        anchors: PathAnchors,
        credentials: protocol::Credentials,
        incoming: Option<mochi_user_platform::handle::Handle>,
    ) -> crate::memory_updates::MutationResult<Response> {
        self.with_memory_admission(incoming, |service| {
            service.open_at(request, payload, anchors, credentials)
        })
    }

    pub fn truncate_at_admitted(
        &mut self,
        request: protocol::Header,
        payload: &[u8],
        anchors: PathAnchors,
        credentials: protocol::Credentials,
        incoming: Option<mochi_user_platform::handle::Handle>,
    ) -> crate::memory_updates::MutationResult<Response> {
        self.with_memory_admission(incoming, |service| {
            service.truncate_at(request, payload, anchors, credentials)
        })
    }

    pub fn truncate_handle_admitted(
        &mut self,
        request: protocol::Header,
        open_id: u64,
        incoming: Option<mochi_user_platform::handle::Handle>,
    ) -> crate::memory_updates::MutationResult<Response> {
        self.with_memory_admission(incoming, |service| {
            service.truncate_handle(request, open_id)
        })
    }

    fn prepare_memory_update(
        &mut self,
        identity: u64,
        old_length: u64,
        length: u64,
    ) -> Result<Box<dyn crate::memory_updates::Update>, i32> {
        use crate::memory_updates::Preparation;
        let backend = self.memory_updates.as_ref().ok_or(ENOTSUP)?;
        if let Some(scope) = self.memory_admission.as_mut() {
            match backend.prepare_admitted(identity, old_length, length, scope.incoming)? {
                Preparation::Ready(update) => Ok(update),
                Preparation::Wait(ticket) => {
                    scope.waiting = Some(ticket);
                    Err(protocol::ERROR_MEMORY_ADMISSION_BUSY)
                }
            }
        } else {
            backend
                .prepare(identity, old_length, length)
                .map_err(crate::memory_updates::admission_error)
        }
    }

    /// Service-owned mount configuration; callers must already hold the volume.
    /// Startup wiring is kept separate from the legacy mount-registration IPC.
    pub fn mount_volume(&mut self, at: &[u8], filesystem: Ext4) -> Result<(), i32> {
        if self.namespace.is_none() {
            self.namespace = Some(Namespace::new(self.fs.clone())?);
        }
        let namespace = self.namespace.as_mut().ok_or(EIO)?;
        let root = namespace.root();
        let at = match namespace.resolve(
            root.clone(),
            root,
            at,
            true,
            path_walk::Credentials {
                uid: 0,
                gid: 0,
                groups: &[],
            },
        )? {
            path_walk::Resolution::Found { inode, .. } => inode,
            path_walk::Resolution::Missing { .. } => return Err(ENOENT),
        };
        namespace.mount(at, filesystem)?;
        Ok(())
    }

    /// Attach a source directory without creating a mountpoint on the disk.
    /// This is service-owned configuration, not an untrusted IPC mount request.
    pub fn mount_named_volume(
        &mut self,
        parent: &[u8],
        name: &[u8],
        filesystem: Ext4,
        source: &[u8],
    ) -> Result<(), i32> {
        if self.namespace.is_none() {
            self.namespace = Some(Namespace::new(self.fs.clone())?);
        }
        let namespace = self.namespace.as_mut().ok_or(EIO)?;
        let root = namespace.root();
        let parent = match namespace.resolve(
            root.clone(),
            root,
            parent,
            true,
            path_walk::Credentials {
                uid: 0,
                gid: 0,
                groups: &[],
            },
        )? {
            path_walk::Resolution::Found { inode, .. } => inode,
            path_walk::Resolution::Missing { .. } => return Err(ENOENT),
        };
        namespace.mount_named(parent, name, filesystem, source)?;
        Ok(())
    }

    pub fn handle(&mut self, request: protocol::Header, payload: &[u8]) -> Response {
        let result = match request.opcode {
            protocol::OP_MOUNT => self.mount(request),
            protocol::OP_LOOKUP => self.lookup(request, payload),
            protocol::OP_OPEN => self.open(request),
            protocol::OP_CLOSE => self.close(request),
            protocol::OP_READ => self.read(request),
            protocol::OP_WRITE => self.write(request, payload),
            protocol::OP_STAT => self.stat(request),
            protocol::OP_READDIR => self.read_dir(request),
            protocol::OP_CREATE => self.create(request, payload),
            protocol::OP_UNLINK => self.unlink(request, payload),
            protocol::OP_RENAME => self.rename(request, payload),
            protocol::OP_SYMLINK => self.symlink(request, payload),
            protocol::OP_TRUNCATE => self.truncate(request),
            protocol::OP_READLINK => self.read_link(request),
            protocol::OP_SYNC => Ok(self.success(request)),
            protocol::OP_SETATTR => self.set_attr(request, payload),
            protocol::OP_OPEN_AT
            | protocol::OP_STAT_AT
            | protocol::OP_STAT_HANDLE
            | protocol::OP_ACCESS_AT
            | protocol::OP_TRUNCATE_HANDLE
            | protocol::OP_SYNC_HANDLE
            | protocol::OP_GET_FLAGS_HANDLE
            | protocol::OP_SET_FLAGS_HANDLE
            | protocol::OP_UPDATE_FLAGS_HANDLE
            | protocol::OP_MKDIR_AT
            | protocol::OP_UNLINK_AT
            | protocol::OP_RENAME_AT
            | protocol::OP_LINK_AT
            | protocol::OP_TRUNCATE_AT
            | protocol::OP_SYMLINK_AT
            | protocol::OP_READLINK_AT
            | protocol::OP_CHMOD_AT
            | protocol::OP_CHOWN_AT
            | protocol::OP_CHMOD_HANDLE
            | protocol::OP_CHOWN_HANDLE
            | protocol::OP_SET_TIMES_AT
            | protocol::OP_SET_TIMES_HANDLE => Err(EINVAL),
            _ => Err(ENOSYS),
        };
        result.unwrap_or_else(|errno| self.error(request, errno))
    }

    fn mount(&self, request: protocol::Header) -> Result<Response, i32> {
        let metadata = self.fs.metadata("/").map_err(errno)?;
        Ok(self.metadata_response(request, 2, metadata))
    }

    fn lookup(&mut self, request: protocol::Header, payload: &[u8]) -> Result<Response, i32> {
        let path = decode_path(payload)?;
        if request.flags & !protocol::LOOKUP_FOLLOW_SYMLINKS != 0 {
            return Err(EINVAL);
        }
        let metadata = if request.flags & protocol::LOOKUP_FOLLOW_SYMLINKS != 0 {
            self.fs.metadata(path)
        } else {
            self.fs.symlink_metadata(path)
        }
        .map_err(errno)?;
        let follow = if request.flags & protocol::LOOKUP_FOLLOW_SYMLINKS != 0 {
            FollowSymlinks::All
        } else {
            FollowSymlinks::ExcludeFinalComponent
        };
        let node_id = self.remember_node(path, follow)?;
        Ok(self.metadata_response(request, node_id, metadata))
    }

    fn open(&mut self, request: protocol::Header) -> Result<Response, i32> {
        let path = self.nodes.get(&request.node_id).ok_or(ENOENT)?;
        let file = self.fs.open(path.as_str()).map_err(errno)?;
        let inode = file.inode().clone();
        let open_id = self.next_open_id;
        self.next_open_id = self.next_open_id.checked_add(1).ok_or(EIO)?;
        let memory_object_id = self.memory_identity_for(request.node_id, open_id);
        self.opens.insert(
            open_id,
            OpenFile {
                node_id: request.node_id,
                volume: 0,
                filesystem: self.fs.clone(),
                memory_object_id,
                inode,
                file: Some(file),
                offset: 0,
                status_flags: 0,
                cursor_records: false,
            },
        );
        let mut response = self.success(request);
        response.header.open_id = open_id;
        Ok(response)
    }

    /// Resolves, optionally creates, validates and opens a path as one
    /// serialized filesystem operation.
    pub fn open_at(
        &mut self,
        request: protocol::Header,
        payload: &[u8],
        anchors: PathAnchors,
        credentials: protocol::Credentials,
    ) -> Result<Response, i32> {
        if request.flags & !protocol::OPEN_AT_FLAGS_ALL != 0 {
            return Err(EINVAL);
        }
        let root_attached = request.flags & protocol::OPEN_AT_ROOT_ATTACHED != 0;
        let base_attached = request.flags & protocol::OPEN_AT_BASE_ATTACHED != 0;
        if root_attached != anchors.root_open_id.is_some()
            || base_attached != anchors.base_open_id.is_some()
        {
            return Err(EINVAL);
        }
        let access = request.flags & (protocol::OPEN_AT_READ | protocol::OPEN_AT_WRITE);
        let search = request.flags & protocol::OPEN_AT_SEARCH != 0;
        if access == 0 && !search
            || search
                && (access != 0
                    || request.flags & protocol::OPEN_AT_DIRECTORY == 0
                    || request.flags
                        & (protocol::OPEN_AT_CREATE
                            | protocol::OPEN_AT_EXCLUSIVE
                            | protocol::OPEN_AT_TRUNCATE
                            | protocol::OPEN_AT_APPEND)
                        != 0)
            || request.flags & protocol::OPEN_AT_EXCLUSIVE != 0
                && request.flags & protocol::OPEN_AT_CREATE == 0
            || request.flags & (protocol::OPEN_AT_TRUNCATE | protocol::OPEN_AT_APPEND) != 0
                && request.flags & protocol::OPEN_AT_WRITE == 0
        {
            return Err(EINVAL);
        }
        let uid = credentials.effective_uid;
        let gid = credentials.effective_gid;
        let groups = credentials.supplementary_groups();
        let exclusive_create = request.flags
            & (protocol::OPEN_AT_CREATE | protocol::OPEN_AT_EXCLUSIVE)
            == (protocol::OPEN_AT_CREATE | protocol::OPEN_AT_EXCLUSIVE);
        let follow = if request.flags & protocol::OPEN_AT_NOFOLLOW != 0 || exclusive_create {
            FollowSymlinks::ExcludeFinalComponent
        } else {
            FollowSymlinks::All
        };
        if let Some(resolution) =
            self.resolve_namespace_path(payload, anchors, follow, uid, gid, groups)?
        {
            let node = match &resolution {
                path_walk::Resolution::Found { inode, .. } => inode,
                path_walk::Resolution::Missing { parent, .. } => parent,
            };
            if node.device_node().is_some() {
                return self.open_device_at(request, resolution, credentials);
            }
        }
        let (resolution, filesystem, volume) =
            self.resolve_open_path(payload, anchors, follow, uid, gid, groups)?;
        let (mut inode, created) = match resolution {
            Resolution::Found { inode, .. } => {
                if request.flags & protocol::OPEN_AT_CREATE != 0
                    && request.flags & protocol::OPEN_AT_EXCLUSIVE != 0
                {
                    return Err(EEXIST);
                }
                (inode, false)
            }
            Resolution::Missing { parent, name }
                if request.flags & protocol::OPEN_AT_CREATE != 0
                    && request.flags & protocol::OPEN_AT_DIRECTORY == 0
                    && payload.last() != Some(&b'/') =>
            {
                (
                    self.create_regular_at(
                        &filesystem,
                        parent,
                        &name,
                        request.mode,
                        uid,
                        gid,
                        groups,
                    )?,
                    true,
                )
            }
            Resolution::Missing { .. } => return Err(ENOENT),
        };
        if request.flags & protocol::OPEN_AT_NOFOLLOW != 0 && inode.file_type().is_symlink() {
            return Err(ELOOP);
        }
        let metadata = inode.metadata();
        let kind = metadata.file_type();
        if request.flags & protocol::OPEN_AT_DIRECTORY != 0 && !kind.is_dir() {
            return Err(ENOTDIR);
        }
        if kind.is_dir() && request.flags & protocol::OPEN_AT_WRITE != 0 {
            return Err(EISDIR);
        }
        let requested_access = if search {
            protocol::ACCESS_AT_EXECUTE
        } else {
            (u32::from(request.flags & protocol::OPEN_AT_READ != 0) * protocol::ACCESS_AT_READ)
                | (u32::from(request.flags & protocol::OPEN_AT_WRITE != 0)
                    * protocol::ACCESS_AT_WRITE)
        };
        if !created
            && !permission_allows(
                metadata.mode(),
                node_type(metadata.file_type()),
                metadata.uid(),
                metadata.gid(),
                uid,
                gid,
                groups,
                requested_access,
            )
        {
            return Err(EACCES);
        }
        let node_id = scoped_node_id(volume, &inode);
        let open_id = self.next_open_id;
        let next_open_id = self.next_open_id.checked_add(1).ok_or(EIO)?;
        self.opens.try_reserve(1).map_err(|_| ENOMEM)?;
        // A newly created file is already empty. In particular, never return
        // a retryable admission status after creating its directory entry.
        if !created && request.flags & protocol::OPEN_AT_TRUNCATE != 0 {
            inode = self.truncate_scoped_inode(inode, filesystem.clone(), node_id, 0, None)?;
        }
        let file = if kind.is_dir() {
            None
        } else {
            Some(File::open_inode(&filesystem, inode.clone()).map_err(errno)?)
        };
        self.next_open_id = next_open_id;
        let memory_object_id = self.memory_identity_for(node_id, open_id);
        self.opens.insert(
            open_id,
            OpenFile {
                node_id,
                volume,
                filesystem,
                memory_object_id,
                inode,
                file,
                offset: 0,
                cursor_records: request.flags & protocol::OPEN_AT_CURSOR_RECORDS != 0,
                status_flags: (if request.flags & protocol::OPEN_AT_APPEND != 0 {
                    protocol::OPEN_STATUS_APPEND
                } else {
                    0
                }) | (if request.flags & protocol::OPEN_AT_NONBLOCK != 0 {
                    protocol::OPEN_STATUS_NONBLOCK
                } else {
                    0
                }),
            },
        );
        let mut response = self.success(request);
        response.header.open_id = open_id;
        response.header.node_id = node_id;
        Ok(response)
    }

    fn create_regular_at(
        &self,
        filesystem: &Ext4,
        parent: Inode,
        name: &[u8],
        mode: u32,
        uid: u32,
        gid: u32,
        groups: &[u32],
    ) -> Result<Inode, i32> {
        let metadata = parent.metadata();
        if !permission_allows(
            metadata.mode(),
            protocol::NODE_TYPE_DIRECTORY,
            metadata.uid(),
            metadata.gid(),
            uid,
            gid,
            groups,
            protocol::ACCESS_AT_WRITE | protocol::ACCESS_AT_EXECUTE,
        ) {
            return Err(EACCES);
        }
        let mut directory = Dir::open_inode(filesystem, parent).map_err(errno)?;
        let name = DirEntryName::try_from(name).map_err(|_| EINVAL)?;
        match directory.get_entry(name) {
            Ok(_) => return Err(EEXIST),
            Err(Ext4Error::NotFound) => {}
            Err(error) => return Err(errno(error)),
        }
        let mut inode = filesystem
            .create_inode(InodeCreationOptions {
                file_type: FileType::Regular,
                mode: InodeMode::from_bits_truncate((mode as u16) & 0x0fff) | InodeMode::S_IFREG,
                uid,
                gid,
                time: Duration::default(),
                flags: InodeFlags::empty(),
            })
            .map_err(errno)?;
        directory.link(name, &mut inode).map_err(errno)?;
        Ok(inode)
    }

    /// Serialized path traversal and exclusive socket-inode creation. Callers
    /// must supply credentials authenticated by their trusted policy boundary;
    /// wire self-reported credentials are not sufficient authority.
    pub fn create_socket_at(
        &mut self,
        request: protocol::Header,
        payload: &[u8],
        anchors: PathAnchors,
        credentials: protocol::Credentials,
    ) -> Result<Response, i32> {
        self.create_socket_at_inner(request, payload, anchors, credentials, false)
    }

    /// Keep an inode description for binding lifetime. The native adapter must
    /// wrap open_id in a metadata-only Provider Handle and release it on failure.
    /// Client FDs never enter this internal description table.
    pub fn create_socket_at_retained(
        &mut self,
        request: protocol::Header,
        payload: &[u8],
        anchors: PathAnchors,
        credentials: protocol::Credentials,
    ) -> Result<Response, i32> {
        self.create_socket_at_inner(request, payload, anchors, credentials, true)
    }

    fn reserve_socket_description(&mut self) -> Result<u64, i32> {
        if self.next_open_id > i64::MAX as u64 {
            return Err(EIO);
        }
        self.opens.try_reserve(1).map_err(|_| 12)?;
        self.next_open_id.checked_add(1).ok_or(EIO)
    }

    /// Resolve, authorize and retain the exact existing inode in one operation.
    /// No pathname is looked up again after obtaining this description.
    pub fn open_socket_at_retained(
        &mut self,
        request: protocol::Header,
        payload: &[u8],
        anchors: PathAnchors,
        credentials: protocol::Credentials,
    ) -> Result<Response, i32> {
        if request.flags & !protocol::SOCKET_AT_FLAGS_ALL != 0
            || (request.flags & protocol::SOCKET_AT_ROOT_ATTACHED != 0)
                != anchors.root_open_id.is_some()
            || (request.flags & protocol::SOCKET_AT_BASE_ATTACHED != 0)
                != anchors.base_open_id.is_some()
        {
            return Err(EINVAL);
        }
        let (resolution, filesystem, volume) = self.resolve_open_path(
            payload,
            anchors,
            FollowSymlinks::All,
            credentials.effective_uid,
            credentials.effective_gid,
            credentials.supplementary_groups(),
        )?;
        let inode = match resolution {
            Resolution::Found { inode, .. } => inode,
            Resolution::Missing { .. } => return Err(ENOENT),
        };
        if !inode.file_type().is_socket() {
            return Err(88);
        }
        let metadata = inode.metadata();
        if !permission_allows(
            metadata.mode(),
            protocol::NODE_TYPE_SOCKET,
            metadata.uid(),
            metadata.gid(),
            credentials.effective_uid,
            credentials.effective_gid,
            credentials.supplementary_groups(),
            protocol::ACCESS_AT_WRITE,
        ) {
            return Err(EACCES);
        }
        let next_open = self.reserve_socket_description()?;
        self.retain_socket_description(request, filesystem, volume, inode, next_open)
    }

    fn retain_socket_description(
        &mut self,
        request: protocol::Header,
        filesystem: Ext4,
        volume: u32,
        inode: Inode,
        next_open: u64,
    ) -> Result<Response, i32> {
        let node_id = scoped_node_id(volume, &inode);
        let mut response = self.node_status_response(request, node_id, inode.metadata());
        if response.header.status != 0 {
            return Err(-response.header.status);
        }
        let open_id = self.next_open_id;
        self.next_open_id = next_open;
        self.opens.insert(
            open_id,
            OpenFile {
                node_id,
                volume,
                filesystem,
                memory_object_id: self.memory_identity_for(node_id, open_id),
                inode,
                file: None,
                offset: 0,
                status_flags: 0,
                cursor_records: false,
            },
        );
        response.header.open_id = open_id;
        response.header.node_id = node_id;
        Ok(response)
    }

    fn create_socket_at_inner(
        &mut self,
        request: protocol::Header,
        payload: &[u8],
        anchors: PathAnchors,
        credentials: protocol::Credentials,
        retain: bool,
    ) -> Result<Response, i32> {
        // Reserve the identity before changing the namespace; a failed identity
        // allocation must not leave a published file without a description.
        let next_open = if retain {
            Some(self.reserve_socket_description()?)
        } else {
            None
        };
        if request.flags & !protocol::SOCKET_AT_FLAGS_ALL != 0
            || (request.flags & protocol::SOCKET_AT_ROOT_ATTACHED != 0)
                != anchors.root_open_id.is_some()
            || (request.flags & protocol::SOCKET_AT_BASE_ATTACHED != 0)
                != anchors.base_open_id.is_some()
        {
            return Err(EINVAL);
        }
        let uid = credentials.effective_uid;
        let gid = credentials.effective_gid;
        let groups = credentials.supplementary_groups();
        let (resolution, filesystem, volume) = self.resolve_open_path(
            payload,
            anchors,
            FollowSymlinks::ExcludeFinalComponent,
            uid,
            gid,
            groups,
        )?;
        let (parent, name) = match resolution {
            Resolution::Found { .. } => return Err(EEXIST),
            Resolution::Missing { parent, name } => (parent, name),
        };
        let metadata = parent.metadata();
        if !permission_allows(
            metadata.mode(),
            protocol::NODE_TYPE_DIRECTORY,
            metadata.uid(),
            metadata.gid(),
            uid,
            gid,
            groups,
            protocol::ACCESS_AT_WRITE | protocol::ACCESS_AT_EXECUTE,
        ) {
            return Err(EACCES);
        }
        let name = DirEntryName::try_from(name.as_slice()).map_err(|_| EINVAL)?;
        let mut parent = Dir::open_inode(&filesystem, parent).map_err(errno)?;
        let mut inode = filesystem
            .create_inode(InodeCreationOptions {
                file_type: FileType::Socket,
                mode: InodeMode::from_bits_truncate((request.mode as u16) & 0o7777)
                    | InodeMode::S_IFSOCK,
                uid,
                gid,
                time: Duration::default(),
                flags: InodeFlags::empty(),
            })
            .map_err(errno)?;
        parent.link(name, &mut inode).map_err(errno)?;
        let node_id = scoped_node_id(volume, &inode);
        if let Some(next_open) = next_open {
            self.retain_socket_description(request, filesystem, volume, inode, next_open)
        } else {
            Ok(self.node_status_response(request, node_id, inode.metadata()))
        }
    }

    pub fn mkdir_at(
        &mut self,
        request: protocol::Header,
        payload: &[u8],
        anchors: PathAnchors,
        credentials: protocol::Credentials,
    ) -> Result<Response, i32> {
        if request.flags & !protocol::MKDIR_AT_FLAGS_ALL != 0 {
            return Err(EINVAL);
        }
        let root_attached = request.flags & protocol::MKDIR_AT_ROOT_ATTACHED != 0;
        let base_attached = request.flags & protocol::MKDIR_AT_BASE_ATTACHED != 0;
        if root_attached != anchors.root_open_id.is_some()
            || base_attached != anchors.base_open_id.is_some()
        {
            return Err(EINVAL);
        }
        let uid = credentials.effective_uid;
        let gid = credentials.effective_gid;
        let groups = credentials.supplementary_groups();
        let (resolution, filesystem, _) = self.resolve_open_path(
            payload,
            anchors,
            FollowSymlinks::ExcludeFinalComponent,
            uid,
            gid,
            groups,
        )?;
        let (parent, name) = match resolution {
            Resolution::Found { .. } => return Err(EEXIST),
            Resolution::Missing { parent, name } => (parent, name),
        };
        let metadata = parent.metadata();
        if !permission_allows(
            metadata.mode(),
            protocol::NODE_TYPE_DIRECTORY,
            metadata.uid(),
            metadata.gid(),
            uid,
            gid,
            groups,
            protocol::ACCESS_AT_WRITE | protocol::ACCESS_AT_EXECUTE,
        ) {
            return Err(EACCES);
        }
        let mut parent = Dir::open_inode(&filesystem, parent).map_err(errno)?;
        let inode = filesystem
            .create_inode(InodeCreationOptions {
                file_type: FileType::Directory,
                mode: InodeMode::from_bits_truncate((request.mode as u16) & 0o7777)
                    | InodeMode::S_IFDIR,
                uid,
                gid,
                time: Duration::default(),
                flags: InodeFlags::empty(),
            })
            .map_err(errno)?;
        let parent_index = parent
            .read_dir()
            .map_err(errno)?
            .find_map(|entry| match entry {
                Ok(entry) if entry.file_name() == "." => Some(Ok(entry.inode)),
                Ok(_) => None,
                Err(error) => Some(Err(errno(error))),
            })
            .ok_or(EIO)??;
        let mut directory = Dir::init(filesystem, inode, parent_index).map_err(errno)?;
        parent
            .link(
                DirEntryName::try_from(name.as_slice()).map_err(|_| EINVAL)?,
                directory.inode_mut(),
            )
            .map_err(errno)?;
        Ok(self.success(request))
    }

    pub fn unlink_at(
        &mut self,
        request: protocol::Header,
        payload: &[u8],
        anchors: PathAnchors,
        credentials: protocol::Credentials,
    ) -> Result<Response, i32> {
        if request.flags & !protocol::UNLINK_AT_FLAGS_ALL != 0 {
            return Err(EINVAL);
        }
        let root_attached = request.flags & protocol::UNLINK_AT_ROOT_ATTACHED != 0;
        let base_attached = request.flags & protocol::UNLINK_AT_BASE_ATTACHED != 0;
        if root_attached != anchors.root_open_id.is_some()
            || base_attached != anchors.base_open_id.is_some()
        {
            return Err(EINVAL);
        }
        let uid = credentials.effective_uid;
        let gid = credentials.effective_gid;
        let groups = credentials.supplementary_groups();
        let (resolution, filesystem, volume) = self.resolve_open_path(
            payload,
            anchors,
            FollowSymlinks::ExcludeFinalComponent,
            uid,
            gid,
            groups,
        )?;
        let (inode, parent, name) = match resolution {
            Resolution::Found {
                inode,
                parent: Some((parent, name)),
            } => (inode, parent, name),
            Resolution::Found { parent: None, .. } => return Err(EINVAL),
            Resolution::Missing { .. } => return Err(ENOENT),
        };
        if self
            .namespace
            .as_ref()
            .is_some_and(|namespace| namespace.is_mount_root(volume, &inode))
        {
            return Err(EBUSY);
        }
        let metadata = parent.metadata();
        if !permission_allows(
            metadata.mode(),
            protocol::NODE_TYPE_DIRECTORY,
            metadata.uid(),
            metadata.gid(),
            uid,
            gid,
            groups,
            protocol::ACCESS_AT_WRITE | protocol::ACCESS_AT_EXECUTE,
        ) {
            return Err(EACCES);
        }
        self.unlink_entry(
            &filesystem,
            volume,
            parent,
            &name,
            inode,
            request.flags & protocol::UNLINK_AT_REMOVE_DIRECTORY != 0,
            None,
        )?;
        Ok(self.success(request))
    }

    pub fn truncate_at(
        &mut self,
        request: protocol::Header,
        payload: &[u8],
        anchors: PathAnchors,
        credentials: protocol::Credentials,
    ) -> Result<Response, i32> {
        if request.flags & !protocol::TRUNCATE_AT_FLAGS_ALL != 0 {
            return Err(EINVAL);
        }
        let root_attached = request.flags & protocol::TRUNCATE_AT_ROOT_ATTACHED != 0;
        let base_attached = request.flags & protocol::TRUNCATE_AT_BASE_ATTACHED != 0;
        if root_attached != anchors.root_open_id.is_some()
            || base_attached != anchors.base_open_id.is_some()
        {
            return Err(EINVAL);
        }
        let uid = credentials.effective_uid;
        let gid = credentials.effective_gid;
        let groups = credentials.supplementary_groups();
        let (inode, filesystem, volume) = self.resolve_disk_operation_inode(
            payload,
            anchors,
            FollowSymlinks::All,
            credentials,
            |kind| {
                if kind == protocol::NODE_TYPE_DIRECTORY { EISDIR } else { EINVAL }
            },
        )?;
        let metadata = inode.metadata();
        if inode.file_type().is_dir() {
            return Err(EISDIR);
        }
        if !permission_allows(
            metadata.mode(),
            node_type(metadata.file_type()),
            metadata.uid(),
            metadata.gid(),
            uid,
            gid,
            groups,
            protocol::ACCESS_AT_WRITE,
        ) {
            return Err(EACCES);
        }
        let node_id = scoped_node_id(volume, &inode);
        self.truncate_scoped_inode(
            inode,
            filesystem,
            node_id,
            request.open_id,
            (request.flags & protocol::TRUNCATE_GROWTH_BOUNDED != 0).then_some(request.node_id),
        )?;
        Ok(self.success(request))
    }

    pub fn symlink_at(
        &mut self,
        request: protocol::Header,
        payload: &[u8],
        anchors: PathAnchors,
        credentials: protocol::Credentials,
    ) -> Result<Response, i32> {
        if request.flags & !protocol::SYMLINK_AT_FLAGS_ALL != 0 {
            return Err(EINVAL);
        }
        let root_attached = request.flags & protocol::SYMLINK_AT_ROOT_ATTACHED != 0;
        let base_attached = request.flags & protocol::SYMLINK_AT_BASE_ATTACHED != 0;
        if root_attached != anchors.root_open_id.is_some()
            || base_attached != anchors.base_open_id.is_some()
        {
            return Err(EINVAL);
        }
        let split = request.mode as usize;
        let (target, link_path) = payload.split_at_checked(split).ok_or(EINVAL)?;
        if target.is_empty()
            || link_path.is_empty()
            || target.len() > protocol::MAX_PATH_LEN
            || link_path.len() > protocol::MAX_PATH_LEN
            || target.contains(&0)
        {
            return Err(EINVAL);
        }
        let uid = credentials.effective_uid;
        let gid = credentials.effective_gid;
        let groups = credentials.supplementary_groups();
        let (resolution, filesystem, _) = self.resolve_open_path(
            link_path,
            anchors,
            FollowSymlinks::ExcludeFinalComponent,
            uid,
            gid,
            groups,
        )?;
        let (parent, name) = match resolution {
            Resolution::Found { .. } => return Err(EEXIST),
            Resolution::Missing { parent, name } => (parent, name),
        };
        let metadata = parent.metadata();
        if !permission_allows(
            metadata.mode(),
            protocol::NODE_TYPE_DIRECTORY,
            metadata.uid(),
            metadata.gid(),
            uid,
            gid,
            groups,
            protocol::ACCESS_AT_WRITE | protocol::ACCESS_AT_EXECUTE,
        ) {
            return Err(EACCES);
        }
        let mut parent = Dir::open_inode(&filesystem, parent).map_err(errno)?;
        filesystem
            .symlink(
                &mut parent,
                DirEntryName::try_from(name.as_slice()).map_err(|_| EINVAL)?,
                PathBuf::try_from(target).map_err(|_| EINVAL)?,
                uid,
                gid,
                Duration::default(),
            )
            .map_err(errno)?;
        Ok(self.success(request))
    }

    pub fn readlink_at(
        &mut self,
        request: protocol::Header,
        payload: &[u8],
        anchors: PathAnchors,
        credentials: protocol::Credentials,
    ) -> Result<Response, i32> {
        if request.flags & !protocol::READLINK_AT_FLAGS_ALL != 0 {
            return Err(EINVAL);
        }
        let root_attached = request.flags & protocol::READLINK_AT_ROOT_ATTACHED != 0;
        let base_attached = request.flags & protocol::READLINK_AT_BASE_ATTACHED != 0;
        if root_attached != anchors.root_open_id.is_some()
            || base_attached != anchors.base_open_id.is_some()
        {
            return Err(EINVAL);
        }
        let (inode, filesystem, _) = self.resolve_disk_operation_inode(
            payload,
            anchors,
            FollowSymlinks::ExcludeFinalComponent,
            credentials,
            |_| EINVAL,
        )?;
        if !inode.file_type().is_symlink() {
            return Err(EINVAL);
        }
        let target = inode.symlink_target(&filesystem).map_err(errno)?;
        let payload = target.as_ref().to_vec();
        if payload.len() > protocol::MAX_PATH_LEN {
            return Err(EFBIG);
        }
        let mut response = self.success(request);
        response.header.length = payload.len() as u32;
        response.payload = payload;
        Ok(response)
    }

    pub fn chmod_at(
        &mut self,
        request: protocol::Header,
        payload: &[u8],
        anchors: PathAnchors,
        credentials: protocol::Credentials,
    ) -> Result<Response, i32> {
        if request.flags & !protocol::CHMOD_AT_FLAGS_ALL != 0 || request.mode & !0o7777 != 0 {
            return Err(EINVAL);
        }
        let root_attached = request.flags & protocol::CHMOD_AT_ROOT_ATTACHED != 0;
        let base_attached = request.flags & protocol::CHMOD_AT_BASE_ATTACHED != 0;
        if root_attached != anchors.root_open_id.is_some()
            || base_attached != anchors.base_open_id.is_some()
        {
            return Err(EINVAL);
        }
        let uid = credentials.effective_uid;
        let gid = credentials.effective_gid;
        let groups = credentials.supplementary_groups();
        let (inode, filesystem, volume) = self.resolve_disk_operation_inode(
            payload,
            anchors,
            FollowSymlinks::All,
            credentials,
            |_| EROFS,
        )?;
        let metadata = inode.metadata();
        if uid != 0 && uid != metadata.uid() {
            return Err(EPERM);
        }
        let mut permissions = request.mode as u16;
        if uid != 0 && gid != metadata.gid() && !groups.contains(&metadata.gid()) {
            permissions &= !0o2000;
        }
        let node_id = scoped_node_id(volume, &inode);
        self.chmod_scoped_inode(inode, filesystem, node_id, permissions)?;
        Ok(self.success(request))
    }

    pub fn chown_at(
        &mut self,
        request: protocol::Header,
        payload: &[u8],
        anchors: PathAnchors,
        credentials: protocol::Credentials,
    ) -> Result<Response, i32> {
        if request.flags & !protocol::CHOWN_AT_FLAGS_ALL != 0 {
            return Err(EINVAL);
        }
        let root_attached = request.flags & protocol::CHOWN_AT_ROOT_ATTACHED != 0;
        let base_attached = request.flags & protocol::CHOWN_AT_BASE_ATTACHED != 0;
        if root_attached != anchors.root_open_id.is_some()
            || base_attached != anchors.base_open_id.is_some()
        {
            return Err(EINVAL);
        }
        let effective_uid = credentials.effective_uid;
        let effective_gid = credentials.effective_gid;
        let groups = credentials.supplementary_groups();
        let requested_uid = request.node_id as u32;
        let requested_gid = (request.node_id >> 32) as u32;
        let follow = if request.flags & protocol::CHOWN_AT_NOFOLLOW != 0 {
            FollowSymlinks::ExcludeFinalComponent
        } else {
            FollowSymlinks::All
        };
        let (inode, filesystem, volume) = self.resolve_disk_operation_inode(
            payload,
            anchors,
            follow,
            credentials,
            |_| EROFS,
        )?;
        let metadata = inode.metadata();
        if effective_uid != 0 {
            if effective_uid != metadata.uid()
                || requested_uid != u32::MAX && requested_uid != metadata.uid()
                || requested_gid != u32::MAX
                    && requested_gid != metadata.gid()
                    && requested_gid != effective_gid
                    && !groups.contains(&requested_gid)
            {
                return Err(EPERM);
            }
        }
        let new_uid = (requested_uid != u32::MAX).then_some(requested_uid);
        let new_gid = (requested_gid != u32::MAX).then_some(requested_gid);
        let node_id = scoped_node_id(volume, &inode);
        self.chown_scoped_inode(
            inode,
            filesystem,
            node_id,
            new_uid,
            new_gid,
            new_uid.is_some() || new_gid.is_some(),
        )?;
        Ok(self.success(request))
    }

    /// Resolves a path and obtains metadata as one serialized operation.
    pub fn stat_at(
        &mut self,
        request: protocol::Header,
        payload: &[u8],
        anchors: PathAnchors,
        credentials: protocol::Credentials,
    ) -> Result<Response, i32> {
        if request.flags & !protocol::STAT_AT_FLAGS_ALL != 0 {
            return Err(EINVAL);
        }
        let root_attached = request.flags & protocol::STAT_AT_ROOT_ATTACHED != 0;
        let base_attached = request.flags & protocol::STAT_AT_BASE_ATTACHED != 0;
        if root_attached != anchors.root_open_id.is_some()
            || base_attached != anchors.base_open_id.is_some()
        {
            return Err(EINVAL);
        }
        let uid = credentials.effective_uid;
        let gid = credentials.effective_gid;
        let groups = credentials.supplementary_groups();
        let follow = if request.flags & protocol::STAT_AT_NOFOLLOW != 0 {
            FollowSymlinks::ExcludeFinalComponent
        } else {
            FollowSymlinks::All
        };
        if let Some(resolution) =
            self.resolve_namespace_path(payload, anchors, follow, uid, gid, groups)?
        {
            match resolution {
                path_walk::Resolution::Found { inode, .. } if inode.device_node().is_some() => {
                    return self.device_status_response(request, &inode);
                }
                path_walk::Resolution::Missing { parent, .. } if parent.device_node().is_some() => {
                    return Err(ENOENT);
                }
                _ => {}
            }
        }
        let (inode, _, volume) =
            self.resolve_scoped_inode(payload, anchors, follow, uid, gid, groups)?;
        let node_id = scoped_node_id(volume, &inode);
        Ok(self.node_status_response(request, node_id, inode.metadata()))
    }

    /// Obtains metadata from an existing provider object. The caller must
    /// identify the attached Handle through the kernel before invoking this.
    pub fn stat_handle(&self, request: protocol::Header, open_id: u64) -> Result<Response, i32> {
        if request.flags != 0 {
            return Err(EINVAL);
        }
        if let Some(open) = self.opens.device(open_id) {
            return self.device_status_response(request, &open.node);
        }
        let open = self.opens.get(&open_id).ok_or(EBADF)?;
        let node_id = open.node_id;
        let metadata = if open.file.is_some()
            || open.inode.file_type().is_socket()
            || open.inode.file_type().is_dir()
        {
            Inode::read(&open.filesystem, open.inode.index)
                .map_err(errno)?
                .metadata()
        } else {
            open.inode.metadata()
        };
        Ok(self.node_status_response(request, node_id, metadata))
    }

    /// Reconstructs the current pathname of an open directory below an open
    /// root directory. This walks live directory entries, so rename is
    /// reflected and an unlinked cwd reports `ENOENT`.
    pub fn path_handle(
        &self,
        request: protocol::Header,
        root_open_id: u64,
        directory_open_id: u64,
    ) -> Result<Response, i32> {
        if request.flags != 0 || request.length != 0 {
            return Err(EINVAL);
        }
        if let Some(namespace) = &self.namespace {
            let payload = namespace.directory_path(
                self.retained_namespace_node(root_open_id)?,
                self.retained_namespace_node(directory_open_id)?,
            )?;
            let mut response = self.success(request);
            response.header.length = payload.len() as u32;
            response.payload = payload;
            return Ok(response);
        }
        let root = self.opens.get(&root_open_id).ok_or(EBADF)?.inode.clone();
        let current = self
            .opens
            .get(&directory_open_id)
            .ok_or(EBADF)?
            .inode
            .clone();
        let path = Self::inode_directory_path(&self.fs, root, current)?;
        let mut response = self.success(request);
        response.header.length = path.len() as u32;
        response.payload = path;
        Ok(response)
    }

    /// Resolves a path and checks its permission bits without exposing a
    /// check-then-use sequence to the POSIX policy service.
    pub fn access_at(
        &self,
        request: protocol::Header,
        payload: &[u8],
        anchors: PathAnchors,
        credentials: protocol::Credentials,
    ) -> Result<Response, i32> {
        if request.flags & !protocol::ACCESS_AT_FLAGS_ALL != 0 {
            return Err(EINVAL);
        }
        let root_attached = request.flags & protocol::ACCESS_AT_ROOT_ATTACHED != 0;
        let base_attached = request.flags & protocol::ACCESS_AT_BASE_ATTACHED != 0;
        if root_attached != anchors.root_open_id.is_some()
            || base_attached != anchors.base_open_id.is_some()
        {
            return Err(EINVAL);
        }
        let uid = credentials.effective_uid;
        let gid = credentials.effective_gid;
        let groups = credentials.supplementary_groups();
        let follow = if request.flags & protocol::ACCESS_AT_NOFOLLOW != 0 {
            FollowSymlinks::ExcludeFinalComponent
        } else {
            FollowSymlinks::All
        };
        if let Some(resolution) =
            self.resolve_namespace_path(payload, anchors, follow, uid, gid, groups)?
        {
            if let path_walk::Resolution::Missing { parent, .. } = &resolution {
                if parent.device_node().is_some() {
                    return Err(ENOENT);
                }
            }
            if let path_walk::Resolution::Found { inode, .. } = resolution {
                if inode.device_node().is_some() {
                    let status = self.namespace.as_ref().ok_or(EIO)?.device_status(&inode)?;
                    let requested = request.flags
                        & (protocol::ACCESS_AT_READ | protocol::ACCESS_AT_WRITE
                            | protocol::ACCESS_AT_EXECUTE);
                    return if permission_allows(
                        u16::try_from(status.mode).map_err(|_| EIO)?, status.kind,
                        status.uid, status.gid, uid, gid, groups, requested,
                    ) {
                        Ok(self.success(request))
                    } else {
                        Err(EACCES)
                    };
                }
            }
        }
        let (inode, _, _) =
            self.resolve_scoped_inode(payload, anchors, follow, uid, gid, groups)?;
        let requested = request.flags
            & (protocol::ACCESS_AT_READ | protocol::ACCESS_AT_WRITE | protocol::ACCESS_AT_EXECUTE);
        let metadata = inode.metadata();
        if permission_allows(
            metadata.mode(),
            node_type(metadata.file_type()),
            metadata.uid(),
            metadata.gid(),
            uid,
            gid,
            groups,
            requested,
        ) {
            Ok(self.success(request))
        } else {
            Err(EACCES)
        }
    }

    fn resolve_anchors(&self, path: &[u8], anchors: PathAnchors) -> Result<(Inode, Inode), i32> {
        let root = match anchors.root_open_id {
            Some(open_id) => self.opens.get(&open_id).ok_or(EBADF)?.inode.clone(),
            None => self.fs.read_root_inode().map_err(errno)?,
        };
        if !root.file_type().is_dir() {
            return Err(ENOTDIR);
        }
        let base = if path.first() == Some(&b'/') {
            root.clone()
        } else {
            match anchors.base_open_id {
                Some(open_id) => self.opens.get(&open_id).ok_or(EBADF)?.inode.clone(),
                None => root.clone(),
            }
        };
        if !base.file_type().is_dir() {
            return Err(ENOTDIR);
        }
        Ok((root, base))
    }

    fn resolve_scoped_inode(
        &self,
        path: &[u8],
        anchors: PathAnchors,
        follow: FollowSymlinks,
        uid: u32,
        gid: u32,
        groups: &[u32],
    ) -> Result<(Inode, Ext4, u32), i32> {
        let (resolution, filesystem, volume) =
            self.resolve_open_path(path, anchors, follow, uid, gid, groups)?;
        match resolution {
            Resolution::Found { inode, .. } => Ok((inode, filesystem, volume)),
            Resolution::Missing { .. } => Err(ENOENT),
        }
    }

    fn resolve_open_path(
        &self,
        path: &[u8],
        anchors: PathAnchors,
        follow: FollowSymlinks,
        uid: u32,
        gid: u32,
        groups: &[u32],
    ) -> Result<(Resolution, Ext4, u32), i32> {
        let Some(resolution) = self.resolve_namespace_path(path, anchors, follow, uid, gid, groups)?
        else {
            let (root, base) = self.resolve_anchors(path, anchors)?;
            let resolution = self.resolve_path_at(root, base, path, follow, uid, gid, groups)?;
            self.check_missing_directory(&resolution, 0)?;
            return Ok((resolution, self.fs.clone(), 0));
        };
        let namespace = self.namespace.as_ref().ok_or(EIO)?;
        let node = match &resolution {
            path_walk::Resolution::Found { inode, .. } => inode,
            path_walk::Resolution::Missing { parent, .. } => parent,
        };
        let filesystem = namespace.filesystem(node)?.clone();
        let volume = u32::try_from(node.id().volume).map_err(|_| EIO)?;
        let resolution = match resolution {
            path_walk::Resolution::Found { inode, parent } => Resolution::Found {
                inode: inode.into_inode()?,
                parent: parent
                    .map(|(node, name)| node.into_inode().map(|inode| (inode, name)))
                    .transpose()?,
            },
            path_walk::Resolution::Missing { parent, name } => Resolution::Missing {
                parent: parent.into_inode()?,
                name,
            },
        };
        self.check_missing_directory(&resolution, volume)?;
        Ok((resolution, filesystem, volume))
    }

    // Only the exact retained link is private. User-created names and other
    // hard links to the same inode remain ordinary namespace entries.
    pub(super) fn is_private_entry(
        &self,
        parent: crate::namespace::NodeId,
        name: &[u8],
        target: crate::namespace::NodeId,
    ) -> bool {
        if parent.volume != target.volume {
            return false;
        }
        let node_id = (target.volume << 32) | u64::from(target.inode);
        self.orphans.get(&node_id).is_some_and(|orphan| {
            orphan.parent.index.get() == parent.inode && orphan.name.as_bytes() == name
        })
    }

    fn resolve_path_at(
        &self,
        root: Inode,
        base: Inode,
        path: &[u8],
        follow: FollowSymlinks,
        uid: u32,
        gid: u32,
        groups: &[u32],
    ) -> Result<Resolution, i32> {
        path_walk::resolve_visible(
            self,
            root,
            base,
            path,
            follow == FollowSymlinks::All,
            path_walk::Credentials { uid, gid, groups },
            |parent, name, child| {
                !self.is_private_entry(
                    crate::namespace::NodeId {
                        volume: 0,
                        inode: parent.index.get(),
                    },
                    name,
                    crate::namespace::NodeId {
                        volume: 0,
                        inode: child.index.get(),
                    },
                )
            },
        )
    }

    fn ancestry_from_root(&self, root: &Inode, base: Inode) -> Result<Vec<Inode>, i32> {
        const MAX_ANCESTORS: usize = 1024;

        if !base.file_type().is_dir() {
            return Err(ENOTDIR);
        }
        let mut reversed = vec![base];
        while reversed.last().ok_or(EIO)?.index != root.index {
            if reversed.len() >= MAX_ANCESTORS {
                return Err(ELOOP);
            }
            let current = reversed.last().ok_or(EIO)?;
            let parent = Dir::open_inode(&self.fs, current.clone())
                .map_err(errno)?
                .get_entry(DirEntryName::try_from("..").map_err(|_| EIO)?)
                .map_err(errno)?;
            if parent.index == current.index {
                return Err(EACCES);
            }
            reversed.push(parent);
        }
        reversed.reverse();
        Ok(reversed)
    }

    pub fn provider_read(&mut self, open_id: u64, length: usize) -> Result<Vec<u8>, i32> {
        if self.opens.device(open_id).is_some() {
            return self.read_device(open_id, length.min(mnu_abi::provider::MAX_DATA_LEN));
        }
        let open = self.opens.get(&open_id).ok_or(EBADF)?;
        if open.file.is_none() {
            let inode = open.inode.clone();
            let filesystem = open.filesystem.clone();
            let volume = open.volume;
            let start_entry = open.offset;
            let cursor_records = open.cursor_records;
            let (payload, next_entry) = self.read_open_directory_payload(
                &filesystem,
                volume,
                inode,
                start_entry,
                length.min(mnu_abi::provider::MAX_DATA_LEN),
                cursor_records,
            )?;
            self.opens.get_mut(&open_id).ok_or(EBADF)?.offset = next_entry;
            return Ok(payload);
        }
        let open = self.opens.get_mut(&open_id).ok_or(EBADF)?;
        refresh_provider_file(open)?;
        let file = open.file.as_mut().ok_or(EISDIR)?;
        let mut payload = vec![0u8; length.min(mnu_abi::provider::MAX_DATA_LEN)];
        let (done, _) = crate::positioned_io::sequential(
            &mut open.offset,
            payload.len(),
            false,
            |done, position, _| {
                file.read_bytes_at(&mut payload[done..], position)
                    .map_err(errno)
            },
        )?;
        payload.truncate(done);
        Ok(payload)
    }

    pub fn provider_read_with_offset(
        &mut self,
        open_id: u64,
        length: usize,
    ) -> Result<(Vec<u8>, u64), i32> {
        if length > mnu_abi::provider::MAX_POSITIONED_READ_LEN {
            return Err(EINVAL);
        }
        if let Some(open) = self.opens.device(open_id) {
            open.null.as_ref().ok_or(EISDIR)?.read_into(&mut [])?;
            return Ok((Vec::new(), 0));
        }
        let open = self.opens.get(&open_id).ok_or(EBADF)?;
        if open.file.is_none() {
            return Err(EISDIR);
        }
        let start = open.offset;
        start.checked_add(length as u64).ok_or(EFBIG)?;
        let payload = self.provider_read(open_id, length)?;
        Ok((payload, start))
    }

    /// Reads one sequential operation into caller-owned storage. The starting
    /// position and offset advance belong to the same open-file description.
    pub fn provider_read_into(
        &mut self,
        open_id: u64,
        output: &mut [u8],
    ) -> Result<(usize, u64), i32> {
        if output.is_empty() || output.len() > mnu_abi::provider::MAX_SHARED_READ_LEN {
            return Err(EINVAL);
        }
        if let Some(open) = self.opens.device(open_id) {
            return open.null.as_ref().ok_or(EISDIR)?
                .read_into(output).map(|count| (count, 0));
        }
        let open = self.opens.get_mut(&open_id).ok_or(EBADF)?;
        refresh_provider_file(open)?;
        let file = open.file.as_mut().ok_or(EISDIR)?;
        crate::positioned_io::sequential(
            &mut open.offset,
            output.len(),
            false,
            |done, position, _| {
                file.read_bytes_at(&mut output[done..], position)
                    .map_err(errno)
            },
        )
    }

    pub fn provider_write(&mut self, open_id: u64, payload: &[u8]) -> Result<usize, i32> {
        self.provider_write_with_offset(open_id, payload)
            .map(|(written, _)| written)
    }

    pub fn provider_write_with_offset(
        &mut self,
        open_id: u64,
        payload: &[u8],
    ) -> Result<(usize, u64), i32> {
        self.provider_write_range(open_id, payload, None)
    }

    pub fn provider_write_bounded(
        &mut self,
        open_id: u64,
        payload: &[u8],
        byte_end: u64,
    ) -> Result<(usize, u64), i32> {
        self.provider_write_range(open_id, payload, Some(byte_end))
    }

    fn provider_write_range(
        &mut self,
        open_id: u64,
        payload: &[u8],
        byte_end: Option<u64>,
    ) -> Result<(usize, u64), i32> {
        if payload.len() > mnu_abi::provider::MAX_DATA_LEN {
            return Err(EINVAL);
        }
        if let Some(open) = self.opens.device(open_id) {
            if byte_end.is_some() {
                return Err(ENOTSUP);
            }
            return open.null.as_ref().ok_or(EISDIR)?
                .write(payload).map(|count| (count, 0));
        }
        let open = self.opens.get_mut(&open_id).ok_or(EBADF)?;
        if open.file.is_none() {
            return Err(EISDIR);
        }
        if payload.is_empty() {
            return Ok((0, open.offset));
        }
        // Another description can have changed the inode/extent map since
        // this one was opened. Select append position from current backing
        // while the provider worker still owns mutation serialization.
        refresh_provider_file(open)?;
        let file = open.file.as_mut().ok_or(EISDIR)?;
        let mut cursor = if open.status_flags & protocol::OPEN_STATUS_APPEND != 0 {
            file.inode().metadata().len()
        } else {
            open.offset
        };
        let length = if let Some(end) = byte_end {
            if cursor >= end {
                return Err((-mnu_abi::provider::STATUS_BOUND_REACHED) as i32);
            }
            (end - cursor).min(payload.len() as u64) as usize
        } else {
            payload.len()
        };
        let result = crate::positioned_io::sequential(
            &mut cursor,
            length,
            true,
            |done, position, _| {
                file.write_bytes_at(&payload[done..length], position)
                    .map_err(errno)
            },
        )?;
        open.offset = cursor;
        open.inode = file.inode().clone();
        Ok(result)
    }

    pub fn provider_read_at(
        &mut self,
        open_id: u64,
        offset: u64,
        length: usize,
    ) -> Result<Vec<u8>, i32> {
        if let Some(open) = self.opens.device(open_id) {
            open.null.as_ref().ok_or(EISDIR)?.read_at(&mut [], offset)?;
            return Ok(Vec::new());
        }
        let open = self.opens.get_mut(&open_id).ok_or(EBADF)?;
        refresh_provider_file(open)?;
        let file = open.file.as_mut().ok_or(EISDIR)?;
        let mut payload = vec![0u8; length.min(mnu_abi::provider::MAX_DATA_LEN)];
        let done =
            crate::positioned_io::transfer(offset, payload.len(), false, |done, position, _| {
                file.read_bytes_at(&mut payload[done..], position)
                    .map_err(errno)
            })?;
        payload.truncate(done);
        Ok(payload)
    }

    pub fn provider_write_at(
        &mut self,
        open_id: u64,
        offset: u64,
        payload: &[u8],
    ) -> Result<usize, i32> {
        if payload.len() > mnu_abi::provider::MAX_DATA_LEN {
            return Err(EINVAL);
        }
        if let Some(open) = self.opens.device(open_id) {
            return open.null.as_ref().ok_or(EISDIR)?.write_at(payload, offset);
        }
        let open = self.opens.get_mut(&open_id).ok_or(EBADF)?;
        refresh_provider_file(open)?;
        let file = open.file.as_mut().ok_or(EISDIR)?;
        crate::positioned_io::transfer(offset, payload.len(), true, |done, position, _| {
            file.write_bytes_at(&payload[done..], position)
                .map_err(errno)
        })
    }

    pub fn provider_sync(&self, open_id: u64) -> Result<(), i32> {
        if self.opens.device(open_id).is_some() {
            return Err(EINVAL);
        }
        let open = self.opens.get(&open_id).ok_or(EBADF)?;
        open.filesystem.flush().map_err(errno)
    }

    pub fn provider_memory_object(&self, open_id: u64) -> Result<u64, i32> {
        if self.opens.device(open_id).is_some() {
            return Ok(0);
        }
        let open = self.opens.get(&open_id).ok_or(EBADF)?;
        if open.file.is_none() || open.node_id == 0 {
            // A directory remains a readable provider stream, but does not
            // expose byte-addressed pager backing. Decline this optional
            // mechanism so native HandleRead uses the ordinary stream path.
            return Ok(0);
        }
        Ok(open.memory_object_id)
    }

    fn memory_identity_for(&self, node_id: u64, new_open_id: u64) -> u64 {
        self.opens
            .values()
            .find(|open| open.node_id == node_id)
            .map_or(new_open_id, |open| open.memory_object_id)
    }

    pub fn provider_seek(&mut self, open_id: u64, offset: i64, basis: u64) -> Result<u64, i32> {
        if let Some(open) = self.opens.device_mut(open_id) {
            if let Some(null) = &open.null {
                let basis = match basis {
                    mnu_abi::HANDLE_SEEK_START => 0,
                    mnu_abi::HANDLE_SEEK_CURRENT => 1,
                    mnu_abi::HANDLE_SEEK_END => 2,
                    _ => return Err(EINVAL),
                };
                return null.seek(offset, basis);
            }
            let base = match basis {
                mnu_abi::HANDLE_SEEK_START => 0,
                mnu_abi::HANDLE_SEEK_CURRENT => i128::from(open.offset),
                mnu_abi::HANDLE_SEEK_END => return Err(EISDIR),
                _ => return Err(EINVAL),
            };
            let next = base.checked_add(i128::from(offset)).ok_or(EINVAL)?;
            open.offset = u64::try_from(next).map_err(|_| EINVAL)?;
            return Ok(open.offset);
        }
        let open = self.opens.get_mut(&open_id).ok_or(EBADF)?;
        let current = i128::from(open.offset);
        let base = match basis {
            mnu_abi::HANDLE_SEEK_START => 0,
            mnu_abi::HANDLE_SEEK_CURRENT => current,
            mnu_abi::HANDLE_SEEK_END => {
                if open.file.is_none() {
                    return Err(EISDIR);
                }
                i128::from(
                    Inode::read(&open.filesystem, open.inode.index)
                        .map_err(errno)?
                        .metadata()
                        .len(),
                )
            }
            _ => return Err(EINVAL),
        };
        let next = base.checked_add(i128::from(offset)).ok_or(EINVAL)?;
        if !(0..=i128::from(u64::MAX)).contains(&next) {
            return Err(EINVAL);
        }
        open.offset = next as u64;
        Ok(open.offset)
    }

    pub fn provider_close(&mut self, open_id: u64) -> Result<(), i32> {
        self.close(protocol::Header {
            opcode: protocol::OP_CLOSE,
            open_id,
            ..protocol::Header::default()
        })?;
        Ok(())
    }

    fn close(&mut self, request: protocol::Header) -> Result<Response, i32> {
        if self.opens.device(request.open_id).is_some() {
            self.opens.remove(&request.open_id);
            return Ok(self.success(request));
        }
        let open = self.opens.get(&request.open_id).ok_or(EBADF)?;
        let node_id = open.node_id;
        if self.removed_directories.contains_key(&node_id) {
            self.opens.remove(&request.open_id);
            self.collect_removed_directories(node_id)?;
            return Ok(self.success(request));
        }
        let is_last_open = self
            .opens
            .values()
            .filter(|other| other.node_id == node_id)
            .count()
            == 1;
        if is_last_open {
            if let Some(orphan) = self.orphans.get(&node_id).cloned() {
                let inode = Inode::read(&open.filesystem, open.inode.index).map_err(errno)?;
                let parent_inode = Inode::read(&open.filesystem, orphan.parent.index).map_err(errno)?;
                let mut parent = Dir::open_inode(&open.filesystem, parent_inode).map_err(errno)?;
                parent
                    .unlink(
                        DirEntryName::try_from(orphan.name.as_str()).map_err(|_| EIO)?,
                        inode,
                    )
                    .map_err(errno)?;
                self.orphans.remove(&node_id);
                self.nodes.remove(&node_id);
            }
        }
        self.opens.remove(&request.open_id);
        Ok(self.success(request))
    }

    fn read(&mut self, request: protocol::Header) -> Result<Response, i32> {
        let length = (request.flags as usize).min(protocol::MAX_IO_LEN);
        let file = self
            .opens
            .get_mut(&request.open_id)
            .ok_or(EBADF)?
            .file
            .as_mut()
            .ok_or(EISDIR)?;
        let mut payload = vec![0u8; length];
        let mut done = 0;
        while done < payload.len() {
            let count = file
                .read_bytes_at(&mut payload[done..], request.offset + done as u64)
                .map_err(errno)?;
            if count == 0 {
                break;
            }
            done += count;
        }
        payload.truncate(done);
        let mut response = self.success(request);
        response.header.length = done as u32;
        response.payload = payload;
        Ok(response)
    }

    fn write(&mut self, request: protocol::Header, payload: &[u8]) -> Result<Response, i32> {
        if payload.len() > protocol::MAX_IO_LEN {
            return Err(EINVAL);
        }
        let file = self
            .opens
            .get_mut(&request.open_id)
            .ok_or(EBADF)?
            .file
            .as_mut()
            .ok_or(EISDIR)?;
        let mut done = 0;
        while done < payload.len() {
            let count = file
                .write_bytes_at(&payload[done..], request.offset + done as u64)
                .map_err(errno)?;
            if count == 0 {
                return Err(EIO);
            }
            done += count;
        }
        let mut response = self.success(request);
        response.header.offset = done as u64;
        Ok(response)
    }

    fn stat(&self, request: protocol::Header) -> Result<Response, i32> {
        let (node_id, metadata) = if request.open_id != 0 {
            let open = self.opens.get(&request.open_id).ok_or(EBADF)?;
            (open.node_id, open.inode.metadata())
        } else {
            let path = self.nodes.get(&request.node_id).ok_or(ENOENT)?;
            (
                request.node_id,
                self.fs.symlink_metadata(path.as_str()).map_err(errno)?,
            )
        };
        Ok(self.metadata_response(request, node_id, metadata))
    }

    fn create(&mut self, request: protocol::Header, payload: &[u8]) -> Result<Response, i32> {
        if request.flags != protocol::NODE_TYPE_REGULAR
            && request.flags != protocol::NODE_TYPE_DIRECTORY
        {
            return Err(ENOSYS);
        }
        let path = decode_path(payload)?;
        let (parent_path, name) = split_parent(path)?;
        match self.fs.symlink_metadata(path) {
            Ok(_) => return Err(EEXIST),
            Err(Ext4Error::NotFound) => {}
            Err(error) => return Err(errno(error)),
        }
        let parent_inode = self
            .fs
            .path_to_inode(
                parent_path.try_into().map_err(|_| EINVAL)?,
                FollowSymlinks::All,
            )
            .map_err(errno)?;
        let mut parent = Dir::open_inode(&self.fs, parent_inode).map_err(errno)?;
        let permissions = InodeMode::from_bits_truncate((request.mode as u16) & 0x0fff);
        let uid = request.offset as u32;
        let gid = (request.offset >> 32) as u32;
        let (file_type, type_mode) = if request.flags == protocol::NODE_TYPE_DIRECTORY {
            (FileType::Directory, InodeMode::S_IFDIR)
        } else {
            (FileType::Regular, InodeMode::S_IFREG)
        };
        let mut inode = self
            .fs
            .create_inode(InodeCreationOptions {
                file_type,
                mode: permissions | type_mode,
                uid,
                gid,
                time: Duration::default(),
                flags: InodeFlags::empty(),
            })
            .map_err(errno)?;
        if file_type == FileType::Directory {
            // ext4plus keeps the InodeIndex type private, but the public `.`
            // entry can be passed directly to the directory initializer.
            let parent_index = parent
                .read_dir()
                .map_err(errno)?
                .find_map(|entry| match entry {
                    Ok(entry) if entry.file_name() == "." => Some(Ok(entry.inode)),
                    Ok(_) => None,
                    Err(error) => Some(Err(errno(error))),
                })
                .ok_or(EIO)??;
            let mut directory = Dir::init(self.fs.clone(), inode, parent_index).map_err(errno)?;
            parent
                .link(
                    DirEntryName::try_from(name).map_err(|_| EINVAL)?,
                    directory.inode_mut(),
                )
                .map_err(errno)?;
            inode = directory.inode().clone();
        } else {
            parent
                .link(
                    DirEntryName::try_from(name).map_err(|_| EINVAL)?,
                    &mut inode,
                )
                .map_err(errno)?;
        }
        let node_id = self.remember_node(path, FollowSymlinks::All)?;
        Ok(self.metadata_response(request, node_id, inode.metadata()))
    }

    fn read_dir(&mut self, request: protocol::Header) -> Result<Response, i32> {
        let max_length = (request.flags as usize).min(protocol::MAX_IO_LEN);
        let (payload, next_entry) =
            self.read_directory_payload(request.node_id, request.offset, max_length)?;
        let mut response = self.success(request);
        response.header.offset = next_entry;
        response.header.length = payload.len() as u32;
        response.payload = payload;
        Ok(response)
    }

    fn read_directory_payload(
        &mut self,
        node_id: u64,
        start_entry: u64,
        max_length: usize,
    ) -> Result<(Vec<u8>, u64), i32> {
        let path = self.nodes.get(&node_id).ok_or(ENOENT)?.clone();
        let start_entry = usize::try_from(start_entry).map_err(|_| EINVAL)?;
        let mut payload = Vec::new();
        let mut next_entry = start_entry;
        let parent = self
            .fs
            .path_to_inode(path.as_str().try_into().map_err(|_| EINVAL)?, FollowSymlinks::All)
            .map_err(errno)?;
        for entry in self
            .fs
            .read_dir(path.as_str())
            .map_err(errno)?
            .skip(start_entry)
        {
            let entry = entry.map_err(errno)?;
            let name = entry.file_name().as_str().map_err(|_| EIO)?;
            if self.is_private_entry(
                crate::namespace::NodeId {
                    volume: 0,
                    inode: parent.index.get(),
                },
                name.as_bytes(),
                crate::namespace::NodeId {
                    volume: 0,
                    inode: entry.inode.get(),
                },
            ) {
                next_entry = next_entry.checked_add(1).ok_or(EIO)?;
                continue;
            }
            let child_path = joined_path(&path, name);
            let node_id = u64::from(entry.inode.get());
            self.remember_known_node(&child_path, node_id);
            let kind = node_type(entry.file_type().map_err(errno)?);
            let record_length = protocol::DIRENT_HEADER_LEN + name.len();
            if payload.len().saturating_add(record_length) > max_length {
                if payload.is_empty() {
                    return Err(ENOSPC);
                }
                break;
            }
            let offset = payload.len();
            payload.resize(offset + record_length, 0);
            protocol::encode_dir_entry(node_id, kind, name.as_bytes(), &mut payload[offset..])
                .map_err(|_| EIO)?;
            next_entry = next_entry.checked_add(1).ok_or(EIO)?;
        }
        Ok((payload, next_entry as u64))
    }

    /// Reads an already-open directory by inode rather than resolving its
    /// former pathname again. Directory handles therefore survive rename and
    /// unlink in the same way as every other open file description.
    fn read_open_directory_payload(
        &self,
        filesystem: &Ext4,
        volume: u32,
        inode: Inode,
        start_entry: u64,
        max_length: usize,
        cursor_records: bool,
    ) -> Result<(Vec<u8>, u64), i32> {
        let start_entry = usize::try_from(start_entry).map_err(|_| EINVAL)?;
        let node = self
            .namespace
            .as_ref()
            .map(|namespace| namespace.retained_node(volume, inode.clone()))
            .transpose()?;
        let parent_id = crate::namespace::NodeId {
            volume: u64::from(volume),
            inode: inode.index.get(),
        };
        let directory = Dir::open_inode(filesystem, inode).map_err(errno)?;
        let physical =
            directory
                .read_dir()
                .map_err(errno)?
                .map(|entry| -> Result<(u64, u32, Vec<u8>), i32> {
                    let entry = entry.map_err(errno)?;
                    let name = entry.file_name().as_ref().to_vec();
                    if self.is_private_entry(
                        parent_id,
                        &name,
                        crate::namespace::NodeId {
                            volume: u64::from(volume),
                            inode: entry.inode.get(),
                        },
                    ) {
                        return Ok((0, 0, name));
                    }
                    let node_id = if let (Some(namespace), Some(node)) = (&self.namespace, &node) {
                        let id = namespace.directory_entry_id(node, &name, entry.inode.get())?;
                        (id.volume << 32) | u64::from(id.inode)
                    } else {
                        (u64::from(volume) << 32) | u64::from(entry.inode.get())
                    };
                    Ok((node_id, node_type(entry.file_type().map_err(errno)?), name))
                });
        let named = if let (Some(namespace), Some(node)) = (&self.namespace, &node) {
            namespace.named_children(node)?
        } else {
            Vec::new()
        };
        let named = named.into_iter().map(|(name, id)| {
            Ok((
                (id.volume << 32) | u64::from(id.inode),
                protocol::NODE_TYPE_DIRECTORY,
                name,
            ))
        });
        let mut payload = Vec::new();
        let mut next_entry = start_entry;
        for entry in physical.chain(named).skip(start_entry) {
            let (node_id, kind, name) = entry?;
            if node_id == 0 {
                next_entry = next_entry.checked_add(1).ok_or(EIO)?;
                continue;
            }
            let header_length = if cursor_records {
                protocol::CURSOR_DIRENT_HEADER_LEN
            } else {
                protocol::DIRENT_HEADER_LEN
            };
            let record_length = header_length + name.len();
            if payload.len().saturating_add(record_length) > max_length {
                if payload.is_empty() {
                    return Err(ENOSPC);
                }
                break;
            }
            let offset = payload.len();
            payload.resize(offset + record_length, 0);
            next_entry = next_entry.checked_add(1).ok_or(EIO)?;
            if cursor_records {
                protocol::encode_cursor_dir_entry(
                    node_id,
                    kind,
                    &name,
                    next_entry as u64,
                    &mut payload[offset..],
                )
            } else {
                protocol::encode_dir_entry(node_id, kind, &name, &mut payload[offset..])
            }
            .map_err(|_| EIO)?;
        }
        Ok((payload, next_entry as u64))
    }

    fn unlink(&mut self, request: protocol::Header, payload: &[u8]) -> Result<Response, i32> {
        let path = decode_path(payload)?;
        let (parent_path, name) = split_parent(path)?;
        let parent_inode = self
            .fs
            .path_to_inode(
                parent_path.try_into().map_err(|_| EINVAL)?,
                FollowSymlinks::All,
            )
            .map_err(errno)?;
        let parent = Dir::open_inode(&self.fs, parent_inode.clone()).map_err(errno)?;
        let inode = parent
            .get_entry(DirEntryName::try_from(name).map_err(|_| EINVAL)?)
            .map_err(errno)?;
        drop(parent);
        self.unlink_entry(
            &self.fs.clone(),
            0,
            parent_inode,
            name.as_bytes(),
            inode,
            request.flags == protocol::NODE_TYPE_DIRECTORY,
            Some(path),
        )?;
        Ok(self.success(request))
    }

    fn unlink_entry(
        &mut self,
        filesystem: &Ext4,
        volume: u32,
        parent_inode: Inode,
        name: &[u8],
        mut inode: Inode,
        remove_directory: bool,
        path_hint: Option<&str>,
    ) -> Result<(), i32> {
        let mut parent = Dir::open_inode(filesystem, parent_inode.clone()).map_err(errno)?;
        if inode.file_type().is_dir() {
            if !remove_directory {
                return Err(EISDIR);
            }
            if !self.prepare_empty_directory(filesystem, volume, &inode)? {
                return Err(ENOTEMPTY);
            }
            // Moving private retention links may have grown the volume root.
            // Refresh before persisting the public parent's directory links.
            parent = Dir::open_inode(
                filesystem,
                Inode::read(filesystem, parent_inode.index).map_err(errno)?,
            )
            .map_err(errno)?;
            self.remove_replaced_directory(filesystem, volume, &mut parent, name, inode)?;
            if let Some(path) = path_hint {
                if let Some(node_id) = self.node_ids.remove(path) {
                    self.nodes.remove(&node_id);
                }
            }
            return Ok(());
        }
        if remove_directory {
            return Err(ENOTDIR);
        }
        let node_id = scoped_node_id(volume, &inode);
        let is_open = self.opens.values().any(|open| open.node_id == node_id);
        // Public hard links already keep the inode alive. Create one private
        // retention link only when the last public name is being removed.
        let retain = is_open && inode.links_count() == 1 && !self.orphans.contains_key(&node_id);
        let mut retention_root = if retain {
            self.orphans.try_reserve(1).map_err(|_| ENOMEM)?;
            Some(
                Dir::open_inode(filesystem, filesystem.read_root_inode().map_err(errno)?)
                    .map_err(errno)?,
            )
        } else {
            None
        };
        let retained = if let Some(root) = retention_root.as_mut() {
            // Never keep a user directory nonempty just to pin an open file.
            // Use the same Dir instance when the public parent is the root,
            // so directory growth does not leave its inode metadata stale.
            let holder = if root.inode().index == parent.inode().index {
                &mut parent
            } else {
                root
            };
            Some(Self::create_retention_link(
                filesystem, holder, &mut inode, node_id,
            )?)
        } else {
            None
        };
        if let Err(error) = parent.unlink(
            DirEntryName::try_from(name).map_err(|_| EINVAL)?,
            inode.clone(),
        ) {
            if let Some(orphan) = retained {
                let holder = if orphan.parent.index == parent.inode().index {
                    &mut parent
                } else {
                    retention_root.as_mut().ok_or(EIO)?
                };
                holder
                    .unlink(
                        DirEntryName::try_from(orphan.name.as_str()).map_err(|_| EIO)?,
                        inode,
                    )
                    .map_err(errno)?;
            }
            return Err(errno(error));
        }
        if let Some(path) = path_hint {
            self.node_ids.remove(path);
        }
        if let Some(orphan) = retained {
            self.orphans.insert(node_id, orphan);
        } else if !is_open {
            self.nodes.remove(&node_id);
        }
        Ok(())
    }

    fn create_retention_link(
        filesystem: &Ext4,
        holder: &mut Dir,
        inode: &mut Inode,
        node_id: u64,
    ) -> Result<Orphan, i32> {
        let mut attempt = 0u64;
        loop {
            let name = if attempt == 0 {
                format!(".mochios-orphan-{node_id}")
            } else {
                format!(".mochios-orphan-{node_id}-{attempt}")
            };
            let entry_name = DirEntryName::try_from(name.as_str()).map_err(|_| EIO)?;
            // FilesystemService serializes the whole operation. Check before
            // link(): the backend increments nlink even if the name exists.
            match holder.get_entry(entry_name) {
                Ok(_) => {
                    attempt = attempt.checked_add(1).ok_or(ENOSPC)?;
                    continue;
                }
                Err(Ext4Error::NotFound) => (),
                Err(error) => return Err(errno(error)),
            }
            let original_links = inode.links_count();
            if let Err(error) = holder.link(entry_name, inode) {
                inode.set_links_count(original_links);
                inode.write(filesystem).map_err(errno)?;
                return Err(errno(error));
            }
            return Ok(Orphan {
                parent: holder.inode().clone(),
                name,
            });
        }
    }

    fn symlink(&mut self, request: protocol::Header, payload: &[u8]) -> Result<Response, i32> {
        let split = usize::try_from(request.offset).map_err(|_| EINVAL)?;
        let (target, link_path) = payload.split_at_checked(split).ok_or(EINVAL)?;
        if target.is_empty() || target.len() > protocol::MAX_PATH_LEN || target.contains(&0) {
            return Err(EINVAL);
        }
        let target = std::str::from_utf8(target).map_err(|_| EINVAL)?;
        let link_path = decode_path(link_path)?;
        let uid = u32::try_from(request.node_id).map_err(|_| EINVAL)?;
        let gid = u32::try_from(request.open_id).map_err(|_| EINVAL)?;
        let (parent_path, name) = split_parent(link_path)?;
        match self.fs.symlink_metadata(link_path) {
            Ok(_) => return Err(EEXIST),
            Err(Ext4Error::NotFound) => {}
            Err(error) => return Err(errno(error)),
        }
        let parent_inode = self
            .fs
            .path_to_inode(
                parent_path.try_into().map_err(|_| EINVAL)?,
                FollowSymlinks::All,
            )
            .map_err(errno)?;
        let mut parent = Dir::open_inode(&self.fs, parent_inode).map_err(errno)?;
        let inode = self
            .fs
            .symlink(
                &mut parent,
                DirEntryName::try_from(name).map_err(|_| EINVAL)?,
                PathBuf::try_from(target).map_err(|_| EINVAL)?,
                uid,
                gid,
                Duration::default(),
            )
            .map_err(errno)?;
        let node_id = self.remember_node(link_path, FollowSymlinks::ExcludeFinalComponent)?;
        Ok(self.metadata_response(request, node_id, inode.metadata()))
    }

    fn rename(&mut self, request: protocol::Header, payload: &[u8]) -> Result<Response, i32> {
        let filesystem = self.fs.clone();
        let split = usize::try_from(request.offset).map_err(|_| EINVAL)?;
        let (old_path, new_path) = payload.split_at_checked(split).ok_or(EINVAL)?;
        let old_path = decode_path(old_path)?;
        let new_path = decode_path(new_path)?;
        if old_path == new_path {
            return Ok(self.success(request));
        }
        let (old_parent_path, old_name) = split_parent(old_path)?;
        let (new_parent_path, new_name) = split_parent(new_path)?;
        let old_parent_inode = self
            .fs
            .path_to_inode(
                old_parent_path.try_into().map_err(|_| EINVAL)?,
                FollowSymlinks::All,
            )
            .map_err(errno)?;
        let new_parent_inode = self
            .fs
            .path_to_inode(
                new_parent_path.try_into().map_err(|_| EINVAL)?,
                FollowSymlinks::All,
            )
            .map_err(errno)?;
        let mut old_parent = Dir::open_inode(&self.fs, old_parent_inode).map_err(errno)?;
        let mut new_parent = Dir::open_inode(&self.fs, new_parent_inode.clone()).map_err(errno)?;
        let mut source_inode = old_parent
            .get_entry(DirEntryName::try_from(old_name).map_err(|_| EINVAL)?)
            .map_err(errno)?;
        let source_is_directory = source_inode.file_type().is_dir();
        self.remember_node(old_path, FollowSymlinks::ExcludeFinalComponent)?;

        let destination =
            match new_parent.get_entry(DirEntryName::try_from(new_name).map_err(|_| EINVAL)?) {
                Ok(inode) if source_is_directory && inode.file_type().is_dir() => {
                    if !self.prepare_empty_directory(&filesystem, 0, &inode)? {
                        return Err(ENOTEMPTY);
                    }
                    let node_id =
                        self.remember_node(new_path, FollowSymlinks::ExcludeFinalComponent)?;
                    Some((node_id, inode))
                }
                Ok(_) if source_is_directory => return Err(ENOTDIR),
                Ok(inode) if inode.file_type().is_dir() => return Err(EISDIR),
                Ok(inode) => {
                    let node_id =
                        self.remember_node(new_path, FollowSymlinks::ExcludeFinalComponent)?;
                    Some((node_id, inode))
                }
                Err(Ext4Error::NotFound) => None,
                Err(error) => return Err(errno(error)),
            };
        if source_is_directory {
            old_parent = Dir::open_inode(
                &filesystem,
                Inode::read(&filesystem, old_parent.inode().index).map_err(errno)?,
            )
            .map_err(errno)?;
            new_parent = Dir::open_inode(
                &filesystem,
                Inode::read(&filesystem, new_parent.inode().index).map_err(errno)?,
            )
            .map_err(errno)?;
            if self.directory_is_at_or_below(&filesystem, &source_inode, new_parent_inode)? {
                return Err(EINVAL);
            }
            let backup_name = format!(".mochios-orphan-rename-{}", request.request_id);
            self.stage_rename_destination(
                &filesystem,
                &mut new_parent,
                new_name,
                &backup_name,
                destination.as_ref(),
            )?;
            if let Err(error) = self.move_directory(
                &filesystem,
                &mut old_parent,
                &mut new_parent,
                old_parent_path == new_parent_path,
                old_name,
                new_name,
                source_inode,
            ) {
                self.restore_rename_destination(
                    &filesystem,
                    &mut new_parent,
                    new_name,
                    &backup_name,
                    destination,
                );
                return Err(error);
            }
            if let Some((destination_node_id, destination_inode)) = destination {
                self.remove_replaced_directory(
                    &filesystem,
                    0,
                    &mut new_parent,
                    backup_name.as_bytes(),
                    destination_inode,
                )?;
                self.node_ids.remove(new_path);
                self.nodes.remove(&destination_node_id);
            }
            self.rename_node_paths(old_path, new_path);
            return Ok(self.success(request));
        }
        let backup_name = format!(".mochios-orphan-rename-{}", request.request_id);
        if let Some((_, mut destination_inode)) = destination.clone() {
            new_parent
                .link(
                    DirEntryName::try_from(backup_name.as_str()).map_err(|_| EIO)?,
                    &mut destination_inode,
                )
                .map_err(errno)?;
            if let Err(error) = new_parent.unlink(
                DirEntryName::try_from(new_name).map_err(|_| EINVAL)?,
                destination_inode.clone(),
            ) {
                let _ = new_parent.unlink(
                    DirEntryName::try_from(backup_name.as_str()).map_err(|_| EIO)?,
                    destination_inode,
                );
                return Err(errno(error));
            }
        }

        if let Err(error) = new_parent.link(
            DirEntryName::try_from(new_name).map_err(|_| EINVAL)?,
            &mut source_inode,
        ) {
            self.restore_rename_destination(
                &filesystem,
                &mut new_parent,
                new_name,
                &backup_name,
                destination,
            );
            return Err(errno(error));
        }
        if let Err(error) = old_parent.unlink(
            DirEntryName::try_from(old_name).map_err(|_| EINVAL)?,
            source_inode.clone(),
        ) {
            let _ = new_parent.unlink(
                DirEntryName::try_from(new_name).map_err(|_| EINVAL)?,
                source_inode,
            );
            self.restore_rename_destination(
                &filesystem,
                &mut new_parent,
                new_name,
                &backup_name,
                destination,
            );
            return Err(errno(error));
        }

        if let Some((destination_node_id, destination_inode)) = destination {
            self.node_ids.remove(new_path);
            if self
                .opens
                .values()
                .any(|open| open.node_id == destination_node_id)
                && destination_inode.links_count() == 1
                && !self.orphans.contains_key(&destination_node_id)
            {
                self.orphans.insert(
                    destination_node_id,
                    Orphan {
                        parent: new_parent_inode,
                        name: backup_name,
                    },
                );
            } else {
                new_parent
                    .unlink(
                        DirEntryName::try_from(backup_name.as_str()).map_err(|_| EIO)?,
                        destination_inode,
                    )
                    .map_err(errno)?;
                self.nodes.remove(&destination_node_id);
            }
        }
        self.rename_node_paths(old_path, new_path);
        Ok(self.success(request))
    }

    pub fn rename_at(
        &mut self,
        request: protocol::Header,
        payload: &[u8],
        anchors: RenameAnchors,
        credentials: protocol::Credentials,
    ) -> Result<Response, i32> {
        if request.flags & !protocol::RENAME_AT_FLAGS_ALL != 0 {
            return Err(EINVAL);
        }
        if (request.flags & protocol::RENAME_AT_ROOT_ATTACHED != 0)
            != anchors.root_open_id.is_some()
            || (request.flags & protocol::RENAME_AT_OLD_BASE_ATTACHED != 0)
                != anchors.old_base_open_id.is_some()
            || (request.flags & protocol::RENAME_AT_NEW_BASE_ATTACHED != 0)
                != anchors.new_base_open_id.is_some()
        {
            return Err(EINVAL);
        }
        let split = request.mode as usize;
        let (old_path, new_path) = payload.split_at_checked(split).ok_or(EINVAL)?;
        if old_path.is_empty()
            || new_path.is_empty()
            || old_path.len() > protocol::MAX_PATH_LEN
            || new_path.len() > protocol::MAX_PATH_LEN
        {
            return Err(EINVAL);
        }
        let uid = credentials.effective_uid;
        let gid = credentials.effective_gid;
        let groups = credentials.supplementary_groups();
        let (source, filesystem, source_volume) = self.resolve_open_path(
            old_path,
            PathAnchors {
                root_open_id: anchors.root_open_id,
                base_open_id: anchors.old_base_open_id,
            },
            FollowSymlinks::ExcludeFinalComponent,
            uid,
            gid,
            groups,
        )?;
        let (destination, _, destination_volume) = self.resolve_open_path(
            new_path,
            PathAnchors {
                root_open_id: anchors.root_open_id,
                base_open_id: anchors.new_base_open_id,
            },
            FollowSymlinks::ExcludeFinalComponent,
            uid,
            gid,
            groups,
        )?;
        let (mut source_inode, old_parent_inode, old_name) = match source {
            Resolution::Found {
                inode,
                parent: Some((parent, name)),
            } => (inode, parent, name),
            Resolution::Found { parent: None, .. } => return Err(EINVAL),
            Resolution::Missing { .. } => return Err(ENOENT),
        };
        if self
            .namespace
            .as_ref()
            .is_some_and(|namespace| namespace.is_mount_root(source_volume, &source_inode))
        {
            return Err(EBUSY);
        }
        let (new_parent_inode, new_name, destination_inode) = match destination {
            Resolution::Found {
                inode,
                parent: Some((parent, name)),
            } => (parent, name, Some(inode)),
            Resolution::Found { parent: None, .. } => return Err(EINVAL),
            Resolution::Missing { parent, name } => (parent, name, None),
        };
        if destination_inode.as_ref().is_some_and(|inode| {
            self.namespace
                .as_ref()
                .is_some_and(|namespace| namespace.is_mount_root(destination_volume, inode))
        }) {
            return Err(EBUSY);
        }
        if source_volume != destination_volume {
            return Err(EXDEV);
        }
        let old_name = old_name.as_slice();
        let new_name = new_name.as_slice();
        let same_parent = old_parent_inode.index == new_parent_inode.index;
        if same_parent && old_name == new_name {
            return Ok(self.success(request));
        }
        for parent in [&old_parent_inode, &new_parent_inode] {
            let metadata = parent.metadata();
            if !permission_allows(
                metadata.mode(),
                protocol::NODE_TYPE_DIRECTORY,
                metadata.uid(),
                metadata.gid(),
                uid,
                gid,
                groups,
                protocol::ACCESS_AT_WRITE | protocol::ACCESS_AT_EXECUTE,
            ) {
                return Err(EACCES);
            }
        }
        let mut old_parent = Dir::open_inode(&filesystem, old_parent_inode).map_err(errno)?;
        let mut new_parent =
            Dir::open_inode(&filesystem, new_parent_inode.clone()).map_err(errno)?;
        let source_node_id = scoped_node_id(source_volume, &source_inode);
        let source_is_directory = source_inode.file_type().is_dir();
        if destination_inode
            .as_ref()
            .is_some_and(|inode| inode.index == source_inode.index)
        {
            return Ok(self.success(request));
        }
        let destination = match destination_inode {
            Some(inode) if source_is_directory && inode.file_type().is_dir() => {
                if !self.prepare_empty_directory(&filesystem, destination_volume, &inode)? {
                    return Err(ENOTEMPTY);
                }
                Some((scoped_node_id(destination_volume, &inode), inode))
            }
            Some(_) if source_is_directory => return Err(ENOTDIR),
            Some(inode) if inode.file_type().is_dir() => return Err(EISDIR),
            Some(inode) => Some((scoped_node_id(destination_volume, &inode), inode)),
            None => None,
        };
        if source_is_directory {
            old_parent = Dir::open_inode(
                &filesystem,
                Inode::read(&filesystem, old_parent.inode().index).map_err(errno)?,
            )
            .map_err(errno)?;
            new_parent = Dir::open_inode(
                &filesystem,
                Inode::read(&filesystem, new_parent.inode().index).map_err(errno)?,
            )
            .map_err(errno)?;
            if self.directory_is_at_or_below(&filesystem, &source_inode, new_parent_inode)? {
                return Err(EINVAL);
            }
            let backup_name = format!(".mochios-orphan-rename-{}", request.request_id);
            self.stage_rename_destination(
                &filesystem,
                &mut new_parent,
                new_name,
                &backup_name,
                destination.as_ref(),
            )?;
            if let Err(error) = self.move_directory(
                &filesystem,
                &mut old_parent,
                &mut new_parent,
                same_parent,
                old_name,
                new_name,
                source_inode,
            ) {
                self.restore_rename_destination(
                    &filesystem,
                    &mut new_parent,
                    new_name,
                    &backup_name,
                    destination,
                );
                return Err(error);
            }
            if let Some((destination_node_id, destination_inode)) = destination {
                self.remove_replaced_directory(
                    &filesystem,
                    destination_volume,
                    &mut new_parent,
                    backup_name.as_bytes(),
                    destination_inode,
                )?;
                self.forget_node_paths(destination_node_id);
            }
            self.forget_node_paths(source_node_id);
            return Ok(self.success(request));
        }
        let backup_name = format!(".mochios-orphan-rename-{}", request.request_id);
        if let Some((_, mut destination_inode)) = destination.clone() {
            new_parent
                .link(
                    DirEntryName::try_from(backup_name.as_str()).map_err(|_| EIO)?,
                    &mut destination_inode,
                )
                .map_err(errno)?;
            if let Err(error) = new_parent.unlink(
                DirEntryName::try_from(new_name).map_err(|_| EINVAL)?,
                destination_inode.clone(),
            ) {
                let _ = new_parent.unlink(
                    DirEntryName::try_from(backup_name.as_str()).map_err(|_| EIO)?,
                    destination_inode,
                );
                return Err(errno(error));
            }
        }
        if let Err(error) = new_parent.link(
            DirEntryName::try_from(new_name).map_err(|_| EINVAL)?,
            &mut source_inode,
        ) {
            self.restore_rename_destination(
                &filesystem,
                &mut new_parent,
                new_name,
                &backup_name,
                destination,
            );
            return Err(errno(error));
        }
        if let Err(error) = old_parent.unlink(
            DirEntryName::try_from(old_name).map_err(|_| EINVAL)?,
            source_inode.clone(),
        ) {
            let _ = new_parent.unlink(
                DirEntryName::try_from(new_name).map_err(|_| EINVAL)?,
                source_inode,
            );
            self.restore_rename_destination(
                &filesystem,
                &mut new_parent,
                new_name,
                &backup_name,
                destination,
            );
            return Err(errno(error));
        }
        if let Some((destination_node_id, destination_inode)) = destination {
            if self
                .opens
                .values()
                .any(|open| open.node_id == destination_node_id)
                && destination_inode.links_count() == 1
                && !self.orphans.contains_key(&destination_node_id)
            {
                self.orphans.insert(
                    destination_node_id,
                    Orphan {
                        parent: new_parent_inode,
                        name: backup_name,
                    },
                );
            } else {
                new_parent
                    .unlink(
                        DirEntryName::try_from(backup_name.as_str()).map_err(|_| EIO)?,
                        destination_inode,
                    )
                    .map_err(errno)?;
                self.forget_node_paths(destination_node_id);
            }
        }
        self.forget_node_paths(source_node_id);
        Ok(self.success(request))
    }

    pub fn link_at(
        &mut self,
        request: protocol::Header,
        payload: &[u8],
        anchors: RenameAnchors,
        credentials: protocol::Credentials,
    ) -> Result<Response, i32> {
        if request.flags & !protocol::LINK_AT_FLAGS_ALL != 0 {
            return Err(EINVAL);
        }
        if (request.flags & protocol::LINK_AT_ROOT_ATTACHED != 0) != anchors.root_open_id.is_some()
            || (request.flags & protocol::LINK_AT_OLD_BASE_ATTACHED != 0)
                != anchors.old_base_open_id.is_some()
            || (request.flags & protocol::LINK_AT_NEW_BASE_ATTACHED != 0)
                != anchors.new_base_open_id.is_some()
        {
            return Err(EINVAL);
        }
        let split = request.mode as usize;
        let (old_path, new_path) = payload.split_at_checked(split).ok_or(EINVAL)?;
        if old_path.is_empty()
            || new_path.is_empty()
            || old_path.len() > protocol::MAX_PATH_LEN
            || new_path.len() > protocol::MAX_PATH_LEN
        {
            return Err(EINVAL);
        }
        let uid = credentials.effective_uid;
        let gid = credentials.effective_gid;
        let groups = credentials.supplementary_groups();
        let source_follow = if request.flags & protocol::LINK_AT_FOLLOW_SOURCE != 0 {
            FollowSymlinks::All
        } else {
            FollowSymlinks::ExcludeFinalComponent
        };
        let (mut source_inode, _, source_volume) = self.resolve_scoped_inode(
            old_path,
            PathAnchors {
                root_open_id: anchors.root_open_id,
                base_open_id: anchors.old_base_open_id,
            },
            source_follow,
            uid,
            gid,
            groups,
        )?;
        if source_inode.file_type().is_dir() {
            return Err(EPERM);
        }
        let (resolution, filesystem, destination_volume) = self.resolve_open_path(
            new_path,
            PathAnchors {
                root_open_id: anchors.root_open_id,
                base_open_id: anchors.new_base_open_id,
            },
            FollowSymlinks::ExcludeFinalComponent,
            uid,
            gid,
            groups,
        )?;
        let (new_parent_inode, new_name) = match resolution {
            Resolution::Found { .. } => return Err(EEXIST),
            Resolution::Missing { parent, name } => (parent, name),
        };
        if source_volume != destination_volume {
            return Err(EXDEV);
        }
        let metadata = new_parent_inode.metadata();
        if !permission_allows(
            metadata.mode(),
            protocol::NODE_TYPE_DIRECTORY,
            metadata.uid(),
            metadata.gid(),
            uid,
            gid,
            groups,
            protocol::ACCESS_AT_WRITE | protocol::ACCESS_AT_EXECUTE,
        ) {
            return Err(EACCES);
        }
        let mut new_parent = Dir::open_inode(&filesystem, new_parent_inode).map_err(errno)?;
        new_parent
            .link(
                DirEntryName::try_from(new_name.as_slice()).map_err(|_| EINVAL)?,
                &mut source_inode,
            )
            .map_err(errno)?;
        Ok(self.success(request))
    }

    fn forget_node_paths(&mut self, node_id: u64) {
        self.nodes.remove(&node_id);
        self.node_ids
            .retain(|_, known_node_id| *known_node_id != node_id);
    }

    fn restore_rename_destination(
        &self,
        filesystem: &Ext4,
        parent: &mut Dir,
        name: impl AsRef<[u8]>,
        backup_name: &str,
        destination: Option<(u64, ext4plus::inode::Inode)>,
    ) {
        let Some((_, mut inode)) = destination else {
            return;
        };
        let (Ok(name), Ok(backup_name)) = (
            DirEntryName::try_from(name.as_ref()),
            DirEntryName::try_from(backup_name),
        ) else {
            return;
        };
        let is_directory = inode.file_type().is_dir();
        let parent_links = parent.inode().links_count();
        if parent.link(name, &mut inode).is_ok()
            && parent.unlink(backup_name, inode).is_ok()
            && is_directory
        {
            parent.inode_mut().set_links_count(parent_links);
            let _ = parent.inode_mut().write(filesystem);
        }
    }

    fn stage_rename_destination(
        &self,
        filesystem: &Ext4,
        parent: &mut Dir,
        name: impl AsRef<[u8]>,
        backup_name: &str,
        destination: Option<&(u64, Inode)>,
    ) -> Result<(), i32> {
        let Some((_, original_inode)) = destination else {
            return Ok(());
        };
        let mut inode = original_inode.clone();
        let is_directory = inode.file_type().is_dir();
        let parent_links = parent.inode().links_count();
        let backup_name = DirEntryName::try_from(backup_name).map_err(|_| EIO)?;
        parent.link(backup_name, &mut inode).map_err(errno)?;
        if let Err(error) = parent.unlink(
            DirEntryName::try_from(name.as_ref()).map_err(|_| EINVAL)?,
            inode.clone(),
        ) {
            let _ = parent.unlink(backup_name, inode);
            if is_directory {
                parent.inode_mut().set_links_count(parent_links);
                let _ = parent.inode_mut().write(filesystem);
            }
            return Err(errno(error));
        }
        if is_directory {
            parent.inode_mut().set_links_count(parent_links);
            if let Err(error) = parent.inode_mut().write(filesystem) {
                self.restore_rename_destination(
                    filesystem,
                    parent,
                    name,
                    backup_name.as_str().map_err(|_| EIO)?,
                    Some((0, original_inode.clone())),
                );
                return Err(errno(error));
            }
        }
        Ok(())
    }

    fn move_directory(
        &self,
        filesystem: &Ext4,
        old_parent: &mut Dir,
        new_parent: &mut Dir,
        same_parent: bool,
        old_name: impl AsRef<[u8]>,
        new_name: impl AsRef<[u8]>,
        mut source_inode: Inode,
    ) -> Result<(), i32> {
        let new_name = DirEntryName::try_from(new_name.as_ref()).map_err(|_| EINVAL)?;
        let old_name = DirEntryName::try_from(old_name.as_ref()).map_err(|_| EINVAL)?;
        if same_parent {
            let parent_links = new_parent.inode().links_count();
            new_parent
                .link(new_name, &mut source_inode)
                .map_err(errno)?;
            new_parent.inode_mut().set_links_count(parent_links);
            if let Err(error) = new_parent.inode_mut().write(filesystem) {
                let _ = new_parent.unlink(new_name, source_inode);
                new_parent.inode_mut().set_links_count(parent_links);
                let _ = new_parent.inode_mut().write(filesystem);
                return Err(errno(error));
            }
            if let Err(error) = old_parent.unlink(old_name, source_inode.clone()) {
                let _ = new_parent.unlink(new_name, source_inode);
                return Err(errno(error));
            }
            return Ok(());
        }

        if source_inode.links_count() == 0 {
            return Err(EIO);
        }
        let old_parent_links = old_parent.inode().links_count();
        let new_parent_links = new_parent.inode().links_count();
        new_parent
            .link(new_name, &mut source_inode)
            .map_err(errno)?;
        let mut moved_directory =
            Dir::open_inode(filesystem, source_inode.clone()).map_err(errno)?;
        if let Err(error) = moved_directory.set_parent(new_parent.inode()) {
            let _ = new_parent.unlink(new_name, source_inode);
            new_parent.inode_mut().set_links_count(new_parent_links);
            let _ = new_parent.inode_mut().write(filesystem);
            return Err(errno(error));
        }

        let mut moved_inode = match old_parent.unlink(old_name, source_inode.clone()) {
            Ok(Some(inode)) => inode,
            Ok(None) => return Err(EIO),
            Err(error) => {
                let _ = moved_directory.set_parent(old_parent.inode());
                let _ = new_parent.unlink(new_name, source_inode);
                new_parent.inode_mut().set_links_count(new_parent_links);
                let _ = new_parent.inode_mut().write(filesystem);
                return Err(errno(error));
            }
        };
        let Some(old_parent_links) = old_parent_links.checked_sub(1) else {
            let _ = old_parent.link(old_name, &mut moved_inode);
            let _ = moved_directory.set_parent(old_parent.inode());
            let _ = new_parent.unlink(new_name, moved_inode);
            new_parent.inode_mut().set_links_count(new_parent_links);
            let _ = new_parent.inode_mut().write(filesystem);
            return Err(EIO);
        };
        old_parent.inode_mut().set_links_count(old_parent_links);
        if let Err(error) = old_parent.inode_mut().write(filesystem) {
            let _ = old_parent.link(old_name, &mut moved_inode);
            let _ = moved_directory.set_parent(old_parent.inode());
            let _ = new_parent.unlink(new_name, moved_inode);
            new_parent.inode_mut().set_links_count(new_parent_links);
            let _ = new_parent.inode_mut().write(filesystem);
            return Err(errno(error));
        }
        Ok(())
    }

    fn remove_replaced_directory(
        &mut self,
        filesystem: &Ext4,
        volume: u32,
        parent: &mut Dir,
        name: &[u8],
        mut inode: Inode,
    ) -> Result<(), i32> {
        let node_id = scoped_node_id(volume, &inode);
        let retained = self.directory_is_referenced(node_id);
        if retained {
            self.removed_directories.try_reserve(1).map_err(|_| ENOMEM)?;
        }
        let original_parent_links = parent.inode().links_count();
        let parent_links = original_parent_links.checked_sub(1).ok_or(EIO)?;
        parent.inode_mut().set_links_count(parent_links);
        parent.inode_mut().write(filesystem).map_err(errno)?;
        let original_links = inode.links_count();
        inode.set_links_count(1);
        if let Err(error) = inode.write(filesystem) {
            parent.inode_mut().set_links_count(original_parent_links);
            let _ = parent.inode_mut().write(filesystem);
            return Err(errno(error));
        }
        let name = DirEntryName::try_from(name).map_err(|_| EINVAL)?;
        let result = if retained {
            parent.unlink_retained(name, inode.clone()).map(Some)
        } else {
            parent.unlink(name, inode.clone())
        };
        let detached = match result {
            Ok(detached) => detached,
            Err(error) => {
                inode.set_links_count(original_links);
                let _ = inode.write(filesystem);
                parent.inode_mut().set_links_count(original_parent_links);
                let _ = parent.inode_mut().write(filesystem);
                return Err(errno(error));
            }
        };
        if let Some(inode) = detached {
            self.removed_directories.insert(
                node_id,
                removed_directories::RetainedDirectory {
                    filesystem: filesystem.clone(),
                    inode,
                    parent: scoped_node_id(volume, parent.inode()),
                },
            );
        }
        Ok(())
    }

    fn prepare_empty_directory(
        &mut self,
        filesystem: &Ext4,
        volume: u32,
        inode: &Inode,
    ) -> Result<bool, i32> {
        let mut directory = Dir::open_inode(filesystem, inode.clone()).map_err(errno)?;
        let mut retained = Vec::new();
        for entry in directory.read_dir().map_err(errno)? {
            let entry = entry.map_err(errno)?;
            if entry.file_name() != "." && entry.file_name() != ".." {
                let node_id = (u64::from(volume) << 32) | u64::from(entry.inode.get());
                let private = self.orphans.get(&node_id).is_some_and(|orphan| {
                    orphan.parent.index == inode.index
                        && orphan.name.as_bytes() == entry.file_name().as_ref()
                });
                if !private {
                    return Ok(false);
                }
                retained.try_reserve(1).map_err(|_| ENOMEM)?;
                retained.push(node_id);
            }
        }
        if retained.is_empty() {
            return Ok(true);
        }
        let mut root = Dir::open_inode(filesystem, filesystem.read_root_inode().map_err(errno)?)
            .map_err(errno)?;
        if root.inode().index == inode.index {
            return Ok(false);
        }
        // Rename's existing rollback transaction keeps its backup in the
        // destination parent. Evacuate only exact registered private entries
        // before that logically-empty parent is removed or replaced.
        for node_id in retained {
            let old = self.orphans.get(&node_id).cloned().ok_or(EIO)?;
            let name = DirEntryName::try_from(old.name.as_str()).map_err(|_| EIO)?;
            let mut target = directory.get_entry(name).map_err(errno)?;
            if scoped_node_id(volume, &target) != node_id {
                return Err(EIO);
            }
            let moved = Self::create_retention_link(filesystem, &mut root, &mut target, node_id)?;
            if let Err(error) = directory.unlink(name, target.clone()) {
                root.unlink(
                    DirEntryName::try_from(moved.name.as_str()).map_err(|_| EIO)?,
                    target,
                )
                .map_err(errno)?;
                return Err(errno(error));
            }
            // Replacing an existing record cannot allocate or lose the pin.
            *self.orphans.get_mut(&node_id).ok_or(EIO)? = moved;
        }
        Ok(true)
    }

    fn directory_is_at_or_below(
        &self,
        filesystem: &Ext4,
        ancestor: &Inode,
        mut directory: Inode,
    ) -> Result<bool, i32> {
        for _ in 0..protocol::MAX_PATH_LEN {
            if directory.index == ancestor.index {
                return Ok(true);
            }
            let parent = Dir::open_inode(filesystem, directory.clone())
                .map_err(errno)?
                .get_entry(DirEntryName::try_from("..").map_err(|_| EIO)?)
                .map_err(errno)?;
            if parent.index == directory.index {
                return Ok(false);
            }
            directory = parent;
        }
        Err(EIO)
    }

    fn truncate(&mut self, request: protocol::Header) -> Result<Response, i32> {
        if request.flags & !protocol::TRUNCATE_GROWTH_BOUNDED != 0 {
            return Err(EINVAL);
        }
        let open = self.opens.get(&request.open_id).ok_or(EBADF)?;
        if open.file.is_none() {
            return Err(EISDIR);
        }
        self.truncate_scoped_inode(
            open.inode.clone(),
            open.filesystem.clone(),
            open.node_id,
            request.offset,
            (request.flags & protocol::TRUNCATE_GROWTH_BOUNDED != 0).then_some(request.node_id),
        )?;
        Ok(self.success(request))
    }

    fn truncate_scoped_inode(
        &mut self,
        inode: Inode,
        filesystem: Ext4,
        node_id: u64,
        length: u64,
        growth_ceiling: Option<u64>,
    ) -> Result<Inode, i32> {
        // OpenFile.inode may predate writes through another description. Read
        // the authoritative size under this service's mutation serialization,
        // not in a separate stat RPC or from the cached open-time metadata.
        let current = Inode::read(&filesystem, inode.index).map_err(errno)?;
        // These are known non-mutating failures. Reject them before marking
        // native aliases in flight; immutable System reads must stay usable.
        if filesystem.is_read_only() {
            return Err(EROFS);
        }
        if current.flags().contains(InodeFlags::IMMUTABLE) {
            return Err(EPERM);
        }
        if let Some(ceiling) = growth_ceiling {
            if length > current.metadata().len() && length > ceiling {
                return Err(protocol::ERROR_GROWTH_LIMIT);
            }
        }
        let old_length = current.metadata().len();
        let identity = self
            .opens
            .values()
            .find(|open| open.node_id == node_id)
            .map(|open| open.memory_object_id);
        // Mutate the backing exactly once. Repeating truncate on each File's
        // stale inode/extent cache can extend a previously empty description
        // over live data and zero it, or free the same extents more than once.
        let mut file = File::open_inode(&filesystem, current).map_err(errno)?;
        let mut update = identity
            .map(|identity| self.prepare_memory_update(identity, old_length, length))
            .transpose()?;
        if let Some(prepared) = update.as_mut() {
            if let Err(error) = prepared.begin() {
                if self.memory_admission.is_some() {
                    if error == 11 {
                        // Failed BEGIN is still pre-storage. Release the
                        // prepared transaction before queueing a new position;
                        // native deferred cleanup restores its old mappings.
                        drop(update.take());
                        let ticket = self
                            .memory_updates
                            .as_ref()
                            .ok_or(ENOTSUP)?
                            .queue(identity.ok_or(EIO)?)?;
                        self.memory_admission.as_mut().ok_or(EIO)?.waiting = Some(ticket);
                        return Err(protocol::ERROR_MEMORY_ADMISSION_BUSY);
                    }
                    return Err(error);
                }
                return Err(crate::memory_updates::admission_error(error));
            }
        }
        // A backend error may follow partial writes. Never interpret it as
        // "unchanged": dropping an in-flight owner quarantines all aliases.
        file.truncate(length).map_err(errno)?;
        let updated = file.into_inode();
        for open in self.opens.values_mut() {
            if open.node_id == node_id {
                open.file = Some(File::open_inode(&filesystem, updated.clone()).map_err(errno)?);
                open.inode = updated.clone();
            }
        }
        if let Some(update) = update.as_mut() {
            update.publish()?;
        }
        Ok(updated)
    }

    fn chmod_scoped_inode(
        &mut self,
        inode: Inode,
        filesystem: Ext4,
        node_id: u64,
        permissions: u16,
    ) -> Result<(), i32> {
        let mut inode = Inode::read(&filesystem, inode.index).map_err(errno)?;
        let file_type = inode.mode().bits() & 0xf000;
        let current = self.metadata_change_time(&inode, &filesystem)?;
        inode
            .set_mode(InodeMode::from_bits_retain(file_type | permissions))
            .map_err(errno)?;
        inode
            .set_signed_timestamps(None, None, Some(current))
            .map_err(timestamp_operations::timestamp_error)?;
        inode.write(&filesystem).map_err(errno)?;
        for open in self.opens.values_mut() {
            if open.node_id == node_id {
                open.inode = inode.clone();
                if let Some(file) = &mut open.file {
                    *file.inode_mut() = inode.clone();
                }
            }
        }
        Ok(())
    }

    fn chown_scoped_inode(
        &mut self,
        inode: Inode,
        filesystem: Ext4,
        node_id: u64,
        uid: Option<u32>,
        gid: Option<u32>,
        clear_set_id: bool,
    ) -> Result<(), i32> {
        fn update(
            filesystem: &Ext4,
            inode: &mut Inode,
            uid: Option<u32>,
            gid: Option<u32>,
            clear_set_id: bool,
            current: ext4plus::inode::InodeTimestamp,
        ) -> Result<(), i32> {
            if let Some(uid) = uid {
                inode.set_uid(uid);
            }
            if let Some(gid) = gid {
                inode.set_gid(gid);
            }
            if clear_set_id {
                let mode = inode.mode().bits() & !0o6000;
                inode
                    .set_mode(InodeMode::from_bits_retain(mode))
                    .map_err(errno)?;
            }
            inode
                .set_signed_timestamps(None, None, Some(current))
                .map_err(timestamp_operations::timestamp_error)?;
            inode.write(filesystem).map_err(errno)
        }

        let mut inode = Inode::read(&filesystem, inode.index).map_err(errno)?;
        let current = self.metadata_change_time(&inode, &filesystem)?;
        update(&filesystem, &mut inode, uid, gid, clear_set_id, current)?;
        for open in self.opens.values_mut() {
            if open.node_id == node_id {
                open.inode = inode.clone();
                if let Some(file) = &mut open.file {
                    *file.inode_mut() = inode.clone();
                }
            }
        }
        Ok(())
    }

    pub fn truncate_handle(
        &mut self,
        mut request: protocol::Header,
        open_id: u64,
    ) -> Result<Response, i32> {
        if let Some(open) = self.opens.device(open_id) {
            return Err(if open.null.is_some() { EINVAL } else { EISDIR });
        }
        request.open_id = open_id;
        self.truncate(request)
    }

    pub fn chmod_handle(
        &mut self,
        request: protocol::Header,
        open_id: u64,
        credentials: protocol::Credentials,
    ) -> Result<Response, i32> {
        if request.flags != 0 || request.mode & !0o7777 != 0 {
            return Err(EINVAL);
        }
        if self.opens.device(open_id).is_some() {
            // Device nodes live on the immutable service-owned filesystem;
            // their descriptions are valid, but their metadata is not mutable.
            return Err(EROFS);
        }
        let effective_uid = credentials.effective_uid;
        let effective_gid = credentials.effective_gid;
        let groups = credentials.supplementary_groups();
        let open = self.opens.get(&open_id).ok_or(EBADF)?;
        let inode = open.inode.clone();
        let filesystem = open.filesystem.clone();
        let node_id = open.node_id;
        let metadata = inode.metadata();
        if effective_uid != 0 && effective_uid != metadata.uid() {
            return Err(EPERM);
        }
        let mut permissions = request.mode as u16;
        if effective_uid != 0
            && effective_gid != metadata.gid()
            && !groups.contains(&metadata.gid())
        {
            permissions &= !0o2000;
        }
        self.chmod_scoped_inode(inode, filesystem, node_id, permissions)?;
        Ok(self.success(request))
    }

    pub fn chown_handle(
        &mut self,
        request: protocol::Header,
        open_id: u64,
        credentials: protocol::Credentials,
    ) -> Result<Response, i32> {
        if request.flags != 0 {
            return Err(EINVAL);
        }
        if self.opens.device(open_id).is_some() {
            return Err(EROFS);
        }
        let effective_uid = credentials.effective_uid;
        let effective_gid = credentials.effective_gid;
        let groups = credentials.supplementary_groups();
        let requested_uid = request.node_id as u32;
        let requested_gid = (request.node_id >> 32) as u32;
        let open = self.opens.get(&open_id).ok_or(EBADF)?;
        let inode = open.inode.clone();
        let filesystem = open.filesystem.clone();
        let node_id = open.node_id;
        let metadata = inode.metadata();
        if effective_uid != 0
            && (effective_uid != metadata.uid()
                || requested_uid != u32::MAX && requested_uid != metadata.uid()
                || requested_gid != u32::MAX
                    && requested_gid != metadata.gid()
                    && requested_gid != effective_gid
                    && !groups.contains(&requested_gid))
        {
            return Err(EPERM);
        }
        let uid = (requested_uid != u32::MAX).then_some(requested_uid);
        let gid = (requested_gid != u32::MAX).then_some(requested_gid);
        self.chown_scoped_inode(
            inode,
            filesystem,
            node_id,
            uid,
            gid,
            uid.is_some() || gid.is_some(),
        )?;
        Ok(self.success(request))
    }

    pub fn sync_handle(&self, request: protocol::Header, open_id: u64) -> Result<Response, i32> {
        self.provider_sync(open_id)?;
        Ok(self.success(request))
    }

    pub fn get_flags_handle(
        &self,
        request: protocol::Header,
        open_id: u64,
    ) -> Result<Response, i32> {
        let mut response = self.success(request);
        if let Some(open) = self.opens.device(open_id) {
            response.header.flags = open.null.as_ref()
                .map_or(open.directory_flags, |null| null.flags());
            return Ok(response);
        }
        response.header.flags = self.opens.get(&open_id).ok_or(EBADF)?.status_flags;
        Ok(response)
    }

    pub fn set_flags_handle(
        &mut self,
        request: protocol::Header,
        open_id: u64,
    ) -> Result<Response, i32> {
        self.update_flags_handle(request, open_id, protocol::OPEN_STATUS_FLAGS_ALL)
    }

    /// Runs under the filesystem worker's exclusive borrow of the OFD table.
    /// No RPC or pathname lookup separates inspection from modification.
    pub fn update_flags_handle(
        &mut self,
        request: protocol::Header,
        open_id: u64,
        mask: u32,
    ) -> Result<Response, i32> {
        if mask & !protocol::OPEN_STATUS_FLAGS_ALL != 0 || request.flags & !mask != 0 {
            return Err(EINVAL);
        }
        let update = |old: u32| (old & !mask) | request.flags;
        if let Some(open) = self.opens.device_mut(open_id) {
            if let Some(null) = &mut open.null {
                null.set_flags(update(null.flags()))?;
            } else {
                open.directory_flags = update(open.directory_flags);
            }
            return Ok(self.success(request));
        }
        let open = self.opens.get_mut(&open_id).ok_or(EBADF)?;
        open.status_flags = update(open.status_flags);
        Ok(self.success(request))
    }

    fn read_link(&self, request: protocol::Header) -> Result<Response, i32> {
        let path = self.nodes.get(&request.node_id).ok_or(ENOENT)?;
        let target = self.fs.read_link(path.as_str()).map_err(errno)?;
        let payload = target.as_ref().to_vec();
        if payload.len() > protocol::MAX_IO_LEN {
            return Err(EFBIG);
        }
        let mut response = self.success(request);
        response.header.length = payload.len() as u32;
        response.payload = payload;
        Ok(response)
    }

    fn set_attr(&self, request: protocol::Header, payload: &[u8]) -> Result<Response, i32> {
        let path = decode_path(payload)?;
        let supported = protocol::SETATTR_MODE | protocol::SETATTR_UID | protocol::SETATTR_GID;
        if request.flags == 0 || request.flags & !supported != 0 {
            return Err(EINVAL);
        }
        let mut inode = self
            .fs
            .path_to_inode(path.try_into().map_err(|_| EINVAL)?, FollowSymlinks::All)
            .map_err(errno)?;
        if request.flags & protocol::SETATTR_MODE != 0 {
            let file_type = inode.mode().bits() & 0xf000;
            let permissions = (request.mode as u16) & 0x0fff;
            inode
                .set_mode(InodeMode::from_bits_retain(file_type | permissions))
                .map_err(errno)?;
        }
        if request.flags & protocol::SETATTR_UID != 0 {
            inode.set_uid(request.offset as u32);
        }
        if request.flags & protocol::SETATTR_GID != 0 {
            inode.set_gid((request.offset >> 32) as u32);
        }
        inode.write(&self.fs).map_err(errno)?;
        Ok(self.metadata_response(request, request.node_id, inode.metadata()))
    }

    fn metadata_response(
        &self,
        request: protocol::Header,
        node_id: u64,
        metadata: Metadata,
    ) -> Response {
        let mut response = self.success(request);
        response.header.node_id = node_id;
        response.header.offset = metadata.len();
        response.header.mode = u32::from(metadata.mode());
        response.header.flags = node_type(metadata.file_type());
        response.payload.resize(protocol::METADATA_LEN, 0);
        protocol::encode_metadata(
            protocol::NodeMetadata {
                uid: metadata.uid(),
                gid: metadata.gid(),
            },
            &mut response.payload,
        )
        .expect("fixed-size metadata response");
        response.header.length = response.payload.len() as u32;
        response
    }

    fn node_status_response(
        &self,
        request: protocol::Header,
        node_id: u64,
        metadata: Metadata,
    ) -> Response {
        let physical_links = u32::from(metadata.links_count);
        let link_count = if self.orphans.contains_key(&node_id) {
            match physical_links.checked_sub(1) {
                Some(links) => links,
                None => return self.error(request, EIO),
            }
        } else {
            physical_links
        };
        let Some((atime_seconds, atime_nanoseconds)) = inode_time::decode(metadata.atime) else {
            return self.error(request, EIO);
        };
        let Some((mtime_seconds, mtime_nanoseconds)) = inode_time::decode(metadata.mtime) else {
            return self.error(request, EIO);
        };
        let Some((ctime_seconds, ctime_nanoseconds)) = inode_time::decode(metadata.ctime) else {
            return self.error(request, EIO);
        };
        let mut response = self.success(request);
        response.payload.resize(protocol::NODE_STATUS_LEN, 0);
        let status = protocol::NodeStatus {
            // Node identity, not a caller-selected request field, identifies
            // the backing volume (also for delegated Handles).
            device: node_id >> 32,
            node_id,
            size: metadata.len(),
            blocks: metadata.len().div_ceil(512),
            block_size: 4096,
            kind: node_type(metadata.file_type()),
            mode: u32::from(metadata.mode()),
            uid: metadata.uid(),
            gid: metadata.gid(),
            link_count,
            special_device: 0,
            access_time_seconds: atime_seconds,
            access_time_nanoseconds: atime_nanoseconds,
            modification_time_seconds: mtime_seconds,
            modification_time_nanoseconds: mtime_nanoseconds,
            change_time_seconds: ctime_seconds,
            change_time_nanoseconds: ctime_nanoseconds,
        };
        protocol::encode_node_status(status, &mut response.payload)
            .expect("fixed-size node status response");
        response.header.length = response.payload.len() as u32;
        response
    }

    fn success(&self, request: protocol::Header) -> Response {
        Response {
            header: protocol::Header {
                opcode: protocol::OP_STATUS,
                request_id: request.request_id,
                mount_id: request.mount_id,
                status: 0,
                ..protocol::Header::default()
            },
            payload: Vec::new(),
        }
    }

    fn error(&self, request: protocol::Header, errno: i32) -> Response {
        let mut response = self.success(request);
        response.header.status = -errno;
        response
    }

    fn remember_node(&mut self, path: &str, follow: FollowSymlinks) -> Result<u64, i32> {
        if let Some(node_id) = self.node_ids.get(path) {
            return Ok(*node_id);
        }
        let inode = self
            .fs
            .path_to_inode(path.try_into().map_err(|_| EINVAL)?, follow)
            .map_err(errno)?;
        let node_id = u64::from(inode.index.get());
        self.remember_known_node(path, node_id);
        Ok(node_id)
    }

    fn remember_known_node(&mut self, path: &str, node_id: u64) {
        self.nodes.insert(node_id, path.to_owned());
        self.node_ids.insert(path.to_owned(), node_id);
    }

    fn rename_node_paths(&mut self, old_path: &str, new_path: &str) {
        let updates: Vec<(String, String, u64)> = self
            .node_ids
            .iter()
            .filter_map(|(path, node_id)| {
                let suffix = path.strip_prefix(old_path)?;
                if !suffix.is_empty() && !suffix.starts_with('/') {
                    return None;
                }
                Some((path.clone(), format!("{new_path}{suffix}"), *node_id))
            })
            .collect();
        for (old, new, node_id) in updates {
            self.node_ids.remove(&old);
            self.node_ids.insert(new.clone(), node_id);
            self.nodes.insert(node_id, new);
        }
    }
}

fn decode_path(payload: &[u8]) -> Result<&str, i32> {
    if payload.is_empty() || payload.len() > protocol::MAX_PATH_LEN || payload.contains(&0) {
        return Err(EINVAL);
    }
    let path = std::str::from_utf8(payload).map_err(|_| EINVAL)?;
    if !path.starts_with('/') {
        return Err(EINVAL);
    }
    Ok(path)
}

fn split_parent(path: &str) -> Result<(&str, &str), i32> {
    let trimmed = path.strip_suffix('/').unwrap_or(path);
    if trimmed.is_empty() || trimmed == "/" {
        return Err(EINVAL);
    }
    let separator = trimmed.rfind('/').ok_or(EINVAL)?;
    let name = &trimmed[separator + 1..];
    if name.is_empty() || name == "." || name == ".." {
        return Err(EINVAL);
    }
    let parent = if separator == 0 {
        "/"
    } else {
        &trimmed[..separator]
    };
    Ok((parent, name))
}

fn joined_path(parent: &str, name: &str) -> String {
    match name {
        "." => parent.to_owned(),
        ".." => split_parent(parent)
            .map(|(grandparent, _)| grandparent.to_owned())
            .unwrap_or_else(|_| "/".to_owned()),
        _ if parent == "/" => format!("/{name}"),
        _ => format!("{}/{name}", parent.trim_end_matches('/')),
    }
}

impl path_walk::Backend for FilesystemService {
    type Node = Inode;
    fn is_directory(&self, node: &Inode) -> bool {
        node.file_type().is_dir()
    }
    fn is_symlink(&self, node: &Inode) -> bool {
        node.file_type().is_symlink()
    }
    fn search(&self, node: &Inode, credentials: path_walk::Credentials<'_>) -> Result<(), i32> {
        let metadata = node.metadata();
        if permission_allows(
            metadata.mode(),
            protocol::NODE_TYPE_DIRECTORY,
            metadata.uid(),
            metadata.gid(),
            credentials.uid,
            credentials.gid,
            credentials.groups,
            protocol::ACCESS_AT_EXECUTE,
        ) {
            Ok(())
        } else {
            Err(EACCES)
        }
    }
    fn child(&self, node: &Inode, name: &[u8]) -> Result<Inode, i32> {
        Dir::open_inode(&self.fs, node.clone())
            .map_err(errno)?
            .get_entry(DirEntryName::try_from(name).map_err(|_| EINVAL)?)
            .map_err(errno)
    }
    fn symlink(&self, node: &Inode) -> Result<Vec<u8>, i32> {
        Ok(node
            .symlink_target(&self.fs)
            .map_err(errno)?
            .as_ref()
            .to_vec())
    }
    fn ancestry(&self, root: &Inode, base: Inode) -> Result<Vec<Inode>, i32> {
        self.ancestry_from_root(root, base)
    }
}

fn scoped_node_id(volume: u32, inode: &Inode) -> u64 {
    (u64::from(volume) << 32) | u64::from(inode.index.get())
}

fn node_type(file_type: FileType) -> u32 {
    if file_type.is_regular_file() {
        protocol::NODE_TYPE_REGULAR
    } else if file_type.is_dir() {
        protocol::NODE_TYPE_DIRECTORY
    } else if file_type.is_symlink() {
        protocol::NODE_TYPE_SYMLINK
    } else if file_type.is_socket() {
        protocol::NODE_TYPE_SOCKET
    } else {
        protocol::NODE_TYPE_SPECIAL
    }
}

pub fn permission_allows(
    mode: u16,
    kind: u32,
    owner_uid: u32,
    owner_gid: u32,
    uid: u32,
    gid: u32,
    supplementary_groups: &[u32],
    requested: u32,
) -> bool {
    if requested == 0 {
        return true;
    }
    let mode = u32::from(mode);
    if uid == 0 {
        return requested & protocol::ACCESS_AT_EXECUTE == 0
            || kind == protocol::NODE_TYPE_DIRECTORY
            || mode & 0o111 != 0;
    }
    let granted = if uid == owner_uid {
        (mode >> 6) & 0o7
    } else if gid == owner_gid || supplementary_groups.contains(&owner_gid) {
        (mode >> 3) & 0o7
    } else {
        mode & 0o7
    };
    requested & !granted == 0
}

/// A description owns a cursor, not a private version of its inode or extents.
/// Called within the provider worker's serialized operation, without RPC.
fn refresh_provider_file(open: &mut OpenFile) -> Result<(), i32> {
    if open.file.is_none() {
        return Err(EISDIR);
    }
    let inode = Inode::read(&open.filesystem, open.inode.index).map_err(errno)?;
    open.file = Some(File::open_inode(&open.filesystem, inode.clone()).map_err(errno)?);
    open.inode = inode;
    Ok(())
}

pub(crate) fn errno(error: Ext4Error) -> i32 {
    match error {
        Ext4Error::NotFound => ENOENT,
        Ext4Error::IsADirectory => EISDIR,
        Ext4Error::NotADirectory => ENOTDIR,
        Ext4Error::Readonly | Ext4Error::Encrypted => EACCES,
        Ext4Error::NoSpace => ENOSPC,
        Ext4Error::AlreadyExists => EEXIST,
        Ext4Error::FileTooLarge => EFBIG,
        Ext4Error::MalformedPath | Ext4Error::NotAbsolute | Ext4Error::NotASymlink => EINVAL,
        _ => EIO,
    }
}
