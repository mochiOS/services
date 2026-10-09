use std::collections::{HashMap, VecDeque};
use std::time::Duration;

use ext4plus::dir::Dir;
use ext4plus::error::Ext4Error;
use ext4plus::file::File;
use ext4plus::inode::{Inode, InodeCreationOptions, InodeFlags, InodeMode};
use ext4plus::path::{Component, Path, PathBuf};
use ext4plus::{DirEntryName, Ext4, FileType, FollowSymlinks, Metadata};
use mochios_filesystem_protocol as protocol;

const EIO: i32 = 5;
const EPERM: i32 = 1;
const ENOENT: i32 = 2;
const EBADF: i32 = 9;
const EACCES: i32 = 13;
const EEXIST: i32 = 17;
const EINVAL: i32 = 22;
const ENOSPC: i32 = 28;
const ENAMETOOLONG: i32 = 36;
const EISDIR: i32 = 21;
const ENOTDIR: i32 = 20;
const ENOSYS: i32 = 38;
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
    nodes: HashMap<u64, String>,
    node_ids: HashMap<String, u64>,
    opens: HashMap<u64, OpenFile>,
    orphans: HashMap<u64, Orphan>,
    next_open_id: u64,
}

struct OpenFile {
    node_id: u64,
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
}

#[derive(Clone)]
struct Orphan {
    parent: Inode,
    name: String,
}

impl FilesystemService {
    pub fn new(fs: Ext4) -> Self {
        let mut nodes = HashMap::new();
        let mut node_ids = HashMap::new();
        // ext4 reserves inode 2 for the filesystem root.
        nodes.insert(2, "/".to_owned());
        node_ids.insert("/".to_owned(), 2);
        Self {
            fs,
            nodes,
            node_ids,
            opens: HashMap::new(),
            orphans: HashMap::new(),
            next_open_id: 1,
        }
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
            | protocol::OP_CHOWN_HANDLE => Err(EINVAL),
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
                memory_object_id,
                inode,
                file: Some(file),
                offset: 0,
                status_flags: 0,
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
        let (root, base) = self.resolve_anchors(payload, anchors)?;
        let exclusive_create = request.flags
            & (protocol::OPEN_AT_CREATE | protocol::OPEN_AT_EXCLUSIVE)
            == (protocol::OPEN_AT_CREATE | protocol::OPEN_AT_EXCLUSIVE);
        let follow = if request.flags & protocol::OPEN_AT_NOFOLLOW != 0 || exclusive_create {
            FollowSymlinks::ExcludeFinalComponent
        } else {
            FollowSymlinks::All
        };
        let (inode, created) =
            match self.resolve_path_at(root, base, payload, follow, uid, gid, groups)? {
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
                        self.create_regular_at(parent, &name, request.mode, uid, gid, groups)?,
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
        let node_id = u64::from(inode.index.get());
        let mut file = if kind.is_dir() {
            None
        } else {
            Some(File::open_inode(&self.fs, inode.clone()).map_err(errno)?)
        };
        if request.flags & protocol::OPEN_AT_TRUNCATE != 0 {
            file.as_mut().ok_or(EISDIR)?.truncate(0).map_err(errno)?;
        }
        let open_id = self.next_open_id;
        self.next_open_id = self.next_open_id.checked_add(1).ok_or(EIO)?;
        let memory_object_id = self.memory_identity_for(node_id, open_id);
        self.opens.insert(
            open_id,
            OpenFile {
                node_id,
                memory_object_id,
                inode,
                file,
                offset: 0,
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
        let mut directory = Dir::open_inode(&self.fs, parent).map_err(errno)?;
        let name = DirEntryName::try_from(name).map_err(|_| EINVAL)?;
        match directory.get_entry(name) {
            Ok(_) => return Err(EEXIST),
            Err(Ext4Error::NotFound) => {}
            Err(error) => return Err(errno(error)),
        }
        let mut inode = self
            .fs
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
        let (root, base) = self.resolve_anchors(payload, anchors)?;
        let (parent, name) = match self.resolve_path_at(
            root,
            base,
            payload,
            FollowSymlinks::ExcludeFinalComponent,
            uid,
            gid,
            groups,
        )? {
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
        let mut parent = Dir::open_inode(&self.fs, parent).map_err(errno)?;
        let inode = self
            .fs
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
        let mut directory = Dir::init(self.fs.clone(), inode, parent_index).map_err(errno)?;
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
        let (root, base) = self.resolve_anchors(payload, anchors)?;
        let (inode, parent, name) = match self.resolve_path_at(
            root,
            base,
            payload,
            FollowSymlinks::ExcludeFinalComponent,
            uid,
            gid,
            groups,
        )? {
            Resolution::Found {
                inode,
                parent: Some((parent, name)),
            } => (inode, parent, name),
            Resolution::Found { parent: None, .. } => return Err(EINVAL),
            Resolution::Missing { .. } => return Err(ENOENT),
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
        self.unlink_entry(
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
        let (root, base) = self.resolve_anchors(payload, anchors)?;
        let inode =
            self.resolve_inode_at(root, base, payload, FollowSymlinks::All, uid, gid, groups)?;
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
        self.truncate_inode(inode, request.open_id)?;
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
        let (root, base) = self.resolve_anchors(link_path, anchors)?;
        let (parent, name) = match self.resolve_path_at(
            root,
            base,
            link_path,
            FollowSymlinks::ExcludeFinalComponent,
            uid,
            gid,
            groups,
        )? {
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
        let mut parent = Dir::open_inode(&self.fs, parent).map_err(errno)?;
        self.fs
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
        let uid = credentials.effective_uid;
        let gid = credentials.effective_gid;
        let groups = credentials.supplementary_groups();
        let (root, base) = self.resolve_anchors(payload, anchors)?;
        let inode = self.resolve_inode_at(
            root,
            base,
            payload,
            FollowSymlinks::ExcludeFinalComponent,
            uid,
            gid,
            groups,
        )?;
        if !inode.file_type().is_symlink() {
            return Err(EINVAL);
        }
        let target = inode.symlink_target(&self.fs).map_err(errno)?;
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
        let (root, base) = self.resolve_anchors(payload, anchors)?;
        let inode =
            self.resolve_inode_at(root, base, payload, FollowSymlinks::All, uid, gid, groups)?;
        let metadata = inode.metadata();
        if uid != 0 && uid != metadata.uid() {
            return Err(EPERM);
        }
        let mut permissions = request.mode as u16;
        if uid != 0 && gid != metadata.gid() && !groups.contains(&metadata.gid()) {
            permissions &= !0o2000;
        }
        self.chmod_inode(inode, permissions)?;
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
        let (root, base) = self.resolve_anchors(payload, anchors)?;
        let inode = self.resolve_inode_at(
            root,
            base,
            payload,
            follow,
            effective_uid,
            effective_gid,
            groups,
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
        self.chown_inode(
            inode,
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
        let (root, base) = self.resolve_anchors(payload, anchors)?;
        let inode = self.resolve_inode_at(root, base, payload, follow, uid, gid, groups)?;
        let node_id = u64::from(inode.index.get());
        Ok(self.node_status_response(request, node_id, inode.metadata()))
    }

    /// Obtains metadata from an existing provider object. The caller must
    /// identify the attached Handle through the kernel before invoking this.
    pub fn stat_handle(&self, request: protocol::Header, open_id: u64) -> Result<Response, i32> {
        if request.flags != 0 {
            return Err(EINVAL);
        }
        let open = self.opens.get(&open_id).ok_or(EBADF)?;
        let node_id = u64::from(open.inode.index.get());
        let metadata = open.inode.metadata();
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
        let root = self.opens.get(&root_open_id).ok_or(EBADF)?.inode.clone();
        let mut current = self
            .opens
            .get(&directory_open_id)
            .ok_or(EBADF)?
            .inode
            .clone();
        if !root.file_type().is_dir() || !current.file_type().is_dir() {
            return Err(ENOTDIR);
        }
        let mut components = Vec::new();
        while current.index != root.index {
            if components.len() >= protocol::MAX_PATH_LEN {
                return Err(EIO);
            }
            let directory = Dir::open_inode(&self.fs, current.clone()).map_err(errno)?;
            let parent = directory
                .get_entry(DirEntryName::try_from("..").map_err(|_| EIO)?)
                .map_err(errno)?;
            if parent.index == current.index {
                return Err(EACCES);
            }
            let parent_directory = Dir::open_inode(&self.fs, parent.clone()).map_err(errno)?;
            let mut name = None;
            for entry in parent_directory.read_dir().map_err(errno)? {
                let entry = entry.map_err(errno)?;
                if entry.file_name() != "."
                    && entry.file_name() != ".."
                    && !entry
                        .file_name()
                        .as_str()
                        .map_err(|_| EIO)?
                        .starts_with(".mochios-orphan-")
                    && entry.inode.get() == current.index.get()
                {
                    name = Some(entry.file_name().as_str().map_err(|_| EIO)?.to_owned());
                    break;
                }
            }
            components.push(name.ok_or(ENOENT)?);
            current = parent;
        }
        let mut path = String::from("/");
        for (index, component) in components.iter().rev().enumerate() {
            if index != 0 {
                path.push('/');
            }
            path.push_str(component);
            if path.len() > protocol::MAX_PATH_LEN {
                return Err(ENAMETOOLONG);
            }
        }
        let mut response = self.success(request);
        response.header.length = path.len() as u32;
        response.payload = path.into_bytes();
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
        let (root, base) = self.resolve_anchors(payload, anchors)?;
        let inode = self.resolve_inode_at(root, base, payload, follow, uid, gid, groups)?;
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

    /// Resolves a path one component at a time from an already-open directory
    /// inode. Search permission is checked on the directory actually visited,
    /// including directories reached through symbolic links.
    fn resolve_inode_at(
        &self,
        root: Inode,
        base: Inode,
        path: &[u8],
        follow: FollowSymlinks,
        uid: u32,
        gid: u32,
        groups: &[u32],
    ) -> Result<Inode, i32> {
        match self.resolve_path_at(root, base, path, follow, uid, gid, groups)? {
            Resolution::Found { inode, .. } => Ok(inode),
            Resolution::Missing { .. } => Err(ENOENT),
        }
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
        const MAX_SYMLINKS: usize = 40;
        const MAX_COMPONENTS: usize = 1024;

        if path.is_empty() || path.len() > protocol::MAX_PATH_LEN || path.contains(&0) {
            return Err(EINVAL);
        }
        let parsed = Path::try_from(path).map_err(|_| EINVAL)?;
        let mut ancestors = if parsed.is_absolute() {
            vec![root.clone()]
        } else {
            self.ancestry_from_root(&root, base)?
        };
        let mut pending = owned_components(parsed);
        let require_directory = path.last() == Some(&b'/');
        let mut symlinks = 0usize;
        let mut iterations = 0usize;
        let mut last_name = None;

        while let Some(component) = pending.pop_front() {
            iterations = iterations.checked_add(1).ok_or(ELOOP)?;
            if iterations > MAX_COMPONENTS {
                return Err(ELOOP);
            }
            if component == OwnedComponent::Root {
                ancestors.truncate(1);
                last_name = None;
                continue;
            }
            let current = ancestors.last().ok_or(EIO)?;
            if !current.file_type().is_dir() {
                return Err(ENOTDIR);
            }
            let metadata = current.metadata();
            if !permission_allows(
                metadata.mode(),
                protocol::NODE_TYPE_DIRECTORY,
                metadata.uid(),
                metadata.gid(),
                uid,
                gid,
                groups,
                protocol::ACCESS_AT_EXECUTE,
            ) {
                return Err(EACCES);
            }
            match component {
                OwnedComponent::Root | OwnedComponent::Current => {
                    last_name = None;
                }
                OwnedComponent::Parent => {
                    if ancestors.len() > 1 {
                        ancestors.pop();
                    }
                    last_name = None;
                }
                OwnedComponent::Normal(name) => {
                    let directory = Dir::open_inode(&self.fs, current.clone()).map_err(errno)?;
                    let child = match directory
                        .get_entry(DirEntryName::try_from(name.as_slice()).map_err(|_| EINVAL)?)
                    {
                        Ok(child) => child,
                        Err(Ext4Error::NotFound) if pending.is_empty() => {
                            return Ok(Resolution::Missing {
                                parent: current.clone(),
                                name,
                            });
                        }
                        Err(error) => return Err(errno(error)),
                    };
                    let is_final = pending.is_empty();
                    if child.file_type().is_symlink()
                        && (follow == FollowSymlinks::All || !is_final)
                    {
                        last_name = None;
                        symlinks = symlinks.checked_add(1).ok_or(ELOOP)?;
                        if symlinks > MAX_SYMLINKS {
                            return Err(ELOOP);
                        }
                        let target = child.symlink_target(&self.fs).map_err(errno)?;
                        if target.as_ref().len().saturating_add(path.len()) > protocol::MAX_PATH_LEN
                        {
                            return Err(EINVAL);
                        }
                        if target.is_absolute() {
                            ancestors.truncate(1);
                        }
                        let mut target_components = owned_components(target.as_path());
                        while let Some(target_component) = target_components.pop_back() {
                            pending.push_front(target_component);
                        }
                    } else {
                        last_name = Some(name);
                        ancestors.push(child);
                    }
                }
            }
        }
        let inode = ancestors.pop().ok_or(EIO)?;
        let parent = last_name.map(|name| (ancestors.last().cloned(), name));
        if require_directory && !inode.file_type().is_dir() {
            return Err(ENOTDIR);
        }
        Ok(Resolution::Found {
            inode,
            parent: parent.and_then(|(parent, name)| parent.map(|parent| (parent, name))),
        })
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
        let open = self.opens.get(&open_id).ok_or(EBADF)?;
        if open.file.is_none() {
            let inode = open.inode.clone();
            let start_entry = open.offset;
            let (payload, next_entry) = self.read_open_directory_payload(
                inode,
                start_entry,
                length.min(mnu_abi::provider::MAX_DATA_LEN),
            )?;
            self.opens.get_mut(&open_id).ok_or(EBADF)?.offset = next_entry;
            return Ok(payload);
        }
        let open = self.opens.get_mut(&open_id).ok_or(EBADF)?;
        let file = open.file.as_mut().ok_or(EISDIR)?;
        let mut payload = vec![0u8; length.min(mnu_abi::provider::MAX_DATA_LEN)];
        let mut done = 0usize;
        while done < payload.len() {
            let count = file
                .read_bytes_at(&mut payload[done..], open.offset + done as u64)
                .map_err(errno)?;
            if count == 0 {
                break;
            }
            done += count;
        }
        open.offset = open.offset.checked_add(done as u64).ok_or(EFBIG)?;
        payload.truncate(done);
        Ok(payload)
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
        if payload.len() > mnu_abi::provider::MAX_DATA_LEN {
            return Err(EINVAL);
        }
        let open = self.opens.get_mut(&open_id).ok_or(EBADF)?;
        let file = open.file.as_mut().ok_or(EISDIR)?;
        if open.status_flags & protocol::OPEN_STATUS_APPEND != 0 {
            open.offset = file.inode().metadata().len();
        }
        let start = open.offset;
        let mut done = 0usize;
        while done < payload.len() {
            let count = file
                .write_bytes_at(&payload[done..], open.offset + done as u64)
                .map_err(errno)?;
            if count == 0 {
                return Err(EIO);
            }
            done += count;
        }
        open.offset = open.offset.checked_add(done as u64).ok_or(EFBIG)?;
        Ok((done, start))
    }

    pub fn provider_read_at(
        &mut self,
        open_id: u64,
        offset: u64,
        length: usize,
    ) -> Result<Vec<u8>, i32> {
        let open = self.opens.get_mut(&open_id).ok_or(EBADF)?;
        let file = open.file.as_mut().ok_or(EISDIR)?;
        let mut payload = vec![0u8; length.min(mnu_abi::provider::MAX_DATA_LEN)];
        let mut done = 0usize;
        while done < payload.len() {
            let position = offset.checked_add(done as u64).ok_or(EFBIG)?;
            let count = file
                .read_bytes_at(&mut payload[done..], position)
                .map_err(errno)?;
            if count == 0 {
                break;
            }
            done += count;
        }
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
        let open = self.opens.get_mut(&open_id).ok_or(EBADF)?;
        let file = open.file.as_mut().ok_or(EISDIR)?;
        let mut done = 0usize;
        while done < payload.len() {
            let position = offset.checked_add(done as u64).ok_or(EFBIG)?;
            let count = file
                .write_bytes_at(&payload[done..], position)
                .map_err(errno)?;
            if count == 0 {
                return Err(EIO);
            }
            done += count;
        }
        Ok(done)
    }

    pub fn provider_sync(&self, open_id: u64) -> Result<(), i32> {
        let open = self.opens.get(&open_id).ok_or(EBADF)?;
        if open.file.is_none() {
            return Err(EISDIR);
        }
        Ok(())
    }

    pub fn provider_memory_object(&self, open_id: u64) -> Result<u64, i32> {
        let open = self.opens.get(&open_id).ok_or(EBADF)?;
        if open.file.is_none() || open.node_id == 0 {
            return Err(EISDIR);
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
        let open = self.opens.get_mut(&open_id).ok_or(EBADF)?;
        let current = i128::from(open.offset);
        let base = match basis {
            mnu_abi::HANDLE_SEEK_START => 0,
            mnu_abi::HANDLE_SEEK_CURRENT => current,
            mnu_abi::HANDLE_SEEK_END => {
                i128::from(open.file.as_ref().ok_or(EISDIR)?.inode().metadata().len())
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
        let open = self.opens.get(&request.open_id).ok_or(EBADF)?;
        let node_id = open.node_id;
        let inode = open.inode.clone();
        let is_last_open = self
            .opens
            .values()
            .filter(|other| other.node_id == node_id)
            .count()
            == 1;
        if is_last_open {
            if let Some(orphan) = self.orphans.get(&node_id).cloned() {
                let mut parent = Dir::open_inode(&self.fs, orphan.parent).map_err(errno)?;
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
        for entry in self
            .fs
            .read_dir(path.as_str())
            .map_err(errno)?
            .skip(start_entry)
        {
            let entry = entry.map_err(errno)?;
            let name = entry.file_name().as_str().map_err(|_| EIO)?;
            if name.starts_with(".mochios-orphan-") {
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
        inode: Inode,
        start_entry: u64,
        max_length: usize,
    ) -> Result<(Vec<u8>, u64), i32> {
        let start_entry = usize::try_from(start_entry).map_err(|_| EINVAL)?;
        let directory = Dir::open_inode(&self.fs, inode).map_err(errno)?;
        let mut payload = Vec::new();
        let mut next_entry = start_entry;
        for entry in directory.read_dir().map_err(errno)?.skip(start_entry) {
            let entry = entry.map_err(errno)?;
            let name = entry.file_name().as_str().map_err(|_| EIO)?;
            if name.starts_with(".mochios-orphan-") {
                next_entry = next_entry.checked_add(1).ok_or(EIO)?;
                continue;
            }
            let node_id = u64::from(entry.inode.get());
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
        parent_inode: Inode,
        name: &[u8],
        mut inode: Inode,
        remove_directory: bool,
        path_hint: Option<&str>,
    ) -> Result<(), i32> {
        let mut parent = Dir::open_inode(&self.fs, parent_inode.clone()).map_err(errno)?;
        if inode.file_type().is_dir() {
            if !remove_directory {
                return Err(EISDIR);
            }
            let directory = Dir::open_inode(&self.fs, inode.clone()).map_err(errno)?;
            for entry in directory.read_dir().map_err(errno)? {
                let entry = entry.map_err(errno)?;
                if entry.file_name() != "." && entry.file_name() != ".." {
                    return Err(ENOTEMPTY);
                }
            }
            let original_parent_links = parent.inode().links_count();
            let parent_links = original_parent_links.checked_sub(1).ok_or(EIO)?;
            parent.inode_mut().set_links_count(parent_links);
            parent.inode_mut().write(&self.fs).map_err(errno)?;
            let original_links = inode.links_count();
            inode.set_links_count(1);
            if let Err(error) = inode.write(&self.fs) {
                parent.inode_mut().set_links_count(original_parent_links);
                let _ = parent.inode_mut().write(&self.fs);
                return Err(errno(error));
            }
            if let Err(error) = parent.unlink(
                DirEntryName::try_from(name).map_err(|_| EINVAL)?,
                inode.clone(),
            ) {
                inode.set_links_count(original_links);
                let _ = inode.write(&self.fs);
                parent.inode_mut().set_links_count(original_parent_links);
                let _ = parent.inode_mut().write(&self.fs);
                return Err(errno(error));
            }
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
        let node_id = u64::from(inode.index.get());
        let is_open = self.opens.values().any(|open| open.node_id == node_id);
        let orphan_name = format!(".mochios-orphan-{node_id}");
        if is_open {
            parent
                .link(
                    DirEntryName::try_from(orphan_name.as_str()).map_err(|_| EIO)?,
                    &mut inode,
                )
                .map_err(errno)?;
        }
        if let Err(error) = parent.unlink(
            DirEntryName::try_from(name).map_err(|_| EINVAL)?,
            inode.clone(),
        ) {
            if is_open {
                let _ = parent.unlink(
                    DirEntryName::try_from(orphan_name.as_str()).map_err(|_| EIO)?,
                    inode,
                );
            }
            return Err(errno(error));
        }
        if let Some(path) = path_hint {
            self.node_ids.remove(path);
        }
        if is_open {
            self.orphans.insert(
                node_id,
                Orphan {
                    parent: parent_inode,
                    name: orphan_name,
                },
            );
        } else {
            self.nodes.remove(&node_id);
        }
        Ok(())
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
                    if !self.directory_is_empty(&inode)? {
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
            if self.directory_is_at_or_below(&source_inode, new_parent_inode)? {
                return Err(EINVAL);
            }
            let backup_name = format!(".mochios-orphan-rename-{}", request.request_id);
            self.stage_rename_destination(
                &mut new_parent,
                new_name,
                &backup_name,
                destination.as_ref(),
            )?;
            if let Err(error) = self.move_directory(
                &mut old_parent,
                &mut new_parent,
                old_parent_path == new_parent_path,
                old_name,
                new_name,
                source_inode,
            ) {
                self.restore_rename_destination(
                    &mut new_parent,
                    new_name,
                    &backup_name,
                    destination,
                );
                return Err(error);
            }
            if let Some((destination_node_id, destination_inode)) = destination {
                self.remove_replaced_directory(&mut new_parent, &backup_name, destination_inode)?;
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
            self.restore_rename_destination(&mut new_parent, new_name, &backup_name, destination);
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
            self.restore_rename_destination(&mut new_parent, new_name, &backup_name, destination);
            return Err(errno(error));
        }

        if let Some((destination_node_id, destination_inode)) = destination {
            self.node_ids.remove(new_path);
            if self
                .opens
                .values()
                .any(|open| open.node_id == destination_node_id)
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
        let (old_root, old_base) = self.resolve_anchors(
            old_path,
            PathAnchors {
                root_open_id: anchors.root_open_id,
                base_open_id: anchors.old_base_open_id,
            },
        )?;
        let (new_root, new_base) = self.resolve_anchors(
            new_path,
            PathAnchors {
                root_open_id: anchors.root_open_id,
                base_open_id: anchors.new_base_open_id,
            },
        )?;
        let (mut source_inode, old_parent_inode, old_name) = match self.resolve_path_at(
            old_root,
            old_base,
            old_path,
            FollowSymlinks::ExcludeFinalComponent,
            uid,
            gid,
            groups,
        )? {
            Resolution::Found {
                inode,
                parent: Some((parent, name)),
            } => (inode, parent, name),
            Resolution::Found { parent: None, .. } => return Err(EINVAL),
            Resolution::Missing { .. } => return Err(ENOENT),
        };
        let (new_parent_inode, new_name, destination_inode) = match self.resolve_path_at(
            new_root,
            new_base,
            new_path,
            FollowSymlinks::ExcludeFinalComponent,
            uid,
            gid,
            groups,
        )? {
            Resolution::Found {
                inode,
                parent: Some((parent, name)),
            } => (parent, name, Some(inode)),
            Resolution::Found { parent: None, .. } => return Err(EINVAL),
            Resolution::Missing { parent, name } => (parent, name, None),
        };
        let old_name = std::str::from_utf8(&old_name).map_err(|_| EINVAL)?;
        let new_name = std::str::from_utf8(&new_name).map_err(|_| EINVAL)?;
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
        let mut old_parent = Dir::open_inode(&self.fs, old_parent_inode).map_err(errno)?;
        let mut new_parent = Dir::open_inode(&self.fs, new_parent_inode.clone()).map_err(errno)?;
        let source_node_id = u64::from(source_inode.index.get());
        let source_is_directory = source_inode.file_type().is_dir();
        if destination_inode
            .as_ref()
            .is_some_and(|inode| inode.index == source_inode.index)
        {
            return Ok(self.success(request));
        }
        let destination = match destination_inode {
            Some(inode) if source_is_directory && inode.file_type().is_dir() => {
                if !self.directory_is_empty(&inode)? {
                    return Err(ENOTEMPTY);
                }
                Some((u64::from(inode.index.get()), inode))
            }
            Some(_) if source_is_directory => return Err(ENOTDIR),
            Some(inode) if inode.file_type().is_dir() => return Err(EISDIR),
            Some(inode) => Some((u64::from(inode.index.get()), inode)),
            None => None,
        };
        if source_is_directory {
            if self.directory_is_at_or_below(&source_inode, new_parent_inode)? {
                return Err(EINVAL);
            }
            let backup_name = format!(".mochios-orphan-rename-{}", request.request_id);
            self.stage_rename_destination(
                &mut new_parent,
                new_name,
                &backup_name,
                destination.as_ref(),
            )?;
            if let Err(error) = self.move_directory(
                &mut old_parent,
                &mut new_parent,
                same_parent,
                old_name,
                new_name,
                source_inode,
            ) {
                self.restore_rename_destination(
                    &mut new_parent,
                    new_name,
                    &backup_name,
                    destination,
                );
                return Err(error);
            }
            if let Some((destination_node_id, destination_inode)) = destination {
                self.remove_replaced_directory(&mut new_parent, &backup_name, destination_inode)?;
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
            self.restore_rename_destination(&mut new_parent, new_name, &backup_name, destination);
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
            self.restore_rename_destination(&mut new_parent, new_name, &backup_name, destination);
            return Err(errno(error));
        }
        if let Some((destination_node_id, destination_inode)) = destination {
            if self
                .opens
                .values()
                .any(|open| open.node_id == destination_node_id)
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
        let (old_root, old_base) = self.resolve_anchors(
            old_path,
            PathAnchors {
                root_open_id: anchors.root_open_id,
                base_open_id: anchors.old_base_open_id,
            },
        )?;
        let (new_root, new_base) = self.resolve_anchors(
            new_path,
            PathAnchors {
                root_open_id: anchors.root_open_id,
                base_open_id: anchors.new_base_open_id,
            },
        )?;
        let source_follow = if request.flags & protocol::LINK_AT_FOLLOW_SOURCE != 0 {
            FollowSymlinks::All
        } else {
            FollowSymlinks::ExcludeFinalComponent
        };
        let mut source_inode = match self.resolve_path_at(
            old_root,
            old_base,
            old_path,
            source_follow,
            uid,
            gid,
            groups,
        )? {
            Resolution::Found { inode, .. } => inode,
            Resolution::Missing { .. } => return Err(ENOENT),
        };
        if source_inode.file_type().is_dir() {
            return Err(EPERM);
        }
        let (new_parent_inode, new_name) = match self.resolve_path_at(
            new_root,
            new_base,
            new_path,
            FollowSymlinks::ExcludeFinalComponent,
            uid,
            gid,
            groups,
        )? {
            Resolution::Found { .. } => return Err(EEXIST),
            Resolution::Missing { parent, name } => (parent, name),
        };
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
        let mut new_parent = Dir::open_inode(&self.fs, new_parent_inode).map_err(errno)?;
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
        parent: &mut Dir,
        name: &str,
        backup_name: &str,
        destination: Option<(u64, ext4plus::inode::Inode)>,
    ) {
        let Some((_, mut inode)) = destination else {
            return;
        };
        let (Ok(name), Ok(backup_name)) = (
            DirEntryName::try_from(name),
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
            let _ = parent.inode_mut().write(&self.fs);
        }
    }

    fn stage_rename_destination(
        &self,
        parent: &mut Dir,
        name: &str,
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
            DirEntryName::try_from(name).map_err(|_| EINVAL)?,
            inode.clone(),
        ) {
            let _ = parent.unlink(backup_name, inode);
            if is_directory {
                parent.inode_mut().set_links_count(parent_links);
                let _ = parent.inode_mut().write(&self.fs);
            }
            return Err(errno(error));
        }
        if is_directory {
            parent.inode_mut().set_links_count(parent_links);
            if let Err(error) = parent.inode_mut().write(&self.fs) {
                self.restore_rename_destination(
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
        old_parent: &mut Dir,
        new_parent: &mut Dir,
        same_parent: bool,
        old_name: &str,
        new_name: &str,
        mut source_inode: Inode,
    ) -> Result<(), i32> {
        let new_name = DirEntryName::try_from(new_name).map_err(|_| EINVAL)?;
        let old_name = DirEntryName::try_from(old_name).map_err(|_| EINVAL)?;
        if same_parent {
            let parent_links = new_parent.inode().links_count();
            new_parent
                .link(new_name, &mut source_inode)
                .map_err(errno)?;
            new_parent.inode_mut().set_links_count(parent_links);
            if let Err(error) = new_parent.inode_mut().write(&self.fs) {
                let _ = new_parent.unlink(new_name, source_inode);
                new_parent.inode_mut().set_links_count(parent_links);
                let _ = new_parent.inode_mut().write(&self.fs);
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
        let mut moved_directory = Dir::open_inode(&self.fs, source_inode.clone()).map_err(errno)?;
        if let Err(error) = moved_directory.set_parent(new_parent.inode()) {
            let _ = new_parent.unlink(new_name, source_inode);
            new_parent.inode_mut().set_links_count(new_parent_links);
            let _ = new_parent.inode_mut().write(&self.fs);
            return Err(errno(error));
        }

        let mut moved_inode = match old_parent.unlink(old_name, source_inode.clone()) {
            Ok(Some(inode)) => inode,
            Ok(None) => return Err(EIO),
            Err(error) => {
                let _ = moved_directory.set_parent(old_parent.inode());
                let _ = new_parent.unlink(new_name, source_inode);
                new_parent.inode_mut().set_links_count(new_parent_links);
                let _ = new_parent.inode_mut().write(&self.fs);
                return Err(errno(error));
            }
        };
        let Some(old_parent_links) = old_parent_links.checked_sub(1) else {
            let _ = old_parent.link(old_name, &mut moved_inode);
            let _ = moved_directory.set_parent(old_parent.inode());
            let _ = new_parent.unlink(new_name, moved_inode);
            new_parent.inode_mut().set_links_count(new_parent_links);
            let _ = new_parent.inode_mut().write(&self.fs);
            return Err(EIO);
        };
        old_parent.inode_mut().set_links_count(old_parent_links);
        if let Err(error) = old_parent.inode_mut().write(&self.fs) {
            let _ = old_parent.link(old_name, &mut moved_inode);
            let _ = moved_directory.set_parent(old_parent.inode());
            let _ = new_parent.unlink(new_name, moved_inode);
            new_parent.inode_mut().set_links_count(new_parent_links);
            let _ = new_parent.inode_mut().write(&self.fs);
            return Err(errno(error));
        }
        Ok(())
    }

    fn remove_replaced_directory(
        &self,
        parent: &mut Dir,
        name: &str,
        mut inode: Inode,
    ) -> Result<(), i32> {
        let original_parent_links = parent.inode().links_count();
        let parent_links = original_parent_links.checked_sub(1).ok_or(EIO)?;
        parent.inode_mut().set_links_count(parent_links);
        parent.inode_mut().write(&self.fs).map_err(errno)?;
        let original_links = inode.links_count();
        inode.set_links_count(1);
        if let Err(error) = inode.write(&self.fs) {
            parent.inode_mut().set_links_count(original_parent_links);
            let _ = parent.inode_mut().write(&self.fs);
            return Err(errno(error));
        }
        if let Err(error) = parent.unlink(
            DirEntryName::try_from(name).map_err(|_| EINVAL)?,
            inode.clone(),
        ) {
            inode.set_links_count(original_links);
            let _ = inode.write(&self.fs);
            parent.inode_mut().set_links_count(original_parent_links);
            let _ = parent.inode_mut().write(&self.fs);
            return Err(errno(error));
        }
        Ok(())
    }

    fn directory_is_empty(&self, inode: &Inode) -> Result<bool, i32> {
        let directory = Dir::open_inode(&self.fs, inode.clone()).map_err(errno)?;
        for entry in directory.read_dir().map_err(errno)? {
            let entry = entry.map_err(errno)?;
            if entry.file_name() != "." && entry.file_name() != ".." {
                return Ok(false);
            }
        }
        Ok(true)
    }

    fn directory_is_at_or_below(
        &self,
        ancestor: &Inode,
        mut directory: Inode,
    ) -> Result<bool, i32> {
        for _ in 0..protocol::MAX_PATH_LEN {
            if directory.index == ancestor.index {
                return Ok(true);
            }
            let parent = Dir::open_inode(&self.fs, directory.clone())
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
        let open = self.opens.get(&request.open_id).ok_or(EBADF)?;
        if open.file.is_none() {
            return Err(EISDIR);
        }
        self.truncate_inode(open.inode.clone(), request.offset)?;
        Ok(self.success(request))
    }

    fn truncate_inode(&mut self, inode: Inode, length: u64) -> Result<(), i32> {
        let node_id = u64::from(inode.index.get());
        let mut matched = false;
        for open in self.opens.values_mut() {
            if open.node_id == node_id {
                open.file
                    .as_mut()
                    .ok_or(EISDIR)?
                    .truncate(length)
                    .map_err(errno)?;
                matched = true;
            }
        }
        if !matched {
            File::open_inode(&self.fs, inode)
                .map_err(errno)?
                .truncate(length)
                .map_err(errno)?;
        }
        Ok(())
    }

    fn chmod_inode(&mut self, mut inode: Inode, permissions: u16) -> Result<(), i32> {
        let node_id = u64::from(inode.index.get());
        let mut matched = false;
        for open in self.opens.values_mut() {
            if open.node_id == node_id {
                let file_type = open.inode.mode().bits() & 0xf000;
                open.inode
                    .set_mode(InodeMode::from_bits_retain(file_type | permissions))
                    .map_err(errno)?;
                open.inode.write(&self.fs).map_err(errno)?;
                matched = true;
            }
        }
        if !matched {
            let file_type = inode.mode().bits() & 0xf000;
            inode
                .set_mode(InodeMode::from_bits_retain(file_type | permissions))
                .map_err(errno)?;
            inode.write(&self.fs).map_err(errno)?;
        }
        Ok(())
    }

    fn chown_inode(
        &mut self,
        mut inode: Inode,
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
            inode.write(filesystem).map_err(errno)
        }

        let node_id = u64::from(inode.index.get());
        let mut matched = false;
        for open in self.opens.values_mut() {
            if open.node_id == node_id {
                update(&self.fs, &mut open.inode, uid, gid, clear_set_id)?;
                matched = true;
            }
        }
        if !matched {
            update(&self.fs, &mut inode, uid, gid, clear_set_id)?;
        }
        Ok(())
    }

    pub fn truncate_handle(
        &mut self,
        mut request: protocol::Header,
        open_id: u64,
    ) -> Result<Response, i32> {
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
        let effective_uid = credentials.effective_uid;
        let effective_gid = credentials.effective_gid;
        let groups = credentials.supplementary_groups();
        let inode = self.opens.get(&open_id).ok_or(EBADF)?.inode.clone();
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
        self.chmod_inode(inode, permissions)?;
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
        let effective_uid = credentials.effective_uid;
        let effective_gid = credentials.effective_gid;
        let groups = credentials.supplementary_groups();
        let requested_uid = request.node_id as u32;
        let requested_gid = (request.node_id >> 32) as u32;
        let inode = self.opens.get(&open_id).ok_or(EBADF)?.inode.clone();
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
        self.chown_inode(inode, uid, gid, uid.is_some() || gid.is_some())?;
        Ok(self.success(request))
    }

    pub fn sync_handle(&self, request: protocol::Header, open_id: u64) -> Result<Response, i32> {
        self.opens.get(&open_id).ok_or(EBADF)?;
        Ok(self.success(request))
    }

    pub fn get_flags_handle(
        &self,
        request: protocol::Header,
        open_id: u64,
    ) -> Result<Response, i32> {
        let mut response = self.success(request);
        response.header.flags = self.opens.get(&open_id).ok_or(EBADF)?.status_flags;
        Ok(response)
    }

    pub fn set_flags_handle(
        &mut self,
        request: protocol::Header,
        open_id: u64,
    ) -> Result<Response, i32> {
        if request.flags & !protocol::OPEN_STATUS_FLAGS_ALL != 0 {
            return Err(EINVAL);
        }
        self.opens.get_mut(&open_id).ok_or(EBADF)?.status_flags = request.flags;
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
        let mut response = self.success(request);
        response.payload.resize(protocol::NODE_STATUS_LEN, 0);
        let status = protocol::NodeStatus {
            device: request.mount_id,
            node_id,
            size: metadata.len(),
            blocks: metadata.len().div_ceil(512),
            block_size: 4096,
            kind: node_type(metadata.file_type()),
            mode: u32::from(metadata.mode()),
            uid: metadata.uid(),
            gid: metadata.gid(),
            link_count: u32::from(metadata.links_count),
            special_device: 0,
            access_time_seconds: metadata.atime.as_secs(),
            access_time_nanoseconds: metadata.atime.subsec_nanos(),
            modification_time_seconds: metadata.mtime.as_secs(),
            modification_time_nanoseconds: metadata.mtime.subsec_nanos(),
            change_time_seconds: metadata.ctime.as_secs(),
            change_time_nanoseconds: metadata.ctime.subsec_nanos(),
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

#[derive(Clone, Debug, PartialEq, Eq)]
enum OwnedComponent {
    Root,
    Current,
    Parent,
    Normal(Vec<u8>),
}

enum Resolution {
    Found {
        inode: Inode,
        parent: Option<(Inode, Vec<u8>)>,
    },
    Missing {
        parent: Inode,
        name: Vec<u8>,
    },
}

fn owned_components(path: Path<'_>) -> VecDeque<OwnedComponent> {
    path.components()
        .map(|component| match component {
            Component::RootDir => OwnedComponent::Root,
            Component::CurDir => OwnedComponent::Current,
            Component::ParentDir => OwnedComponent::Parent,
            Component::Normal(name) => OwnedComponent::Normal(name.as_ref().to_vec()),
        })
        .collect()
}

fn node_type(file_type: FileType) -> u32 {
    if file_type.is_regular_file() {
        protocol::NODE_TYPE_REGULAR
    } else if file_type.is_dir() {
        protocol::NODE_TYPE_DIRECTORY
    } else if file_type.is_symlink() {
        protocol::NODE_TYPE_SYMLINK
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

fn errno(error: Ext4Error) -> i32 {
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
