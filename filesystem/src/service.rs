use std::collections::HashMap;
use std::time::Duration;

use ext4plus::dir::Dir;
use ext4plus::error::Ext4Error;
use ext4plus::file::File;
use ext4plus::inode::{InodeCreationOptions, InodeFlags, InodeMode};
use ext4plus::path::PathBuf;
use ext4plus::{DirEntryName, Ext4, FileType, FollowSymlinks, Metadata};
use mochios_filesystem_protocol as protocol;

const EIO: i32 = 5;
const ENOENT: i32 = 2;
const EBADF: i32 = 9;
const EACCES: i32 = 13;
const EEXIST: i32 = 17;
const EINVAL: i32 = 22;
const ENOSPC: i32 = 28;
const EISDIR: i32 = 21;
const ENOTDIR: i32 = 20;
const ENOSYS: i32 = 38;
const ENOTEMPTY: i32 = 39;
const EFBIG: i32 = 27;

pub struct Response {
    pub header: protocol::Header,
    pub payload: Vec<u8>,
}

pub struct FilesystemService {
    fs: Ext4,
    nodes: HashMap<u64, String>,
    node_ids: HashMap<String, u64>,
    opens: HashMap<u64, OpenFile>,
    orphans: HashMap<u64, Orphan>,
    next_node_id: u64,
    next_open_id: u64,
}

struct OpenFile {
    node_id: u64,
    file: File,
}

#[derive(Clone)]
struct Orphan {
    parent_path: String,
    name: String,
}

impl FilesystemService {
    pub fn new(fs: Ext4) -> Self {
        let mut nodes = HashMap::new();
        let mut node_ids = HashMap::new();
        nodes.insert(1, "/".to_owned());
        node_ids.insert("/".to_owned(), 1);
        Self {
            fs,
            nodes,
            node_ids,
            opens: HashMap::new(),
            orphans: HashMap::new(),
            next_node_id: 2,
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
            _ => Err(ENOSYS),
        };
        result.unwrap_or_else(|errno| self.error(request, errno))
    }

    fn mount(&self, request: protocol::Header) -> Result<Response, i32> {
        let metadata = self.fs.metadata("/").map_err(errno)?;
        Ok(self.metadata_response(request, 1, metadata))
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
        let node_id = self.remember_node(path)?;
        Ok(self.metadata_response(request, node_id, metadata))
    }

    fn open(&mut self, request: protocol::Header) -> Result<Response, i32> {
        let path = self.nodes.get(&request.node_id).ok_or(ENOENT)?;
        let file = self.fs.open(path.as_str()).map_err(errno)?;
        let open_id = self.next_open_id;
        self.next_open_id = self.next_open_id.checked_add(1).ok_or(EIO)?;
        self.opens.insert(
            open_id,
            OpenFile {
                node_id: request.node_id,
                file,
            },
        );
        let mut response = self.success(request);
        response.header.open_id = open_id;
        Ok(response)
    }

    fn close(&mut self, request: protocol::Header) -> Result<Response, i32> {
        let open = self.opens.get(&request.open_id).ok_or(EBADF)?;
        let node_id = open.node_id;
        let inode = open.file.inode().clone();
        let is_last_open = self
            .opens
            .values()
            .filter(|other| other.node_id == node_id)
            .count()
            == 1;
        if is_last_open {
            if let Some(orphan) = self.orphans.get(&node_id).cloned() {
                let parent_inode = self
                    .fs
                    .path_to_inode(
                        orphan.parent_path.as_str().try_into().map_err(|_| EIO)?,
                        FollowSymlinks::All,
                    )
                    .map_err(errno)?;
                let mut parent = Dir::open_inode(&self.fs, parent_inode).map_err(errno)?;
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
        let file = &mut self.opens.get_mut(&request.open_id).ok_or(EBADF)?.file;
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
        let file = &mut self.opens.get_mut(&request.open_id).ok_or(EBADF)?.file;
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
            (open.node_id, open.file.inode().metadata())
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
                uid: 0,
                gid: 0,
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
        let node_id = self.remember_node(path)?;
        Ok(self.metadata_response(request, node_id, inode.metadata()))
    }

    fn read_dir(&mut self, request: protocol::Header) -> Result<Response, i32> {
        let path = self.nodes.get(&request.node_id).ok_or(ENOENT)?.clone();
        let max_length = (request.flags as usize).min(protocol::MAX_IO_LEN);
        let start_entry = usize::try_from(request.offset).map_err(|_| EINVAL)?;
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
            let node_id = self.remember_node(&child_path)?;
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
        let mut response = self.success(request);
        response.header.offset = next_entry as u64;
        response.header.length = payload.len() as u32;
        response.payload = payload;
        Ok(response)
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
        let mut parent = Dir::open_inode(&self.fs, parent_inode).map_err(errno)?;
        let mut inode = parent
            .get_entry(DirEntryName::try_from(name).map_err(|_| EINVAL)?)
            .map_err(errno)?;
        if inode.file_type().is_dir() {
            if request.flags != protocol::NODE_TYPE_DIRECTORY {
                return Err(EISDIR);
            }
            let directory = Dir::open_inode(&self.fs, inode.clone()).map_err(errno)?;
            for entry in directory.read_dir().map_err(errno)? {
                let entry = entry.map_err(errno)?;
                if entry.file_name() != "." && entry.file_name() != ".." {
                    return Err(ENOTEMPTY);
                }
            }
            let original_links = inode.links_count();
            inode.set_links_count(1);
            inode.write(&self.fs).map_err(errno)?;
            if let Err(error) = parent.unlink(
                DirEntryName::try_from(name).map_err(|_| EINVAL)?,
                inode.clone(),
            ) {
                inode.set_links_count(original_links);
                let _ = inode.write(&self.fs);
                return Err(errno(error));
            }
            if let Some(node_id) = self.node_ids.remove(path) {
                self.nodes.remove(&node_id);
            }
            return Ok(self.success(request));
        }
        if request.flags == protocol::NODE_TYPE_DIRECTORY {
            return Err(ENOTDIR);
        }
        let node_id = self.remember_node(path)?;
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
        self.node_ids.remove(path);
        if is_open {
            self.orphans.insert(
                node_id,
                Orphan {
                    parent_path: parent_path.to_owned(),
                    name: orphan_name,
                },
            );
        } else {
            self.nodes.remove(&node_id);
        }
        Ok(self.success(request))
    }

    fn symlink(&mut self, request: protocol::Header, payload: &[u8]) -> Result<Response, i32> {
        let split = usize::try_from(request.offset).map_err(|_| EINVAL)?;
        let (target, link_path) = payload.split_at_checked(split).ok_or(EINVAL)?;
        if target.is_empty() || target.len() > protocol::MAX_PATH_LEN || target.contains(&0) {
            return Err(EINVAL);
        }
        let target = std::str::from_utf8(target).map_err(|_| EINVAL)?;
        let link_path = decode_path(link_path)?;
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
                0,
                0,
                Duration::default(),
            )
            .map_err(errno)?;
        let node_id = self.remember_node(link_path)?;
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
        let mut new_parent = Dir::open_inode(&self.fs, new_parent_inode).map_err(errno)?;
        let mut source_inode = old_parent
            .get_entry(DirEntryName::try_from(old_name).map_err(|_| EINVAL)?)
            .map_err(errno)?;
        let source_is_directory = source_inode.file_type().is_dir();
        self.remember_node(old_path)?;

        let destination =
            match new_parent.get_entry(DirEntryName::try_from(new_name).map_err(|_| EINVAL)?) {
                Ok(inode) if source_is_directory && inode.file_type().is_dir() => {
                    return Err(ENOTEMPTY);
                }
                Ok(_) if source_is_directory => return Err(ENOTDIR),
                Ok(inode) if inode.file_type().is_dir() => return Err(EISDIR),
                Ok(inode) => {
                    let node_id = self.remember_node(new_path)?;
                    Some((node_id, inode))
                }
                Err(Ext4Error::NotFound) => None,
                Err(error) => return Err(errno(error)),
            };
        if source_is_directory {
            if old_parent_path != new_parent_path {
                return Err(ENOSYS);
            }
            let parent_links = new_parent.inode().links_count();
            new_parent
                .link(
                    DirEntryName::try_from(new_name).map_err(|_| EINVAL)?,
                    &mut source_inode,
                )
                .map_err(errno)?;
            new_parent.inode_mut().set_links_count(parent_links);
            if let Err(error) = new_parent.inode_mut().write(&self.fs) {
                let _ = new_parent.unlink(
                    DirEntryName::try_from(new_name).map_err(|_| EINVAL)?,
                    source_inode,
                );
                new_parent.inode_mut().set_links_count(parent_links);
                let _ = new_parent.inode_mut().write(&self.fs);
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
                return Err(errno(error));
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
                        parent_path: new_parent_path.to_owned(),
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
        if parent.link(name, &mut inode).is_ok() {
            let _ = parent.unlink(backup_name, inode);
        }
    }

    fn truncate(&mut self, request: protocol::Header) -> Result<Response, i32> {
        self.opens
            .get_mut(&request.open_id)
            .ok_or(EBADF)?
            .file
            .truncate(request.offset)
            .map_err(errno)?;
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

    fn set_attr(
        &self,
        request: protocol::Header,
        payload: &[u8],
    ) -> Result<Response, i32> {
        let path = decode_path(payload)?;
        let supported = protocol::SETATTR_MODE | protocol::SETATTR_UID | protocol::SETATTR_GID;
        if request.flags == 0 || request.flags & !supported != 0 {
            return Err(EINVAL);
        }
        let mut inode = self
            .fs
            .path_to_inode(
                path.try_into().map_err(|_| EINVAL)?,
                FollowSymlinks::All,
            )
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

    fn remember_node(&mut self, path: &str) -> Result<u64, i32> {
        if let Some(node_id) = self.node_ids.get(path) {
            return Ok(*node_id);
        }
        let node_id = self.next_node_id;
        self.next_node_id = self.next_node_id.checked_add(1).ok_or(EIO)?;
        self.nodes.insert(node_id, path.to_owned());
        self.node_ids.insert(path.to_owned(), node_id);
        Ok(node_id)
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
