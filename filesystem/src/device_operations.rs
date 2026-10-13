//! Device-backed descriptions share the provider ID allocator with disk files.

use super::*;

impl FilesystemService {
    /// Startup-owned mount configuration; never accepts a caller-selected ID.
    pub fn mount_devices(
        &mut self,
        at: &[u8],
        filesystem: crate::devfs::DeviceFilesystem,
    ) -> Result<(), i32> {
        if self.namespace.is_none() {
            self.namespace = Some(Namespace::new(self.fs.clone())?);
        }
        let namespace = self.namespace.as_mut().ok_or(EIO)?;
        let root = namespace.root();
        match namespace.resolve(
            root.clone(),
            root,
            at,
            false,
            path_walk::Credentials {
                uid: 0,
                gid: 0,
                groups: &[],
            },
        )? {
            path_walk::Resolution::Found { inode, .. } => {
                namespace.mount_devices(inode, filesystem)?;
            }
            path_walk::Resolution::Missing { parent, name } => {
                namespace.mount_named_devices(parent, &name, filesystem)?;
            }
        }
        Ok(())
    }

    pub(super) fn retained_namespace_node(&self, open_id: u64) -> Result<Node, i32> {
        if let Some(open) = self.opens.device(open_id) {
            return Ok(open.node.clone());
        }
        let open = self.opens.get(&open_id).ok_or(EBADF)?;
        self.namespace
            .as_ref()
            .ok_or(EIO)?
            .retained_node(open.volume, open.inode.clone())
    }

    pub(super) fn resolve_namespace_path(
        &self,
        path: &[u8],
        anchors: PathAnchors,
        follow: FollowSymlinks,
        uid: u32,
        gid: u32,
        groups: &[u32],
    ) -> Result<Option<path_walk::Resolution<Node>>, i32> {
        let Some(namespace) = &self.namespace else {
            return Ok(None);
        };
        let root = match anchors.root_open_id {
            Some(id) => self.retained_namespace_node(id)?,
            None => namespace.root(),
        };
        let base = if path.first() == Some(&b'/') {
            root.clone()
        } else {
            match anchors.base_open_id {
                Some(id) => self.retained_namespace_node(id)?,
                None => root.clone(),
            }
        };
        namespace
            .resolve(
                root,
                base,
                path,
                follow == FollowSymlinks::All,
                path_walk::Credentials { uid, gid, groups },
            )
            .map(Some)
    }

    pub(super) fn open_device_at(
        &mut self,
        request: protocol::Header,
        resolution: path_walk::Resolution<Node>,
        credentials: protocol::Credentials,
    ) -> Result<Response, i32> {
        let node = match resolution {
            path_walk::Resolution::Found { inode, .. } => inode,
            path_walk::Resolution::Missing { .. } => {
                return Err(if request.flags & protocol::OPEN_AT_CREATE != 0 {
                    30
                } else {
                    ENOENT
                });
            }
        };
        if request.flags & (protocol::OPEN_AT_CREATE | protocol::OPEN_AT_EXCLUSIVE)
            == protocol::OPEN_AT_CREATE | protocol::OPEN_AT_EXCLUSIVE
        {
            return Err(EEXIST);
        }
        let namespace = self.namespace.as_ref().ok_or(EIO)?;
        let status = namespace.device_status(&node)?;
        let directory = status.kind == protocol::NODE_TYPE_DIRECTORY;
        if request.flags & protocol::OPEN_AT_DIRECTORY != 0 && !directory {
            return Err(ENOTDIR);
        }
        if directory && request.flags & protocol::OPEN_AT_WRITE != 0 {
            return Err(EISDIR);
        }
        let read = request.flags & protocol::OPEN_AT_READ != 0;
        let write = request.flags & protocol::OPEN_AT_WRITE != 0;
        let access = if request.flags & protocol::OPEN_AT_SEARCH != 0 {
            protocol::ACCESS_AT_EXECUTE
        } else {
            u32::from(read) * protocol::ACCESS_AT_READ
                | u32::from(write) * protocol::ACCESS_AT_WRITE
        };
        if !permission_allows(
            u16::try_from(status.mode).map_err(|_| EIO)?,
            status.kind,
            status.uid,
            status.gid,
            credentials.effective_uid,
            credentials.effective_gid,
            credentials.supplementary_groups(),
            access,
        ) {
            return Err(EACCES);
        }
        let flags = if request.flags & protocol::OPEN_AT_APPEND != 0 {
            protocol::OPEN_STATUS_APPEND
        } else {
            0
        } | if request.flags & protocol::OPEN_AT_NONBLOCK != 0 {
            protocol::OPEN_STATUS_NONBLOCK
        } else {
            0
        };
        let null = if directory {
            None
        } else {
            Some(namespace.open_null(
                &node,
                path_walk::Credentials {
                    uid: credentials.effective_uid,
                    gid: credentials.effective_gid,
                    groups: credentials.supplementary_groups(),
                },
                read,
                write,
                flags,
            )?)
        };
        let open_id = self.next_open_id;
        self.next_open_id = open_id.checked_add(1).ok_or(EIO)?;
        let id = node.id();
        self.opens.insert_device(
            open_id,
            DeviceOpen {
                node,
                null,
                offset: 0,
                directory_flags: flags,
            },
        );
        let mut response = self.success(request);
        response.header.open_id = open_id;
        response.header.node_id = (id.volume << 32) | u64::from(id.inode);
        Ok(response)
    }

    pub(super) fn device_status_response(
        &self,
        request: protocol::Header,
        node: &Node,
    ) -> Result<Response, i32> {
        let mut status = self.namespace.as_ref().ok_or(EIO)?.device_status(node)?;
        status.node_id |= status.device << 32;
        let mut response = self.success(request);
        response.payload.resize(protocol::NODE_STATUS_LEN, 0);
        protocol::encode_node_status(status, &mut response.payload).map_err(|_| EIO)?;
        response.header.length = response.payload.len() as u32;
        Ok(response)
    }

    pub(super) fn read_device(&mut self, open_id: u64, length: usize) -> Result<Vec<u8>, i32> {
        let open = self.opens.device(open_id).ok_or(EBADF)?;
        if let Some(null) = &open.null {
            null.read_into(&mut [])?;
            return Ok(Vec::new());
        }
        let entries = self
            .namespace
            .as_ref()
            .ok_or(EIO)?
            .device_entries(&open.node)?;
        let start = usize::try_from(open.offset).map_err(|_| EINVAL)?;
        let mut payload = Vec::new();
        let mut next = start;
        for (id, kind, name) in entries.into_iter().skip(start) {
            let size = protocol::DIRENT_HEADER_LEN + name.len();
            if payload.len().saturating_add(size) > length {
                if payload.is_empty() {
                    return Err(ENOSPC);
                }
                break;
            }
            let offset = payload.len();
            payload.resize(offset + size, 0);
            protocol::encode_dir_entry(
                (id.volume << 32) | u64::from(id.inode),
                kind,
                &name,
                &mut payload[offset..],
            )
            .map_err(|_| EIO)?;
            next = next.checked_add(1).ok_or(EIO)?;
        }
        self.opens.device_mut(open_id).ok_or(EBADF)?.offset = next as u64;
        Ok(payload)
    }
}
