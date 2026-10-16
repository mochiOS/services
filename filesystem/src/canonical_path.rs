//! Resolve and reconstruct a path under the same serialized namespace borrow.
use super::*;

impl FilesystemService {
    pub fn canonical_path_at(
        &self,
        request: protocol::Header,
        path: &[u8],
        anchors: PathAnchors,
        credentials: protocol::Credentials,
    ) -> Result<Response, i32> {
        let allowed = protocol::STAT_AT_ROOT_ATTACHED | protocol::STAT_AT_BASE_ATTACHED;
        if request.flags & !allowed != 0
            || (request.flags & protocol::STAT_AT_ROOT_ATTACHED != 0)
                != anchors.root_open_id.is_some()
            || (request.flags & protocol::STAT_AT_BASE_ATTACHED != 0)
                != anchors.base_open_id.is_some()
        {
            return Err(EINVAL);
        }
        if path.is_empty() {
            return Err(ENOENT);
        }
        let resolution = self.resolve_namespace_path(
            path,
            anchors,
            FollowSymlinks::All,
            credentials.effective_uid,
            credentials.effective_gid,
            credentials.supplementary_groups(),
        )?;
        let (mut result, name) = if let Some(resolution) = resolution {
            let namespace = self.namespace.as_ref().ok_or(EIO)?;
            let root = match anchors.root_open_id {
                Some(handle) => self.retained_namespace_node(handle)?,
                None => namespace.root(),
            };
            match resolution {
                path_walk::Resolution::Found { inode, parent } => {
                    if path_walk::Backend::is_directory(namespace, &inode) {
                        (namespace.directory_path(root, inode)?, None)
                    } else {
                        let (parent, name) = parent.ok_or(EIO)?;
                        (namespace.directory_path(root, parent)?, Some(name))
                    }
                }
                path_walk::Resolution::Missing { .. } => return Err(ENOENT),
            }
        } else {
            let (root, base) = self.resolve_anchors(path, anchors)?;
            match self.resolve_path_at(
                root.clone(),
                base,
                path,
                FollowSymlinks::All,
                credentials.effective_uid,
                credentials.effective_gid,
                credentials.supplementary_groups(),
            )? {
                Resolution::Found { inode, parent } => {
                    if inode.file_type().is_dir() {
                        (Self::inode_directory_path(&self.fs, root, inode)?, None)
                    } else {
                        let (parent, name) = parent.ok_or(EIO)?;
                        (
                            Self::inode_directory_path(&self.fs, root, parent)?,
                            Some(name),
                        )
                    }
                }
                Resolution::Missing { .. } => return Err(ENOENT),
            }
        };
        if let Some(name) = name {
            if result.len() != 1 {
                result.push(b'/');
            }
            result.extend_from_slice(&name);
        }
        if result.len() > protocol::MAX_PATH_LEN {
            return Err(ENAMETOOLONG);
        }
        let mut response = self.success(request);
        response.header.length = result.len() as u32;
        response.payload = result;
        Ok(response)
    }

    pub(super) fn inode_directory_path(
        filesystem: &Ext4,
        root: Inode,
        mut current: Inode,
    ) -> Result<Vec<u8>, i32> {
        if !root.file_type().is_dir() || !current.file_type().is_dir() {
            return Err(ENOTDIR);
        }
        let mut components = Vec::new();
        while current.index != root.index {
            if components.len() >= protocol::MAX_PATH_LEN {
                return Err(ELOOP);
            }
            let directory = Dir::open_inode(filesystem, current).map_err(errno)?;
            let parent = directory
                .get_entry(DirEntryName::try_from("..").map_err(|_| EIO)?)
                .map_err(errno)?;
            if parent.index == directory.inode().index {
                return Err(EACCES);
            }
            let mut name = None;
            for entry in Dir::open_inode(filesystem, parent.clone())
                .map_err(errno)?
                .read_dir()
                .map_err(errno)?
            {
                let entry = entry.map_err(errno)?;
                let entry_name = entry.file_name();
                let bytes = entry_name.as_ref();
                if bytes != b"." && bytes != b".." && entry.inode == directory.inode().index {
                    name = Some(bytes.to_vec());
                    break;
                }
            }
            components.push(name.ok_or(ENOENT)?);
            current = parent;
        }
        let mut path = vec![b'/'];
        for (index, component) in components.iter().rev().enumerate() {
            if index != 0 {
                path.push(b'/');
            }
            path.extend_from_slice(component);
            if path.len() > protocol::MAX_PATH_LEN {
                return Err(ENAMETOOLONG);
            }
        }
        Ok(path)
    }
}
