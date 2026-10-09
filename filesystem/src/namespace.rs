//! User-space mount topology. Paths cross mounts by inode identity, not prefixes.

use std::collections::HashMap;
use std::sync::Arc;

use ext4plus::dir::Dir;
use ext4plus::inode::Inode;
use ext4plus::{DirEntryName, Ext4, Metadata};
use mochios_filesystem_protocol as protocol;

use crate::path_walk::{self, Backend, Credentials, Resolution};
use crate::service::{errno, permission_allows};

const EACCES: i32 = 13;
const EBUSY: i32 = 16;
const ENOTDIR: i32 = 20;
const EINVAL: i32 = 22;
const ELOOP: i32 = 40;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct NodeId {
    pub volume: u64,
    pub inode: u32,
}

/// Only this namespace can construct its nodes. IDs alone are not authority.
#[derive(Clone)]
pub struct Node {
    owner: Arc<()>,
    volume: u64,
    inode: Inode,
}

impl Node {
    pub(crate) fn into_inode(self) -> Inode {
        self.inode
    }
    pub fn id(&self) -> NodeId {
        NodeId {
            volume: self.volume,
            inode: self.inode.index.get(),
        }
    }

    pub fn metadata(&self) -> Metadata {
        self.inode.metadata()
    }
}

pub struct Namespace {
    owner: Arc<()>,
    volumes: Vec<Ext4>,
    root: Node,
    // Covered directory -> mounted volume root; mounted root -> covered directory.
    mounts: HashMap<NodeId, Node>,
    covered: HashMap<NodeId, Node>,
}

impl Namespace {
    pub fn new(filesystem: Ext4) -> Result<Self, i32> {
        let owner = Arc::new(());
        let root = Node {
            owner: owner.clone(),
            volume: 0,
            inode: filesystem.read_root_inode().map_err(errno)?,
        };
        Ok(Self {
            owner,
            volumes: vec![filesystem],
            root,
            mounts: HashMap::new(),
            covered: HashMap::new(),
        })
    }

    pub fn root(&self) -> Node {
        self.root.clone()
    }

    /// Mount configuration belongs to the service holding the volume authority.
    /// No pathname, process identity or service knowledge is sent to the kernel.
    /// Overmount and unmount are deliberately not supported by this operation.
    pub fn mount(&mut self, at: Node, filesystem: Ext4) -> Result<Node, i32> {
        self.filesystem(&at)?;
        if !at.inode.file_type().is_dir() {
            return Err(ENOTDIR);
        }
        if at.id() == self.root.id()
            || self.mounts.contains_key(&at.id())
            || self.covered.contains_key(&at.id())
        {
            return Err(EBUSY);
        }
        let root = Node {
            owner: self.owner.clone(),
            volume: u64::try_from(self.volumes.len()).map_err(|_| EINVAL)?,
            inode: filesystem.read_root_inode().map_err(errno)?,
        };
        self.volumes.push(filesystem);
        self.covered.insert(root.id(), at.clone());
        self.mounts.insert(at.id(), root.clone());
        Ok(root)
    }

    pub fn resolve(
        &self,
        root: Node,
        base: Node,
        path: &[u8],
        follow_final: bool,
        credentials: Credentials<'_>,
    ) -> Result<Resolution<Node>, i32> {
        self.filesystem(&root)?;
        self.filesystem(&base)?;
        let root = self.refresh(root)?;
        let base = self.refresh(base)?;
        if !self.is_directory(&root) || !self.is_directory(&base) {
            return Err(ENOTDIR);
        }
        path_walk::resolve(self, root, base, path, follow_final, credentials)
    }

    /// Reconstruct a retained directory's current namespace path, including
    /// mount edges. A removed directory has no pathname, even while open.
    pub(crate) fn directory_path(&self, root: Node, mut current: Node) -> Result<Vec<u8>, i32> {
        self.filesystem(&root)?;
        self.filesystem(&current)?;
        if !self.is_directory(&root) || !self.is_directory(&current) {
            return Err(ENOTDIR);
        }
        let mut components = Vec::new();
        let mut length = 1usize;
        while current.id() != root.id() {
            if components.len() >= 1024 {
                return Err(ELOOP);
            }
            let entry_node = self.covered.get(&current.id()).unwrap_or(&current);
            let parent = self.parent(&current)?;
            if parent.id() == current.id() {
                return Err(EACCES);
            }
            let directory =
                Dir::open_inode(self.filesystem(&parent)?, parent.inode.clone()).map_err(errno)?;
            let mut name = None;
            for entry in directory.read_dir().map_err(errno)? {
                let entry = entry.map_err(errno)?;
                let file_name = entry.file_name();
                let bytes = file_name.as_ref();
                if bytes != b"."
                    && bytes != b".."
                    && !bytes.starts_with(b".mochios-orphan-")
                    && entry.inode == entry_node.inode.index
                    && parent.volume == entry_node.volume
                {
                    name = Some(bytes.to_vec());
                    break;
                }
            }
            let name = name.ok_or(2)?;
            length = length
                .checked_add(name.len() + usize::from(!components.is_empty()))
                .ok_or(36)?;
            if length > protocol::MAX_PATH_LEN {
                return Err(36);
            }
            components.push(name);
            current = parent;
        }
        let mut path = vec![b'/'];
        for (index, component) in components.iter().rev().enumerate() {
            if index != 0 {
                path.push(b'/');
            }
            path.extend_from_slice(component);
        }
        Ok(path)
    }

    pub(crate) fn filesystem(&self, node: &Node) -> Result<&Ext4, i32> {
        if !Arc::ptr_eq(&self.owner, &node.owner) {
            return Err(EACCES);
        }
        self.volumes.get(node.volume as usize).ok_or(EINVAL)
    }

    fn refresh(&self, mut node: Node) -> Result<Node, i32> {
        node.inode = Inode::read(self.filesystem(&node)?, node.inode.index).map_err(errno)?;
        Ok(node)
    }

    /// Reconstruct only a node already retained by this service's open table.
    /// This is not a wire API accepting a caller-selected volume/inode pair.
    pub(crate) fn retained_node(&self, volume: u32, inode: Inode) -> Result<Node, i32> {
        if self.volumes.get(volume as usize).is_none() {
            return Err(EINVAL);
        }
        Ok(Node {
            owner: self.owner.clone(),
            volume: u64::from(volume),
            inode,
        })
    }

    pub(crate) fn directory_entry_id(
        &self,
        current: &Node,
        name: &[u8],
        inode: u32,
    ) -> Result<NodeId, i32> {
        self.filesystem(current)?;
        if name == b"." {
            return Ok(current.id());
        }
        if name == b".." {
            return Ok(self.parent(current)?.id());
        }
        let id = NodeId {
            volume: current.volume,
            inode,
        };
        Ok(self.mounts.get(&id).map_or(id, Node::id))
    }

    fn parent(&self, node: &Node) -> Result<Node, i32> {
        let node = self.covered.get(&node.id()).unwrap_or(node);
        let filesystem = self.filesystem(node)?;
        let current = Inode::read(filesystem, node.inode.index).map_err(errno)?;
        let inode = Dir::open_inode(filesystem, current)
            .map_err(errno)?
            .get_entry(DirEntryName::try_from("..").map_err(|_| EINVAL)?)
            .map_err(errno)?;
        Ok(Node {
            owner: self.owner.clone(),
            volume: node.volume,
            inode,
        })
    }
}

impl Backend for Namespace {
    type Node = Node;

    fn is_directory(&self, node: &Node) -> bool {
        node.inode.file_type().is_dir()
    }

    fn is_symlink(&self, node: &Node) -> bool {
        node.inode.file_type().is_symlink()
    }

    fn search(&self, node: &Node, credentials: Credentials<'_>) -> Result<(), i32> {
        let metadata = Inode::read(self.filesystem(node)?, node.inode.index)
            .map_err(errno)?
            .metadata();
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

    fn child(&self, node: &Node, name: &[u8]) -> Result<Node, i32> {
        let filesystem = self.filesystem(node)?;
        let current = Inode::read(filesystem, node.inode.index).map_err(errno)?;
        let inode = Dir::open_inode(filesystem, current)
            .map_err(errno)?
            .get_entry(DirEntryName::try_from(name).map_err(|_| EINVAL)?)
            .map_err(errno)?;
        let child = Node {
            owner: self.owner.clone(),
            volume: node.volume,
            inode,
        };
        self.refresh(self.mounts.get(&child.id()).cloned().unwrap_or(child))
    }

    fn symlink(&self, node: &Node) -> Result<Vec<u8>, i32> {
        Ok(node
            .inode
            .symlink_target(self.filesystem(node)?)
            .map_err(errno)?
            .as_ref()
            .to_vec())
    }

    fn ancestry(&self, root: &Node, base: Node) -> Result<Vec<Node>, i32> {
        self.filesystem(root)?;
        self.filesystem(&base)?;
        if !self.is_directory(&base) {
            return Err(ENOTDIR);
        }
        let mut ancestors = vec![base];
        while ancestors.last().ok_or(EINVAL)?.id() != root.id() {
            if ancestors.len() >= 1024 {
                return Err(ELOOP);
            }
            let current = ancestors.last().ok_or(EINVAL)?;
            let parent = self.parent(current)?;
            if parent.id() == current.id() {
                return Err(EACCES);
            }
            ancestors.push(parent);
        }
        ancestors.reverse();
        Ok(ancestors)
    }
}
