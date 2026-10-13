//! User-space mount topology. Paths cross mounts by inode identity, not prefixes.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use ext4plus::dir::Dir;
use ext4plus::inode::Inode;
use ext4plus::{DirEntryName, Ext4, Metadata};
use mochios_filesystem_protocol as protocol;

use crate::devfs::{DeviceFilesystem, NodeKind};
use crate::path_walk::{self, Backend, Credentials, Resolution};
use crate::service::{errno, permission_allows};

const EACCES: i32 = 13;
const EBUSY: i32 = 16;
const EEXIST: i32 = 17;
const ENOTDIR: i32 = 20;
const EINVAL: i32 = 22;
const ELOOP: i32 = 40;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NodeId {
    pub volume: u64,
    pub inode: u32,
}

/// Only this namespace can construct its nodes. IDs alone are not authority.
#[derive(Clone)]
pub struct Node {
    owner: Arc<()>,
    volume: u64,
    backing: NodeBacking,
}

#[derive(Clone)]
enum NodeBacking {
    Ext4(Inode),
    Device(crate::devfs::Node),
}

enum Volume {
    Ext4(Ext4),
    Device(DeviceFilesystem),
}

impl Node {
    pub(crate) fn into_inode(self) -> Result<Inode, i32> {
        match self.backing {
            NodeBacking::Ext4(inode) => Ok(inode),
            NodeBacking::Device(_) => Err(95),
        }
    }

    fn inode(&self) -> Result<&Inode, i32> {
        match &self.backing {
            NodeBacking::Ext4(inode) => Ok(inode),
            NodeBacking::Device(_) => Err(95),
        }
    }

    pub fn device_node(&self) -> Option<&crate::devfs::Node> {
        match &self.backing {
            NodeBacking::Device(node) => Some(node),
            NodeBacking::Ext4(_) => None,
        }
    }
    pub fn id(&self) -> NodeId {
        NodeId {
            volume: self.volume,
            inode: match &self.backing {
                NodeBacking::Ext4(inode) => inode.index.get(),
                NodeBacking::Device(node) => node.id(),
            },
        }
    }

    /// ext4 metadata is unavailable for virtual nodes; use `device_status`
    /// on their owning namespace instead of fabricating a disk inode.
    pub fn metadata(&self) -> Result<Metadata, i32> {
        Ok(self.inode()?.metadata())
    }
}

pub struct Namespace {
    owner: Arc<()>,
    volumes: Vec<Volume>,
    root: Node,
    // Covered directory -> mounted volume root; mounted root -> covered directory.
    mounts: HashMap<NodeId, Node>,
    covered: HashMap<NodeId, Node>,
    named_mounts: BTreeMap<(NodeId, Vec<u8>), Node>,
    named_parents: HashMap<NodeId, (Node, Vec<u8>)>,
}

impl Namespace {
    pub fn new(filesystem: Ext4) -> Result<Self, i32> {
        let owner = Arc::new(());
        let root = Node {
            owner: owner.clone(),
            volume: 0,
            backing: NodeBacking::Ext4(filesystem.read_root_inode().map_err(errno)?),
        };
        Ok(Self {
            owner,
            volumes: vec![Volume::Ext4(filesystem)],
            root,
            mounts: HashMap::new(),
            covered: HashMap::new(),
            named_mounts: BTreeMap::new(),
            named_parents: HashMap::new(),
        })
    }

    pub fn root(&self) -> Node {
        self.root.clone()
    }

    /// Attach a device filesystem over an existing directory by node identity.
    pub fn mount_devices(&mut self, at: Node, filesystem: DeviceFilesystem) -> Result<Node, i32> {
        self.validate(&at)?;
        if !self.is_directory(&at) {
            return Err(ENOTDIR);
        }
        if at.id() == self.root.id()
            || self.mounts.contains_key(&at.id())
            || self.covered.contains_key(&at.id())
            || self.named_parents.contains_key(&at.id())
        {
            return Err(EBUSY);
        }
        let root = Node {
            owner: self.owner.clone(),
            volume: u64::from(u32::try_from(self.volumes.len()).map_err(|_| EINVAL)?),
            backing: NodeBacking::Device(filesystem.root()),
        };
        self.volumes.push(Volume::Device(filesystem));
        self.covered.insert(root.id(), at.clone());
        self.mounts.insert(at.id(), root.clone());
        Ok(root)
    }

    /// Attach a device root without modifying the parent filesystem on disk.
    pub fn mount_named_devices(
        &mut self,
        parent: Node,
        name: &[u8],
        filesystem: DeviceFilesystem,
    ) -> Result<Node, i32> {
        self.validate(&parent)?;
        if !self.is_directory(&parent) {
            return Err(ENOTDIR);
        }
        if name == b"." || name == b".." {
            return Err(EINVAL);
        }
        DirEntryName::try_from(name).map_err(|_| EINVAL)?;
        match self.child(&parent, name) {
            Ok(_) => return Err(EEXIST),
            Err(2) => {}
            Err(error) => return Err(error),
        }
        let root = Node {
            owner: self.owner.clone(),
            volume: u64::from(u32::try_from(self.volumes.len()).map_err(|_| EINVAL)?),
            backing: NodeBacking::Device(filesystem.root()),
        };
        self.volumes.push(Volume::Device(filesystem));
        self.named_parents
            .insert(root.id(), (parent.clone(), name.to_vec()));
        self.named_mounts
            .insert((parent.id(), name.to_vec()), root.clone());
        Ok(root)
    }

    pub fn device_status(&self, node: &Node) -> Result<protocol::NodeStatus, i32> {
        self.validate(node)?;
        match (self.volumes.get(node.volume as usize), &node.backing) {
            (Some(Volume::Device(filesystem)), NodeBacking::Device(device)) => {
                filesystem.status(device, node.volume)
            }
            _ => Err(95),
        }
    }

    pub(crate) fn open_null(
        &self,
        node: &Node,
        credentials: Credentials<'_>,
        read: bool,
        write: bool,
        flags: u32,
    ) -> Result<crate::null_device::NullDescription, i32> {
        self.validate(node)?;
        match (self.volumes.get(node.volume as usize), &node.backing) {
            (Some(Volume::Device(filesystem)), NodeBacking::Device(device)) => {
                filesystem.open_null(device, credentials, read, write, flags)
            }
            _ => Err(95),
        }
    }

    pub(crate) fn device_entries(&self, node: &Node) -> Result<Vec<(NodeId, u32, Vec<u8>)>, i32> {
        self.validate(node)?;
        if !self.is_directory(node) {
            return Err(ENOTDIR);
        }
        let (filesystem, device) = match (self.volumes.get(node.volume as usize), &node.backing) {
            (Some(Volume::Device(filesystem)), NodeBacking::Device(device)) => (filesystem, device),
            _ => return Err(95),
        };
        let mut entries = vec![
            (node.id(), protocol::NODE_TYPE_DIRECTORY, b".".to_vec()),
            (
                self.parent(node)?.id(),
                protocol::NODE_TYPE_DIRECTORY,
                b"..".to_vec(),
            ),
        ];
        for (name, child) in filesystem.children(device)? {
            entries.push((
                NodeId {
                    volume: node.volume,
                    inode: child.id(),
                },
                filesystem.status(&child, node.volume)?.kind,
                name,
            ));
        }
        for (name, id) in self.named_children(node)? {
            entries.push((id, protocol::NODE_TYPE_DIRECTORY, name));
        }
        Ok(entries)
    }

    /// Mount configuration belongs to the service holding the volume authority.
    /// No pathname, process identity or service knowledge is sent to the kernel.
    /// Overmount and unmount are deliberately not supported by this operation.
    pub fn mount(&mut self, at: Node, filesystem: Ext4) -> Result<Node, i32> {
        self.filesystem(&at)?;
        if !self.is_directory(&at) {
            return Err(ENOTDIR);
        }
        if at.id() == self.root.id()
            || self.mounts.contains_key(&at.id())
            || self.covered.contains_key(&at.id())
            || self.named_parents.contains_key(&at.id())
        {
            return Err(EBUSY);
        }
        let root = Node {
            owner: self.owner.clone(),
            volume: u64::from(u32::try_from(self.volumes.len()).map_err(|_| EINVAL)?),
            backing: NodeBacking::Ext4(filesystem.read_root_inode().map_err(errno)?),
        };
        self.volumes.push(Volume::Ext4(filesystem));
        self.covered.insert(root.id(), at.clone());
        self.mounts.insert(at.id(), root.clone());
        Ok(root)
    }

    /// Attach a volume directory as a namespace-only child. The backing parent
    /// is not modified, and the mounted source's physical parent is not exposed.
    pub fn mount_named(
        &mut self,
        parent: Node,
        name: &[u8],
        filesystem: Ext4,
        source: &[u8],
    ) -> Result<Node, i32> {
        self.filesystem(&parent)?;
        if !self.is_directory(&parent) {
            return Err(ENOTDIR);
        }
        if name == b"." || name == b".." {
            return Err(EINVAL);
        }
        DirEntryName::try_from(name).map_err(|_| EINVAL)?;
        match self.child(&parent, name) {
            Ok(_) => return Err(EEXIST),
            Err(2) => {}
            Err(error) => return Err(error),
        }
        if source.first() != Some(&b'/')
            || source.len() > protocol::MAX_PATH_LEN
            || source.contains(&0)
        {
            return Err(EINVAL);
        }
        let inode = filesystem
            .path_to_inode(
                source.try_into().map_err(|_| EINVAL)?,
                ext4plus::FollowSymlinks::All,
            )
            .map_err(errno)?;
        if !inode.file_type().is_dir() {
            return Err(ENOTDIR);
        }
        let root = Node {
            owner: self.owner.clone(),
            volume: u64::from(u32::try_from(self.volumes.len()).map_err(|_| EINVAL)?),
            backing: NodeBacking::Ext4(inode),
        };
        self.volumes.push(Volume::Ext4(filesystem));
        self.named_parents
            .insert(root.id(), (parent.clone(), name.to_vec()));
        self.named_mounts
            .insert((parent.id(), name.to_vec()), root.clone());
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
        self.validate(&root)?;
        self.validate(&base)?;
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
        self.validate(&root)?;
        self.validate(&current)?;
        if !self.is_directory(&root) || !self.is_directory(&current) {
            return Err(ENOTDIR);
        }
        let mut components = Vec::new();
        let mut length = 1usize;
        while current.id() != root.id() {
            if components.len() >= 1024 {
                return Err(ELOOP);
            }
            let (parent, name) = if let Some((parent, name)) = self.named_parents.get(&current.id())
            {
                (self.refresh(parent.clone())?, name.clone())
            } else {
                let entry_node = self.covered.get(&current.id()).unwrap_or(&current);
                let parent = self.parent(&current)?;
                if parent.id() == current.id() {
                    return Err(EACCES);
                }
                let directory = Dir::open_inode(self.filesystem(&parent)?, parent.inode()?.clone())
                    .map_err(errno)?;
                let mut name = None;
                for entry in directory.read_dir().map_err(errno)? {
                    let entry = entry.map_err(errno)?;
                    let file_name = entry.file_name();
                    let bytes = file_name.as_ref();
                    if bytes != b"."
                        && bytes != b".."
                        && !bytes.starts_with(b".mochios-orphan-")
                        && entry.inode == entry_node.inode()?.index
                        && parent.volume == entry_node.volume
                    {
                        name = Some(bytes.to_vec());
                        break;
                    }
                }
                let name = name.ok_or(2)?;
                (parent, name)
            };
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
        self.validate(node)?;
        match self.volumes.get(node.volume as usize) {
            Some(Volume::Ext4(filesystem)) => Ok(filesystem),
            Some(Volume::Device(_)) => Err(95),
            None => Err(EINVAL),
        }
    }

    fn validate(&self, node: &Node) -> Result<(), i32> {
        if !Arc::ptr_eq(&self.owner, &node.owner) {
            return Err(EACCES);
        }
        match (self.volumes.get(node.volume as usize), &node.backing) {
            (Some(Volume::Ext4(_)), NodeBacking::Ext4(_)) => Ok(()),
            (Some(Volume::Device(filesystem)), NodeBacking::Device(device)) => {
                filesystem.status(device, node.volume).map(|_| ())
            }
            _ => Err(EINVAL),
        }
    }

    fn refresh(&self, mut node: Node) -> Result<Node, i32> {
        self.validate(&node)?;
        if let NodeBacking::Ext4(inode) = &node.backing {
            node.backing = NodeBacking::Ext4(
                Inode::read(self.filesystem(&node)?, inode.index).map_err(errno)?,
            );
        }
        Ok(node)
    }

    /// Reconstruct only a node already retained by this service's open table.
    /// This is not a wire API accepting a caller-selected volume/inode pair.
    pub(crate) fn retained_node(&self, volume: u32, inode: Inode) -> Result<Node, i32> {
        if !matches!(self.volumes.get(volume as usize), Some(Volume::Ext4(_))) {
            return Err(EINVAL);
        }
        Ok(Node {
            owner: self.owner.clone(),
            volume: u64::from(volume),
            backing: NodeBacking::Ext4(inode),
        })
    }

    pub(crate) fn directory_entry_id(
        &self,
        current: &Node,
        name: &[u8],
        inode: u32,
    ) -> Result<NodeId, i32> {
        self.validate(current)?;
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

    pub(crate) fn is_mount_root(&self, volume: u32, inode: &Inode) -> bool {
        let id = NodeId {
            volume: u64::from(volume),
            inode: inode.index.get(),
        };
        self.covered.contains_key(&id) || self.named_parents.contains_key(&id)
    }

    /// Stable name order keeps appended readdir cookies deterministic.
    pub(crate) fn named_children(&self, parent: &Node) -> Result<Vec<(Vec<u8>, NodeId)>, i32> {
        self.validate(parent)?;
        Ok(self
            .named_mounts
            .iter()
            .filter(|((id, _), _)| *id == parent.id())
            .map(|((_, name), node)| (name.clone(), node.id()))
            .collect())
    }

    fn parent(&self, node: &Node) -> Result<Node, i32> {
        if let Some((parent, _)) = self.named_parents.get(&node.id()) {
            return self.refresh(parent.clone());
        }
        let node = self.covered.get(&node.id()).unwrap_or(node);
        let filesystem = self.filesystem(node)?;
        let current = Inode::read(filesystem, node.inode()?.index).map_err(errno)?;
        let inode = Dir::open_inode(filesystem, current)
            .map_err(errno)?
            .get_entry(DirEntryName::try_from("..").map_err(|_| EINVAL)?)
            .map_err(errno)?;
        Ok(Node {
            owner: self.owner.clone(),
            volume: node.volume,
            backing: NodeBacking::Ext4(inode),
        })
    }
}

impl Backend for Namespace {
    type Node = Node;

    fn is_directory(&self, node: &Node) -> bool {
        match &node.backing {
            NodeBacking::Ext4(inode) => inode.file_type().is_dir(),
            NodeBacking::Device(device) => device.kind() == NodeKind::Directory,
        }
    }

    fn is_symlink(&self, node: &Node) -> bool {
        matches!(&node.backing, NodeBacking::Ext4(inode) if inode.file_type().is_symlink())
    }

    fn search(&self, node: &Node, credentials: Credentials<'_>) -> Result<(), i32> {
        self.validate(node)?;
        if let (Some(Volume::Device(filesystem)), NodeBacking::Device(device)) =
            (self.volumes.get(node.volume as usize), &node.backing)
        {
            return filesystem.search(device, credentials);
        }
        let metadata = Inode::read(self.filesystem(node)?, node.inode()?.index)
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
        self.validate(node)?;
        if let Some(mounted) = self.named_mounts.get(&(node.id(), name.to_vec())) {
            return self.refresh(mounted.clone());
        }
        if let (Some(Volume::Device(filesystem)), NodeBacking::Device(device)) =
            (self.volumes.get(node.volume as usize), &node.backing)
        {
            return Ok(Node {
                owner: self.owner.clone(),
                volume: node.volume,
                backing: NodeBacking::Device(filesystem.child(device, name)?),
            });
        }
        let filesystem = self.filesystem(node)?;
        let current = Inode::read(filesystem, node.inode()?.index).map_err(errno)?;
        let inode = Dir::open_inode(filesystem, current)
            .map_err(errno)?
            .get_entry(DirEntryName::try_from(name).map_err(|_| EINVAL)?)
            .map_err(errno)?;
        let child = Node {
            owner: self.owner.clone(),
            volume: node.volume,
            backing: NodeBacking::Ext4(inode),
        };
        self.refresh(self.mounts.get(&child.id()).cloned().unwrap_or(child))
    }

    fn symlink(&self, node: &Node) -> Result<Vec<u8>, i32> {
        Ok(node
            .inode()?
            .symlink_target(self.filesystem(node)?)
            .map_err(errno)?
            .as_ref()
            .to_vec())
    }

    fn ancestry(&self, root: &Node, base: Node) -> Result<Vec<Node>, i32> {
        self.validate(root)?;
        self.validate(&base)?;
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
