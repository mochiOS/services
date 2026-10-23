//! Service-owned device namespace. Registration uses retained Nodes, not paths
//! or caller-selected inode numbers. Open descriptions outlive unpublication.
use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};

use crate::null_device::{self, NullDescription};
use crate::path_walk::{Backend, Credentials};
use crate::service::permission_allows;
use ext4plus::inode::InodeTimestamp;
use mochios_filesystem_protocol as protocol;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NodeKind {
    Directory,
    Null,
    External,
}

/// Service-owner registration data, not a path or caller-chosen object ID.
/// The factory owns the explicit capabilities needed to create this device.
pub struct ExternalDevice {
    pub special_device: u64,
    pub factory: Arc<dyn crate::device_factory::Factory>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Attributes {
    /// Permission/special bits only; node kind is immutable.
    pub mode: u16,
    pub uid: u32,
    pub gid: u32,
}

struct Metadata {
    attributes: Attributes,
    links: u32,
    changed: ext4plus::inode::InodeTimestamp,
    accessed: InodeTimestamp,
    modified: InodeTimestamp,
}

pub(crate) enum AttributeChange {
    Mode(u16),
    Owner { uid: u32, gid: u32 },
}
struct Record {
    id: u32,
    kind: NodeKind,
    parent: Option<Node>,
    metadata: RwLock<Metadata>,
    external: Option<ExternalDevice>,
}

/// Only this filesystem constructs references. Arc ownership seals both the
/// namespace and the inode lifetime; removed numeric IDs are never reused.
#[derive(Clone)]
pub struct Node {
    owner: Arc<()>,
    record: Arc<Record>,
}
impl Node {
    pub fn id(&self) -> u32 {
        self.record.id
    }
    pub fn kind(&self) -> NodeKind {
        self.record.kind
    }
}

pub struct DeviceFilesystem {
    owner: Arc<()>,
    root: Node,
    children: BTreeMap<u32, BTreeMap<Vec<u8>, Node>>,
    next_id: u64,
}

/// An admitted open retains exactly its inode/factory across unpublication.
/// Access mode is frozen here; each publication asks for a fresh native OFD.
pub struct ExternalOpen {
    node: Node,
    request: protocol::device_open::Request,
}
impl ExternalOpen {
    pub fn data_rights(&self) -> u64 {
        self.request.rights
    }
    pub fn node(&self) -> &Node {
        &self.node
    }
    pub fn publish(
        &self,
        metadata: mnu_abi::IpcObjectHandle,
    ) -> Result<mnu_abi::IpcObjectHandle, i32> {
        self.node
            .record
            .external
            .as_ref()
            .ok_or(5)?
            .factory
            .open(metadata, self.request)
    }
}

impl Default for DeviceFilesystem {
    fn default() -> Self {
        let owner = Arc::new(());
        let root = Self::node(
            &owner,
            1,
            NodeKind::Directory,
            None,
            Attributes {
                mode: 0o555,
                uid: 0,
                gid: 0,
            },
            None,
        );
        let null = Self::node(
            &owner,
            2,
            NodeKind::Null,
            Some(root.clone()),
            Attributes {
                mode: 0o666,
                uid: 0,
                gid: 0,
            },
            None,
        );
        Self {
            owner,
            root,
            children: BTreeMap::from([(1, BTreeMap::from([(b"null".to_vec(), null)]))]),
            next_id: 3,
        }
    }
}

impl DeviceFilesystem {
    fn node(
        owner: &Arc<()>,
        id: u32,
        kind: NodeKind,
        parent: Option<Node>,
        attributes: Attributes,
        external: Option<ExternalDevice>,
    ) -> Node {
        let initial = InodeTimestamp {
            seconds: 0,
            nanoseconds: 0,
        };
        Node {
            owner: owner.clone(),
            record: Arc::new(Record {
                id,
                kind,
                parent,
                metadata: RwLock::new(Metadata {
                    attributes,
                    links: if kind == NodeKind::Directory { 2 } else { 1 },
                    changed: initial,
                    accessed: initial,
                    modified: initial,
                }),
                external,
            }),
        }
    }
    pub fn root(&self) -> Node {
        self.root.clone()
    }

    fn validate(&self, node: &Node) -> Result<(), i32> {
        if Arc::ptr_eq(&self.owner, &node.owner) {
            Ok(())
        } else {
            Err(13)
        }
    }
    fn directory(&self, node: &Node) -> Result<(), i32> {
        self.validate(node)?;
        if node.kind() == NodeKind::Directory {
            Ok(())
        } else {
            Err(20)
        }
    }
    fn name(name: &[u8]) -> Result<(), i32> {
        if name.len() > 255 {
            return Err(36);
        }
        if name.is_empty()
            || name == b"."
            || name == b".."
            || name.contains(&0)
            || name.contains(&b'/')
        {
            return Err(22);
        }
        Ok(())
    }

    /// Owner-only configuration, not an untrusted credential-bearing wire API.
    /// Namespace/IPC admission must retain this filesystem authority separately.
    pub fn register(
        &mut self,
        parent: &Node,
        name: &[u8],
        kind: NodeKind,
        attributes: Attributes,
    ) -> Result<Node, i32> {
        if kind == NodeKind::External {
            return Err(22);
        }
        self.register_node(parent, name, kind, attributes, None)
    }

    pub fn register_external(
        &mut self,
        parent: &Node,
        name: &[u8],
        attributes: Attributes,
        device: ExternalDevice,
    ) -> Result<Node, i32> {
        self.register_node(parent, name, NodeKind::External, attributes, Some(device))
    }

    fn register_node(
        &mut self,
        parent: &Node,
        name: &[u8],
        kind: NodeKind,
        attributes: Attributes,
        external: Option<ExternalDevice>,
    ) -> Result<Node, i32> {
        self.directory(parent)?;
        Self::name(name)?;
        if attributes.mode & !0o7777 != 0 {
            return Err(22);
        }
        if self
            .children
            .get(&parent.id())
            .is_some_and(|children| children.contains_key(name))
        {
            return Err(17);
        }
        let mut metadata = parent.record.metadata.write().map_err(|_| 5)?;
        if metadata.links == 0 {
            return Err(2);
        }
        let links = metadata
            .links
            .checked_add(u32::from(kind == NodeKind::Directory))
            .ok_or(28)?;
        let id = u32::try_from(self.next_id).map_err(|_| 28)?;
        let node = Self::node(
            &self.owner,
            id,
            kind,
            Some(parent.clone()),
            attributes,
            external,
        );
        self.next_id += 1;
        self.children
            .entry(parent.id())
            .or_default()
            .insert(name.to_vec(), node.clone());
        if kind == NodeKind::Directory {
            self.children.insert(id, BTreeMap::new());
        }
        metadata.links = links;
        Ok(node)
    }

    pub fn unregister(&mut self, parent: &Node, name: &[u8]) -> Result<Node, i32> {
        self.directory(parent)?;
        Self::name(name)?;
        let node = self
            .children
            .get(&parent.id())
            .and_then(|children| children.get(name))
            .cloned()
            .ok_or(2)?;
        if node.kind() == NodeKind::Directory
            && self
                .children
                .get(&node.id())
                .is_some_and(|children| !children.is_empty())
        {
            return Err(39);
        }
        let mut parent_metadata = parent.record.metadata.write().map_err(|_| 5)?;
        let mut metadata = node.record.metadata.write().map_err(|_| 5)?;
        let links = parent_metadata
            .links
            .checked_sub(u32::from(node.kind() == NodeKind::Directory))
            .ok_or(5)?;
        self.children
            .get_mut(&parent.id())
            .ok_or(5)?
            .remove(name)
            .ok_or(5)?;
        self.children.remove(&node.id());
        parent_metadata.links = links;
        metadata.links = 0;
        drop(metadata);
        Ok(node)
    }

    pub fn set_attributes(&mut self, node: &Node, attributes: Attributes) -> Result<(), i32> {
        self.validate(node)?;
        if attributes.mode & !0o7777 != 0 {
            return Err(22);
        }
        node.record.metadata.write().map_err(|_| 5)?.attributes = attributes;
        Ok(())
    }

    /// Owner configuration with a provider-selected ctime. All fields change
    /// under the same metadata lock; clock failure commits nothing.
    pub(crate) fn set_attributes_timed(
        &mut self,
        node: &Node,
        attributes: Attributes,
        clock: crate::clock::Clock,
    ) -> Result<(), i32> {
        self.validate(node)?;
        if attributes.mode & !0o7777 != 0 {
            return Err(22);
        }
        let mut metadata = node.record.metadata.write().map_err(|_| 5)?;
        let now = clock()?;
        if now.nanoseconds >= 1_000_000_000 {
            return Err(22);
        }
        metadata.attributes = attributes;
        metadata.changed = now;
        Ok(())
    }

    /// Check fresh ownership and publish one atomic metadata update. The
    /// service has already authenticated the attached CONTROL Handle and
    /// credentials; this retained Node remains valid after unpublication.
    pub(crate) fn change_attributes(
        &mut self,
        node: &Node,
        change: AttributeChange,
        caller: Credentials<'_>,
        clock: crate::clock::Clock,
    ) -> Result<(), i32> {
        self.validate(node)?;
        let mut metadata = node.record.metadata.write().map_err(|_| 5)?;
        let old = metadata.attributes;
        if caller.uid != 0 && caller.uid != old.uid {
            return Err(1);
        }
        let mut updated = old;
        match change {
            AttributeChange::Mode(mode) => {
                if mode & !0o7777 != 0 {
                    return Err(22);
                }
                updated.mode = mode;
                if caller.uid != 0 && caller.gid != old.gid && !caller.groups.contains(&old.gid) {
                    updated.mode &= !0o2000;
                }
            }
            AttributeChange::Owner { uid, gid } => {
                if caller.uid != 0
                    && (uid != u32::MAX && uid != old.uid
                        || gid != u32::MAX
                            && gid != old.gid
                            && gid != caller.gid
                            && !caller.groups.contains(&gid))
                {
                    return Err(1);
                }
                if uid != u32::MAX {
                    updated.uid = uid;
                }
                if gid != u32::MAX {
                    updated.gid = gid;
                }
                if uid != u32::MAX || gid != u32::MAX {
                    updated.mode &= !0o6000;
                }
            }
        }
        let now = clock()?;
        if now.nanoseconds >= 1_000_000_000 {
            return Err(22);
        }
        metadata.attributes = updated;
        metadata.changed = now;
        Ok(())
    }

    /// Timestamp requests retain inode identity and authorize against fresh
    /// attributes. OMIT/OMIT never reads the clock or changes any timestamp.
    pub(crate) fn set_times(
        &mut self,
        node: &Node,
        times: protocol::FileTimeUpdate,
        caller: Credentials<'_>,
        now: impl FnOnce() -> Result<InodeTimestamp, i32>,
    ) -> Result<(), i32> {
        self.validate(node)?;
        if !times.valid() {
            return Err(22);
        }
        if times.unchanged() {
            return Ok(());
        }
        let mut metadata = node.record.metadata.write().map_err(|_| 5)?;
        let attributes = metadata.attributes;
        if caller.uid != 0 && caller.uid != attributes.uid {
            if !times.both_now() {
                return Err(1);
            }
            let kind = if node.kind() == NodeKind::Directory {
                protocol::NODE_TYPE_DIRECTORY
            } else {
                protocol::NODE_TYPE_SPECIAL
            };
            if !permission_allows(
                attributes.mode,
                kind,
                attributes.uid,
                attributes.gid,
                caller.uid,
                caller.gid,
                caller.groups,
                protocol::ACCESS_AT_WRITE,
            ) {
                return Err(13);
            }
        }
        let current = now()?;
        if current.nanoseconds >= 1_000_000_000 {
            return Err(22);
        }
        let resolve = |update, old| match update {
            protocol::TimestampUpdate::Set {
                seconds,
                nanoseconds,
            } => InodeTimestamp {
                seconds,
                nanoseconds,
            },
            protocol::TimestampUpdate::Now => current,
            protocol::TimestampUpdate::Omit => old,
        };
        metadata.accessed = resolve(times.access, metadata.accessed);
        metadata.modified = resolve(times.modification, metadata.modified);
        metadata.changed = current;
        Ok(())
    }

    pub fn parent(&self, node: &Node) -> Result<Node, i32> {
        self.validate(node)?;
        Ok(node.record.parent.clone().unwrap_or_else(|| node.clone()))
    }

    /// The namespace supplies its volume ID. Removed retained Nodes report
    /// link_count zero, while already open descriptions keep their authority.
    pub fn status(&self, node: &Node, volume: u64) -> Result<protocol::NodeStatus, i32> {
        self.validate(node)?;
        let metadata = node.record.metadata.read().map_err(|_| 5)?;
        let mut status = match node.kind() {
            NodeKind::Directory => protocol::NodeStatus {
                device: volume,
                node_id: u64::from(node.id()),
                kind: protocol::NODE_TYPE_DIRECTORY,
                mode: 0o040000,
                block_size: 4096,
                ..protocol::NodeStatus::default()
            },
            NodeKind::Null => null_device::node_status(volume, u64::from(node.id())),
            NodeKind::External => protocol::NodeStatus {
                device: volume,
                node_id: u64::from(node.id()),
                kind: protocol::NODE_TYPE_SPECIAL,
                mode: 0o020000,
                special_device: node.record.external.as_ref().ok_or(5)?.special_device,
                block_size: 4096,
                ..protocol::NodeStatus::default()
            },
        };
        status.mode = (status.mode & 0o170000) | u32::from(metadata.attributes.mode);
        status.uid = metadata.attributes.uid;
        status.gid = metadata.attributes.gid;
        status.link_count = metadata.links;
        status.change_time_seconds = metadata.changed.seconds;
        status.change_time_nanoseconds = metadata.changed.nanoseconds;
        status.access_time_seconds = metadata.accessed.seconds;
        status.access_time_nanoseconds = metadata.accessed.nanoseconds;
        status.modification_time_seconds = metadata.modified.seconds;
        status.modification_time_nanoseconds = metadata.modified.nanoseconds;
        Ok(status)
    }

    /// Real children only; the namespace owns virtual `.`/`..` mount edges.
    pub fn children(&self, node: &Node) -> Result<Vec<(Vec<u8>, Node)>, i32> {
        self.directory(node)?;
        Ok(self
            .children
            .get(&node.id())
            .map(|children| {
                children
                    .iter()
                    .map(|(name, child)| (name.clone(), child.clone()))
                    .collect()
            })
            .unwrap_or_default())
    }

    pub fn open_null(
        &self,
        node: &Node,
        credentials: Credentials<'_>,
        read: bool,
        write: bool,
        flags: u32,
    ) -> Result<NullDescription, i32> {
        self.validate(node)?;
        if node.kind() != NodeKind::Null {
            return Err(21);
        }
        let status = self.status(node, 0)?;
        let access = if read { protocol::ACCESS_AT_READ } else { 0 }
            | if write { protocol::ACCESS_AT_WRITE } else { 0 };
        if !permission_allows(
            u16::try_from(status.mode).map_err(|_| 22)?,
            status.kind,
            status.uid,
            status.gid,
            credentials.uid,
            credentials.gid,
            credentials.groups,
            access,
        ) {
            return Err(13);
        }
        NullDescription::new(read, write, flags)
    }

    /// Namespace traversal and native capability admission precede this call.
    /// Node owner, mode, uid/gid/groups and access mode are checked before the
    /// factory is exposed through the admitted open; no factory RPC occurs here.
    pub fn open_external(
        &self,
        node: &Node,
        credentials: Credentials<'_>,
        read: bool,
        write: bool,
        flags: u32,
    ) -> Result<ExternalOpen, i32> {
        self.validate(node)?;
        if node.kind() != NodeKind::External {
            return Err(95);
        }
        if (!read && !write)
            || flags & !(protocol::OPEN_STATUS_APPEND | protocol::OPEN_STATUS_NONBLOCK) != 0
        {
            return Err(22);
        }
        let status = self.status(node, 0)?;
        let access = u32::from(read) * protocol::ACCESS_AT_READ
            | u32::from(write) * protocol::ACCESS_AT_WRITE;
        if !permission_allows(
            u16::try_from(status.mode).map_err(|_| 22)?,
            status.kind,
            status.uid,
            status.gid,
            credentials.uid,
            credentials.gid,
            credentials.groups,
            access,
        ) {
            return Err(13);
        }
        let rights = mnu_abi::HANDLE_RIGHT_CONTROL
            | mnu_abi::HANDLE_RIGHT_DUPLICATE
            | mnu_abi::HANDLE_RIGHT_TRANSFER
            | mnu_abi::HANDLE_RIGHT_WAIT
            | if read { mnu_abi::HANDLE_RIGHT_READ } else { 0 }
            | if write {
                mnu_abi::HANDLE_RIGHT_WRITE
            } else {
                0
            };
        let options = if flags & protocol::OPEN_STATUS_NONBLOCK != 0 {
            mnu_abi::HANDLE_OPTION_NONBLOCKING
        } else {
            0
        };
        Ok(ExternalOpen {
            node: node.clone(),
            request: protocol::device_open::Request { rights, options },
        })
    }
}

impl Backend for DeviceFilesystem {
    type Node = Node;
    fn is_directory(&self, node: &Node) -> bool {
        self.directory(node).is_ok()
    }
    fn is_symlink(&self, _node: &Node) -> bool {
        false
    }
    fn search(&self, node: &Node, credentials: Credentials<'_>) -> Result<(), i32> {
        self.directory(node)?;
        let status = self.status(node, 0)?;
        if permission_allows(
            u16::try_from(status.mode).map_err(|_| 22)?,
            status.kind,
            status.uid,
            status.gid,
            credentials.uid,
            credentials.gid,
            credentials.groups,
            protocol::ACCESS_AT_EXECUTE,
        ) {
            Ok(())
        } else {
            Err(13)
        }
    }
    fn child(&self, node: &Node, name: &[u8]) -> Result<Node, i32> {
        self.directory(node)?;
        self.children
            .get(&node.id())
            .and_then(|children| children.get(name))
            .cloned()
            .ok_or(2)
    }
    fn symlink(&self, node: &Node) -> Result<Vec<u8>, i32> {
        self.validate(node)?;
        Err(22)
    }
    fn ancestry(&self, root: &Node, mut base: Node) -> Result<Vec<Node>, i32> {
        self.directory(root)?;
        self.directory(&base)?;
        let mut nodes = Vec::new();
        loop {
            if nodes.len() >= 1024 {
                return Err(40);
            }
            let at_root = base.id() == root.id();
            nodes.push(base.clone());
            if at_root {
                nodes.reverse();
                return Ok(nodes);
            }
            let parent = self.parent(&base)?;
            if parent.id() == base.id() {
                return Err(13);
            }
            base = parent;
        }
    }
}
