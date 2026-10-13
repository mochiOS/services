//! Service-owned immutable device filesystem. Nodes, not paths, select devices.

use std::sync::Arc;

use mochios_filesystem_protocol as protocol;

use crate::null_device::{self, NullDescription};
use crate::path_walk::{Backend, Credentials};
use crate::service::permission_allows;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NodeKind {
    Directory,
    Null,
}

/// Only the owning filesystem constructs node references. Numeric IDs alone
/// cannot be used to manufacture authority or import another filesystem's node.
#[derive(Clone)]
pub struct Node {
    owner: Arc<()>,
    kind: NodeKind,
}

impl Node {
    pub fn id(&self) -> u32 {
        match self.kind {
            NodeKind::Directory => 1,
            NodeKind::Null => 2,
        }
    }

    pub fn kind(&self) -> NodeKind {
        self.kind
    }
}

#[derive(Default)]
pub struct DeviceFilesystem {
    owner: Arc<()>,
}

impl DeviceFilesystem {
    pub fn root(&self) -> Node {
        self.node(NodeKind::Directory)
    }

    fn node(&self, kind: NodeKind) -> Node {
        Node {
            owner: self.owner.clone(),
            kind,
        }
    }

    fn validate(&self, node: &Node) -> Result<(), i32> {
        if Arc::ptr_eq(&self.owner, &node.owner) {
            Ok(())
        } else {
            Err(13)
        }
    }

    /// The mount namespace supplies its volume ID; this is not a wire operation.
    pub fn status(&self, node: &Node, volume: u64) -> Result<protocol::NodeStatus, i32> {
        self.validate(node)?;
        Ok(match node.kind {
            NodeKind::Directory => protocol::NodeStatus {
                device: volume,
                node_id: u64::from(node.id()),
                kind: protocol::NODE_TYPE_DIRECTORY,
                mode: 0o040555,
                link_count: 2,
                block_size: 4096,
                ..protocol::NodeStatus::default()
            },
            NodeKind::Null => null_device::node_status(volume, u64::from(node.id())),
        })
    }

    /// Real children only. The mount namespace supplies virtual `.`/`..` edges.
    pub fn children(&self, node: &Node) -> Result<Vec<(Vec<u8>, Node)>, i32> {
        self.validate(node)?;
        if node.kind != NodeKind::Directory {
            return Err(20);
        }
        Ok(vec![(b"null".to_vec(), self.node(NodeKind::Null))])
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
        if node.kind != NodeKind::Null {
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
}

impl Backend for DeviceFilesystem {
    type Node = Node;

    fn is_directory(&self, node: &Node) -> bool {
        self.validate(node).is_ok() && node.kind == NodeKind::Directory
    }

    fn is_symlink(&self, _node: &Node) -> bool {
        false
    }

    fn search(&self, node: &Node, credentials: Credentials<'_>) -> Result<(), i32> {
        self.validate(node)?;
        if !self.is_directory(node) {
            return Err(20);
        }
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
        self.validate(node)?;
        if !self.is_directory(node) {
            return Err(20);
        }
        match name {
            b"null" => Ok(self.node(NodeKind::Null)),
            _ => Err(2),
        }
    }

    fn symlink(&self, node: &Node) -> Result<Vec<u8>, i32> {
        self.validate(node)?;
        Err(22)
    }

    fn ancestry(&self, root: &Node, base: Node) -> Result<Vec<Node>, i32> {
        self.validate(root)?;
        self.validate(&base)?;
        if !self.is_directory(root) || !self.is_directory(&base) {
            return Err(20);
        }
        Ok(vec![base])
    }
}
