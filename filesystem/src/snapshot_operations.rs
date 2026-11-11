//! Generic immutable-tree open descriptions. No package paths, signatures or
//! developer identities are interpreted by this filesystem mechanism.
use super::*;
use crate::readonly_tree::{Open, Tree};

impl FilesystemService {
    /// Capture caller-owned data without granting any new ambient authority.
    /// Returns an unpublished description; native publication owns its release.
    pub fn create_readonly_tree(&mut self, bytes: Vec<u8>) -> Result<u64, i32> {
        if self.snapshot_opens.len() >= 8192 {
            return Err(ENOSPC);
        }
        let tree = Tree::capture(bytes, &self.snapshot_budget)?;
        let identity_base = self.next_open_id;
        let id = identity_base.checked_add(tree.nodes() as u64).ok_or(EIO)?;
        let next = id
            .checked_add(1)
            .filter(|id| *id <= i64::MAX as u64)
            .ok_or(EIO)?;
        self.snapshot_opens.try_reserve(1).map_err(|_| ENOMEM)?;
        self.snapshot_opens.insert(
            id,
            Open {
                tree,
                node: 0,
                identity_base,
                offset: 0,
                flags: protocol::OPEN_AT_READ | protocol::OPEN_AT_DIRECTORY,
                cursor_records: true,
            },
        );
        self.next_open_id = next;
        Ok(id)
    }
    /// Remove writable/control/execute authority from every snapshot reference.
    pub fn snapshot_rights(&self, id: u64) -> Option<u64> {
        let open = self.snapshot_opens.get(&id)?;
        Some(
            mnu_abi::HANDLE_RIGHT_READ
                | mnu_abi::HANDLE_RIGHT_SEEK
                | mnu_abi::HANDLE_RIGHT_DUPLICATE
                | mnu_abi::HANDLE_RIGHT_TRANSFER
                | if open.tree.directory(open.node).ok()? {
                    0
                } else {
                    mnu_abi::HANDLE_RIGHT_MAP
                },
        )
    }
    pub(super) fn authorize_snapshot(
        &self,
        anchors: PathAnchors,
        credentials: protocol::Credentials,
        path: &[u8],
    ) -> Result<(), i32> {
        // These IDs must have been identified from native attachments by the
        // dispatcher. An ambient uid or a numeric request field is insufficient.
        if path.starts_with(b"/") || credentials.namespace.explicit_read_bases & 1 == 0 {
            return Err(EACCES);
        }
        let base = anchors.base_open_id.ok_or(EBADF)?;
        let open = self.snapshot_opens.get(&base).ok_or(EBADF)?;
        open.tree.resolve(open.node, path)?;
        Ok(())
    }
    pub(super) fn snapshot_open_at(
        &mut self,
        request: protocol::Header,
        base: u64,
        path: &[u8],
    ) -> Result<Response, i32> {
        if request.flags
            & (protocol::OPEN_AT_WRITE
                | protocol::OPEN_AT_CREATE
                | protocol::OPEN_AT_TRUNCATE
                | protocol::OPEN_AT_APPEND
                | protocol::OPEN_AT_EXCLUSIVE)
            != 0
        {
            return Err(EROFS);
        }
        if request.flags & protocol::OPEN_AT_EXECUTE != 0 {
            return Err(EACCES);
        }
        if self.snapshot_opens.len() >= 8192 {
            return Err(ENOSPC);
        }
        let parent = self.snapshot_opens.get(&base).ok_or(EBADF)?;
        let node = parent.tree.resolve(parent.node, path)?;
        let directory = parent.tree.directory(node)?;
        if request.flags & protocol::OPEN_AT_DIRECTORY != 0 && !directory {
            return Err(ENOTDIR);
        }
        let open = Open {
            tree: parent.tree.clone(),
            node,
            identity_base: parent.identity_base,
            offset: 0,
            flags: protocol::OPEN_AT_READ
                | if directory {
                    protocol::OPEN_AT_DIRECTORY
                } else {
                    0
                },
            cursor_records: request.flags & protocol::OPEN_AT_CURSOR_RECORDS != 0,
        };
        let id = self.next_open_id;
        let next = self
            .next_open_id
            .checked_add(1)
            .filter(|id| *id <= i64::MAX as u64)
            .ok_or(EIO)?;
        self.snapshot_opens.try_reserve(1).map_err(|_| ENOMEM)?;
        self.snapshot_opens.insert(id, open);
        self.next_open_id = next;
        let mut response = self.success(request);
        response.header.open_id = id;
        Ok(response)
    }
    pub(super) fn snapshot_status(
        &self,
        request: protocol::Header,
        open: &Open,
        node: usize,
    ) -> Result<Response, i32> {
        let directory = open.tree.directory(node)?;
        let size = if directory {
            0
        } else {
            open.tree.length(node)?
        };
        let status = protocol::NodeStatus {
            device: u64::MAX,
            node_id: open.identity_base + node as u64,
            kind: if directory {
                protocol::NODE_TYPE_DIRECTORY
            } else {
                protocol::NODE_TYPE_REGULAR
            },
            mode: if directory { 0o555 } else { 0o444 },
            size,
            blocks: size.div_ceil(512),
            block_size: 4096,
            uid: 0,
            gid: 0,
            link_count: 1,
            special_device: 0,
            access_time_seconds: 0,
            access_time_nanoseconds: 0,
            modification_time_seconds: 0,
            modification_time_nanoseconds: 0,
            change_time_seconds: 0,
            change_time_nanoseconds: 0,
        };
        let mut response = self.success(request);
        response.payload.resize(protocol::NODE_STATUS_LEN, 0);
        protocol::encode_node_status(status, &mut response.payload).map_err(|_| EIO)?;
        response.header.length = response.payload.len() as u32;
        Ok(response)
    }
}
