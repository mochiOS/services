//! Removed directory references keep their inode, blocks and original `..`.
//! A retained child also pins its parent identity, even without a direct open.
//! This is live-reference retention; persistent orphan recovery after a service
//! or machine crash is a separate, still-required storage lifecycle mechanism.
use super::*;

pub(super) struct RetainedDirectory {
    pub(super) filesystem: Ext4,
    pub(super) inode: Inode,
    pub(super) parent: u64,
}

impl FilesystemService {
    pub(super) fn directory_is_referenced(&self, node_id: u64) -> bool {
        self.opens.values().any(|open| open.node_id == node_id)
            || self
                .removed_directories
                .values()
                .any(|child| child.parent == node_id)
    }

    pub(super) fn collect_removed_directories(&mut self, mut node_id: u64) -> Result<(), i32> {
        while !self.directory_is_referenced(node_id) {
            let Some(retained) = self.removed_directories.get(&node_id) else {
                break;
            };
            let parent = retained.parent;
            // Keep the ownership record on storage failure. Never make a
            // failed reclamation eligible for reuse by dropping bookkeeping.
            retained
                .filesystem
                .reclaim_unlinked_inode(retained.inode.clone())
                .map_err(errno)?;
            self.removed_directories.remove(&node_id);
            self.nodes.remove(&node_id);
            node_id = parent;
        }
        Ok(())
    }

    pub(super) fn check_missing_directory(
        &self,
        resolution: &Resolution,
        volume: u32,
    ) -> Result<(), i32> {
        if let Resolution::Missing { parent, .. } = resolution {
            if self
                .removed_directories
                .contains_key(&scoped_node_id(volume, parent))
            {
                return Err(ENOENT);
            }
        }
        Ok(())
    }
}
