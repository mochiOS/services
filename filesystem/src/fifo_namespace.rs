//! Disk namespace and retained identity for FIFO channels. Actual stream bytes
//! and blocking-open policy belong to the userspace FIFO owner, not ext4.
use super::*;

impl FilesystemService {
    /// Create an exclusive FIFO entry in one serialized path operation.
    /// Uses MKDIR_AT's ordered root/base flags. The trusted policy caller must
    /// apply umask before supplying mode and authenticate these credentials.
    /// No data endpoint or open description is created by this operation.
    pub fn create_fifo_at(
        &mut self,
        request: protocol::Header,
        path: &[u8],
        anchors: PathAnchors,
        credentials: protocol::Credentials,
    ) -> Result<Response, i32> {
        self.create_special_at_inner(request, path, anchors, credentials, FileType::Fifo, false)
    }

    /// Resolve, check access, and retain the exact FIFO inode atomically. This
    /// does not complete a POSIX open or create a readable/writable disk File.
    /// The native adapter must publish only a metadata reference, then let the
    /// channel owner perform its open rendezvous and data-Handle publication.
    pub fn open_fifo_at_retained(
        &mut self,
        request: protocol::Header,
        path: &[u8],
        anchors: PathAnchors,
        credentials: protocol::Credentials,
    ) -> Result<Response, i32> {
        let allowed = protocol::OPEN_AT_READ
            | protocol::OPEN_AT_WRITE
            | protocol::OPEN_AT_NOFOLLOW
            | protocol::OPEN_AT_ROOT_ATTACHED
            | protocol::OPEN_AT_BASE_ATTACHED;
        let access = request.flags & (protocol::OPEN_AT_READ | protocol::OPEN_AT_WRITE);
        if request.flags & !allowed != 0
            || !matches!(access, protocol::OPEN_AT_READ | protocol::OPEN_AT_WRITE)
            || (request.flags & protocol::OPEN_AT_ROOT_ATTACHED != 0)
                != anchors.root_open_id.is_some()
            || (request.flags & protocol::OPEN_AT_BASE_ATTACHED != 0)
                != anchors.base_open_id.is_some()
        {
            return Err(EINVAL);
        }
        let (resolution, filesystem, volume) = self.resolve_open_path(
            path,
            anchors,
            lookup_symlinks(path, request.flags & protocol::OPEN_AT_NOFOLLOW != 0),
            credentials.effective_uid,
            credentials.effective_gid,
            credentials.supplementary_groups(),
        )?;
        let inode = match resolution {
            Resolution::Found { inode, .. } => inode,
            Resolution::Missing { .. } => return Err(ENOENT),
        };
        if inode.file_type().is_symlink() && request.flags & protocol::OPEN_AT_NOFOLLOW != 0 {
            return Err(ELOOP);
        }
        if !inode.file_type().is_fifo() {
            return Err(EINVAL);
        }
        let metadata = inode.metadata();
        let requested = if access == protocol::OPEN_AT_READ {
            protocol::ACCESS_AT_READ
        } else {
            protocol::ACCESS_AT_WRITE
        };
        if !permission_allows(
            metadata.mode(),
            protocol::NODE_TYPE_FIFO,
            metadata.uid(),
            metadata.gid(),
            credentials.effective_uid,
            credentials.effective_gid,
            credentials.supplementary_groups(),
            requested,
        ) {
            return Err(EACCES);
        }
        let next_open = self.reserve_inode_description()?;
        self.retain_inode_description(request, filesystem, volume, inode, next_open)
    }
}
