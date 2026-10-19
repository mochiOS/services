//! Namespace lookup, credential checks and timestamp mutation are one serialized
//! provider operation. The caller may supply a trusted clock, never a ctime.
use super::*;
use ext4plus::inode::{InodeTimestamp, TimestampError};
use protocol::{FileTimeUpdate, TimestampUpdate};

pub(super) fn timestamp_error(error: TimestampError) -> i32 {
    match error {
        TimestampError::InvalidNanoseconds => EINVAL,
        TimestampError::OutOfRange => 75, // filesystem wire EOVERFLOW, not a native status
        TimestampError::InvalidInodeLayout => EIO,
    }
}

impl FilesystemService {
    pub(super) fn prepare_link_times(
        &self,
        filesystem: &Ext4,
        parent: &mut Dir,
        target: &mut Inode,
    ) -> Result<(), i32> {
        // Known failures precede clock access and every inode/directory write.
        if target.flags().contains(InodeFlags::IMMUTABLE) {
            return Err(EPERM);
        }
        if target.links_count() == u16::MAX {
            return Err(EMLINK);
        }
        let now = self.metadata_change_time(parent.inode(), filesystem)?;
        parent
            .inode_mut()
            .set_signed_timestamps(None, Some(now), Some(now))
            .map_err(timestamp_error)?;
        target
            .set_signed_timestamps(None, None, Some(now))
            .map_err(timestamp_error)?;
        Ok(())
    }

    pub(super) fn prepare_creation_parent(
        &self,
        filesystem: &Ext4,
        parent: &mut Dir,
    ) -> Result<InodeTimestamp, i32> {
        let now = self.metadata_change_time(parent.inode(), filesystem)?;
        parent
            .inode_mut()
            .set_signed_timestamps(None, Some(now), Some(now))
            .map_err(timestamp_error)?;
        Ok(now)
    }

    pub(super) fn metadata_change_time(
        &self,
        inode: &Inode,
        filesystem: &Ext4,
    ) -> Result<InodeTimestamp, i32> {
        if filesystem.is_read_only() {
            return Err(EROFS);
        }
        if inode.flags().contains(InodeFlags::IMMUTABLE) {
            return Err(EPERM);
        }
        (self.clock)()
    }

    pub fn set_times_at(
        &mut self,
        request: protocol::Header,
        path: &[u8],
        anchors: PathAnchors,
        credentials: protocol::Credentials,
        times: FileTimeUpdate,
        now: impl FnOnce() -> Result<InodeTimestamp, i32>,
    ) -> Result<Response, i32> {
        if !times.valid()
            || request.flags & !protocol::SET_TIMES_AT_FLAGS_ALL != 0
            || (request.flags & protocol::SET_TIMES_AT_ROOT_ATTACHED != 0)
                != anchors.root_open_id.is_some()
            || (request.flags & protocol::SET_TIMES_AT_BASE_ATTACHED != 0)
                != anchors.base_open_id.is_some()
        {
            return Err(EINVAL);
        }
        let follow = if request.flags & protocol::SET_TIMES_AT_NOFOLLOW != 0 {
            FollowSymlinks::ExcludeFinalComponent
        } else {
            FollowSymlinks::All
        };
        // Keep device nodes visible to an unchanged request, without pretending
        // that their service-owned immutable metadata can be changed.
        let (inode, filesystem, volume) = match self.resolve_namespace_path(
            path,
            anchors,
            follow,
            credentials.effective_uid,
            credentials.effective_gid,
            credentials.supplementary_groups(),
        )? {
            Some(path_walk::Resolution::Found { inode, .. }) => {
                if inode.device_node().is_some() {
                    return if times.unchanged() {
                        Ok(self.success(request))
                    } else {
                        Err(EROFS)
                    };
                }
                let namespace = self.namespace.as_ref().ok_or(EIO)?;
                let filesystem = namespace.filesystem(&inode)?.clone();
                let volume = u32::try_from(inode.id().volume).map_err(|_| EIO)?;
                (inode.into_inode()?, filesystem, volume)
            }
            Some(path_walk::Resolution::Missing { .. }) => return Err(ENOENT),
            None => self.resolve_scoped_inode(
                path,
                anchors,
                follow,
                credentials.effective_uid,
                credentials.effective_gid,
                credentials.supplementary_groups(),
            )?,
        };
        let node_id = scoped_node_id(volume, &inode);
        self.set_inode_times(inode, filesystem, node_id, credentials, times, now)?;
        Ok(self.success(request))
    }

    /// `open_id` must have been resolved from the one explicitly attached
    /// provider-owned CONTROL|TRANSFER Handle, not from a client numeric ID.
    pub fn set_times_handle(
        &mut self,
        request: protocol::Header,
        open_id: u64,
        credentials: protocol::Credentials,
        times: FileTimeUpdate,
        now: impl FnOnce() -> Result<InodeTimestamp, i32>,
    ) -> Result<Response, i32> {
        if request.flags != 0 || !times.valid() {
            return Err(EINVAL);
        }
        if self.opens.device(open_id).is_some() {
            return if times.unchanged() {
                Ok(self.success(request))
            } else {
                Err(EROFS)
            };
        }
        let open = self.opens.get(&open_id).ok_or(EBADF)?;
        self.set_inode_times(
            open.inode.clone(),
            open.filesystem.clone(),
            open.node_id,
            credentials,
            times,
            now,
        )?;
        Ok(self.success(request))
    }

    fn set_inode_times(
        &mut self,
        inode: Inode,
        filesystem: Ext4,
        node_id: u64,
        credentials: protocol::Credentials,
        times: FileTimeUpdate,
        now: impl FnOnce() -> Result<InodeTimestamp, i32>,
    ) -> Result<(), i32> {
        if times.unchanged() {
            return Ok(());
        }
        if filesystem.is_read_only() {
            return Err(EROFS);
        }
        // Fresh metadata: another description may have changed mode/ownership
        // since this one opened. Retain identity even after rename or unlink.
        let mut inode = Inode::read(&filesystem, inode.index).map_err(errno)?;
        if inode.flags().contains(InodeFlags::IMMUTABLE) {
            return Err(EPERM);
        }
        let uid = credentials.effective_uid;
        if uid != 0 && uid != inode.uid() {
            if !times.both_now() {
                return Err(EPERM);
            }
            if !permission_allows(
                inode.mode().bits(),
                node_type(inode.file_type()),
                inode.uid(),
                inode.gid(),
                uid,
                credentials.effective_gid,
                credentials.supplementary_groups(),
                protocol::ACCESS_AT_WRITE,
            ) {
                return Err(EACCES);
            }
        }
        // One trusted instant for both NOW fields and ctime. No clock reads
        // or writes for OMIT/OMIT, invalid authority, or a read-only volume.
        let current = now()?;
        let resolve = |value| match value {
            TimestampUpdate::Set {
                seconds,
                nanoseconds,
            } => Some(InodeTimestamp {
                seconds,
                nanoseconds,
            }),
            TimestampUpdate::Now => Some(current),
            TimestampUpdate::Omit => None,
        };
        inode
            .set_signed_timestamps(
                resolve(times.access),
                resolve(times.modification),
                Some(current),
            )
            .map_err(timestamp_error)?;
        inode.write(&filesystem).map_err(errno)?;
        for open in self.opens.values_mut() {
            if open.node_id == node_id {
                open.inode = inode.clone();
                if let Some(file) = &mut open.file {
                    *file.inode_mut() = inode.clone();
                }
            }
        }
        Ok(())
    }
}
