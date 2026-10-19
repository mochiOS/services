//! Validate every affected timestamp before a public rename or even private
//! retention-pin evacuation. Persistence never selects a second clock instant.
//! Both renamed and replaced inodes get ctime; their data times are preserved.
use super::*;
use ext4plus::inode::InodeTimestamp;

fn stage(
    old: &mut Dir,
    new: &mut Dir,
    source: &mut Inode,
    destination: &mut Option<(u64, Inode)>,
    now: InodeTimestamp,
) -> Result<(), i32> {
    for parent in [old, new] {
        parent
            .inode_mut()
            .set_signed_timestamps(None, Some(now), Some(now))
            .map_err(timestamp_operations::timestamp_error)?;
    }
    source
        .set_signed_timestamps(None, None, Some(now))
        .map_err(timestamp_operations::timestamp_error)?;
    if let Some((_, inode)) = destination {
        inode
            .set_signed_timestamps(None, None, Some(now))
            .map_err(timestamp_operations::timestamp_error)?;
    }
    Ok(())
}

impl FilesystemService {
    pub(super) fn prepare_rename_times(
        &mut self,
        filesystem: &Ext4,
        volume: u32,
        old: &mut Dir,
        new: &mut Dir,
        source: &mut Inode,
        destination: &mut Option<(u64, Inode)>,
    ) -> Result<InodeTimestamp, i32> {
        let retained = if source.file_type().is_dir() {
            if self.directory_is_at_or_below(filesystem, source, new.inode().clone())? {
                return Err(EINVAL);
            }
            match destination.as_ref() {
                Some((_, inode)) => Some(
                    self.empty_directory_private_entries(filesystem, volume, inode)?
                        .ok_or(ENOTEMPTY)?,
                ),
                None => None,
            }
        } else {
            None
        };
        if filesystem.is_read_only() {
            return Err(EROFS);
        }
        for inode in [old.inode(), new.inode(), source] {
            if inode.flags().contains(InodeFlags::IMMUTABLE) {
                return Err(EPERM);
            }
        }
        if destination
            .as_ref()
            .is_some_and(|(_, inode)| inode.flags().contains(InodeFlags::IMMUTABLE))
        {
            return Err(EPERM);
        }
        let now = (self.clock)()?;
        stage(old, new, source, destination, now)?;
        if let Some(retained) = retained {
            let inode = &destination.as_ref().ok_or(EIO)?.1;
            if !self.evacuate_directory_private_entries(filesystem, volume, inode, retained)? {
                return Err(ENOTEMPTY);
            }
            // Evacuation can grow the volume root or shrink the replaced
            // directory. Never write a pre-evacuation extent map afterwards.
            *old = Dir::open_inode(
                filesystem,
                Inode::read(filesystem, old.inode().index).map_err(errno)?,
            )
            .map_err(errno)?;
            *new = Dir::open_inode(
                filesystem,
                Inode::read(filesystem, new.inode().index).map_err(errno)?,
            )
            .map_err(errno)?;
            *source = Inode::read(filesystem, source.index).map_err(errno)?;
            let target = &mut destination.as_mut().ok_or(EIO)?.1;
            *target = Inode::read(filesystem, target.index).map_err(errno)?;
            stage(old, new, source, destination, now)?;
        }
        Ok(now)
    }

    pub(super) fn finish_rename_times(
        &self,
        filesystem: &Ext4,
        old: &Dir,
        new: &Dir,
        now: InodeTimestamp,
    ) -> Result<(), i32> {
        // Namespace/reference ownership must already be recorded by the caller.
        // Storage errors here are terminal; they never authorize rename replay.
        for (position, index) in [old.inode().index, new.inode().index]
            .into_iter()
            .enumerate()
        {
            if position == 1 && new.inode().index == old.inode().index {
                continue;
            }
            let mut inode = Inode::read(filesystem, index).map_err(errno)?;
            inode
                .set_signed_timestamps(None, Some(now), Some(now))
                .map_err(timestamp_operations::timestamp_error)?;
            inode.write(filesystem).map_err(errno)?;
        }
        Ok(())
    }
}
