//! Timestamp policy stays in the provider. The storage writer commits the
//! staged inode with each completed block, including in-place overwrites.
//! Delegated data writes never preserve set-ID execution privileges.
use super::*;

pub(super) fn write(
    file: &mut File,
    filesystem: &Ext4,
    clock: crate::clock::Clock,
    offset: u64,
    bytes: &[u8],
) -> Result<usize, i32> {
    if bytes.is_empty() {
        return Ok(0);
    }
    offset.checked_add(bytes.len() as u64).ok_or(EFBIG)?;
    if filesystem.is_read_only() {
        return Err(EROFS);
    }
    if file.inode().flags().contains(InodeFlags::IMMUTABLE) {
        return Err(EPERM);
    }
    let now = clock()?;
    let previous_mtime = file.inode().mtime();
    file.inode_mut()
        .set_signed_timestamps(None, Some(now), Some(now))
        .map_err(timestamp_operations::timestamp_error)?;
    if file.inode().mode().bits() & 0o6000 != 0 {
        // A delegated WRITE Handle authorizes data changes, not preservation
        // of execution privileges. Invalidate those bits before any data can
        // change, including a write that later reports only a completed prefix.
        // Do not defer this to the post-data inode write: that write can fail.
        let mode = file.inode().mode() & !InodeMode::from_bits_retain(0o6000);
        file.inode_mut().set_mode(mode).map_err(errno)?;
        let mut invalidated = file.inode().clone();
        // Status changes now; data mtime is committed only with actual data.
        invalidated.set_mtime(previous_mtime);
        invalidated.write(filesystem).map_err(errno)?;
    }
    crate::positioned_io::transfer(offset, bytes.len(), true, |done, position, _| {
        file.write_bytes_at(&bytes[done..], position).map_err(errno)
    })
}
