//! Timestamp policy stays in the provider. The storage writer commits the
//! staged inode with each completed block, including in-place overwrites.
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
    file.inode_mut()
        .set_signed_timestamps(None, Some(now), Some(now))
        .map_err(timestamp_operations::timestamp_error)?;
    crate::positioned_io::transfer(offset, bytes.len(), true, |done, position, _| {
        file.write_bytes_at(&bytes[done..], position).map_err(errno)
    })
}
