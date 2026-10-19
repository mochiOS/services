//! Access-time policy belongs to the provider, not the kernel or its pager.
//! Read-only volumes and immutable inodes have no access-time writes. Zero-byte
//! requests do not read the clock. Nonempty successful requests include EOF.
use super::*;

pub(super) fn prepare(
    inode: &Inode,
    filesystem: &Ext4,
    clock: crate::clock::Clock,
    requested: bool,
) -> Result<Option<Inode>, i32> {
    if !requested || filesystem.is_read_only() || inode.flags().contains(InodeFlags::IMMUTABLE) {
        return Ok(None);
    }
    let now = clock()?;
    let mut staged = inode.clone();
    staged
        .set_signed_timestamps(Some(now), None, None)
        .map_err(timestamp_operations::timestamp_error)?;
    Ok(Some(staged))
}

pub(super) fn commit(staged: Option<Inode>, filesystem: &Ext4) -> Result<Option<Inode>, i32> {
    let Some(mut inode) = staged else {
        return Ok(None);
    };
    inode.write(filesystem).map_err(errno)?;
    Ok(Some(inode))
}

pub(super) fn read(
    file: &mut File,
    filesystem: &Ext4,
    clock: crate::clock::Clock,
    offset: u64,
    output: &mut [u8],
) -> Result<usize, i32> {
    if output.is_empty() {
        return Ok(0);
    }
    offset.checked_add(output.len() as u64).ok_or(EFBIG)?;
    let staged = prepare(file.inode(), filesystem, clock, true)?;
    let done = crate::positioned_io::transfer(offset, output.len(), false, |done, position, _| {
        file.read_bytes_at(&mut output[done..], position)
            .map_err(errno)
    })?;
    // Publish neither a sequential offset nor a successful read before the
    // required metadata write succeeds. These are positioned, non-consuming
    // backing reads; an I/O error must not turn into an unreported cursor move.
    if let Some(inode) = commit(staged, filesystem)? {
        *file.inode_mut() = inode;
    }
    Ok(done)
}
