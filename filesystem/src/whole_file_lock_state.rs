//! No allocation, process policy, filesystem I/O or kernel lock ownership.
use super::*;
use protocol::whole_file_lock as wire;

impl FilesystemService {
    /// Apply an authenticated provider request to one open description.
    /// Different opens conflict even in one process; aliases share this slot.
    /// A conversion releases the old mode before attempting the new one,
    /// matching flock's deliberately non-atomic conversion semantics.
    pub fn whole_file_lock(&mut self, open_id: u64, mode: u32) -> Result<(), i32> {
        if !matches!(mode, wire::SHARED | wire::EXCLUSIVE | wire::UNLOCK) {
            return Err(EINVAL);
        }
        let open = self.opens.get_mut(&open_id).ok_or(EBADF)?;
        if open.inode.file_type().is_fifo() {
            return Err(ENOTSUP);
        }
        if mode == wire::UNLOCK {
            open.whole_file_lock = 0;
            return Ok(());
        }
        if open.whole_file_lock == mode {
            return Ok(());
        }
        let key = (open.volume, open.inode.index);
        open.whole_file_lock = 0;
        if self.opens.values().any(|other| {
            (other.volume, other.inode.index) == key
                && other.whole_file_lock != 0
                && (mode == wire::EXCLUSIVE || other.whole_file_lock == wire::EXCLUSIVE)
        }) {
            return Err(11);
        }
        self.opens.get_mut(&open_id).ok_or(EBADF)?.whole_file_lock = mode;
        Ok(())
    }
}
