//! Initial boot policy reads from the selected immutable System partition.
//! Reuse the userspace filesystem reader; no POSIX endpoint exists yet.

use std::sync::{Arc, Mutex};

use filesystem_service::bootstrap_read::BootstrapReader;
use filesystem_service::platform_storage::{MochiDisk, find_system_partition};
use filesystem_service::storage::PartitionIo;
use mochi_user_syscall::{EIO, SysError};

const MAX_BOOT_POLICY_BYTES: usize = 256 * 1024;
static READER: Mutex<Option<BootstrapReader>> = Mutex::new(None);

pub(super) fn read(path: &str) -> Result<Vec<u8>, SysError> {
    let mut reader = READER.lock().map_err(|_| SysError::from_raw(EIO as i64))?;
    if reader.is_none() {
        let (first_lba, sector_count) =
            find_system_partition(0).map_err(|_| SysError::from_raw(EIO as i64))?;
        let partition = Arc::new(PartitionIo::new(MochiDisk::new(0), first_lba, sector_count));
        *reader =
            Some(BootstrapReader::load(partition).map_err(|_| SysError::from_raw(EIO as i64))?);
    }
    reader
        .as_ref()
        .ok_or_else(|| SysError::from_raw(EIO as i64))?
        .read(path, MAX_BOOT_POLICY_BYTES)
        .map_err(|_| SysError::from_raw(EIO as i64))
}
