use std::error::Error;
use std::fmt;

use mochi_user_platform::storage;

use crate::storage::SectorDevice;

const DATA_PARTITION_TYPE: [u8; 16] = [
    0x68, 0x63, 0x6f, 0x6d, 0x4f, 0x69, 0x00, 0x53, 0x80, 0x00, 0x6d, 0x50, 0x61, 0x72, 0x74, 0x02,
];
const SYSTEM_PARTITION_TYPE: [u8; 16] = [
    0x68, 0x63, 0x6f, 0x6d, 0x4f, 0x69, 0x00, 0x53, 0x80, 0x00, 0x6d, 0x50, 0x61, 0x72, 0x74, 0x01,
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MochiStorageError(i64);

impl fmt::Display for MochiStorageError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "mochiOS storage error {}", self.0)
    }
}

impl MochiStorageError {
    pub const fn is_not_found(self) -> bool {
        self.0 == -2
    }
}

impl Error for MochiStorageError {}

pub struct MochiDisk {
    disk_id: u32,
}

impl MochiDisk {
    pub const fn new(disk_id: u32) -> Self {
        Self { disk_id }
    }
}

impl SectorDevice for MochiDisk {
    type Error = MochiStorageError;

    fn read_sectors(&mut self, lba: u64, bytes: &mut [u8]) -> Result<(), Self::Error> {
        for (index, chunk) in bytes.chunks_mut(256 * 1024).enumerate() {
            storage::block_read(self.disk_id, lba + (index * 512) as u64, chunk)
                .map_err(|error| MochiStorageError(error.raw()))?;
        }
        Ok(())
    }

    fn write_sectors(&mut self, lba: u64, bytes: &[u8]) -> Result<(), Self::Error> {
        for (index, chunk) in bytes.chunks(256 * 1024).enumerate() {
            storage::block_write(self.disk_id, lba + (index * 512) as u64, chunk)
                .map_err(|error| MochiStorageError(error.raw()))?;
        }
        Ok(())
    }

    fn flush(&mut self) -> Result<(), Self::Error> {
        storage::block_flush(self.disk_id)
            .map(|_| ())
            .map_err(|error| MochiStorageError(error.raw()))
    }
}

pub fn find_data_partition(disk_id: u32) -> Result<(u64, u64), MochiStorageError> {
    find_partition(disk_id, DATA_PARTITION_TYPE, 1, 0)
}

/// Match the boot loader's ordering: A is the lower-LBA System partition.
/// Never silently use legacy discovery when boot metadata cannot be read.
pub fn find_system_partition(disk_id: u32) -> Result<(u64, u64), MochiStorageError> {
    use mochi_user_platform::boot;
    let slot = boot::system_slot().map_err(|error| MochiStorageError(error.raw()))?;
    let slot = u8::try_from(slot).map_err(|_| MochiStorageError(-22))?;
    let (count, ordinal) = match slot {
        boot::BOOT_SYSTEM_SLOT_LEGACY => (1, 0),
        boot::BOOT_SYSTEM_SLOT_A => (2, 0),
        boot::BOOT_SYSTEM_SLOT_B => (2, 1),
        _ => return Err(MochiStorageError(-22)),
    };
    find_partition(disk_id, SYSTEM_PARTITION_TYPE, count, ordinal)
}

fn find_partition(
    disk_id: u32,
    kind: [u8; 16],
    count: usize,
    ordinal: usize,
) -> Result<(u64, u64), MochiStorageError> {
    use crate::partition::{DiscoveryError, find_by_type_ordinal};
    match find_by_type_ordinal(&mut MochiDisk::new(disk_id), kind, count, ordinal) {
        Ok(Some(range)) => Ok((range.first_lba, range.sector_count)),
        Ok(None) => Err(MochiStorageError(-2)),
        Err(DiscoveryError::Device(error)) => Err(error),
        Err(DiscoveryError::InvalidTable | DiscoveryError::AmbiguousType) => {
            Err(MochiStorageError(-22))
        }
    }
}
