use std::error::Error;
use std::fmt;

use mochi_user_platform::storage::{self, StorageControlRequest};

use crate::storage::SectorDevice;

const DATA_PARTITION_TYPE: [u8; 16] = [
    0x68, 0x63, 0x6f, 0x6d, 0x4f, 0x69, 0x00, 0x53, 0x80, 0x00, 0x6d, 0x50, 0x61, 0x72, 0x74, 0x02,
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MochiStorageError(i64);

impl fmt::Display for MochiStorageError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "mochiOS storage error {}", self.0)
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
    for ordinal in 0..128 {
        let guids = storage::control(StorageControlRequest {
            operation: storage::STORAGE_CONTROL_INSPECT,
            device_id: disk_id,
            arguments: [storage::STORAGE_QUERY_PARTITION_GUIDS, ordinal, 0, 0],
            ..Default::default()
        })
        .map_err(|error| MochiStorageError(error.raw()))?;
        if guids.status == storage::STORAGE_STATUS_END {
            break;
        }
        if guids.status != storage::STORAGE_STATUS_OK {
            return Err(MochiStorageError(-(guids.status as i64)));
        }
        let mut partition_type = [0u8; 16];
        partition_type[..8].copy_from_slice(&guids.values[0].to_le_bytes());
        partition_type[8..].copy_from_slice(&guids.values[1].to_le_bytes());
        if partition_type != DATA_PARTITION_TYPE {
            continue;
        }
        let range = storage::control(StorageControlRequest {
            operation: storage::STORAGE_CONTROL_INSPECT,
            device_id: disk_id,
            arguments: [storage::STORAGE_QUERY_PARTITION_RANGE, ordinal, 0, 0],
            ..Default::default()
        })
        .map_err(|error| MochiStorageError(error.raw()))?;
        if range.status != storage::STORAGE_STATUS_OK || range.values[1] == 0 {
            return Err(MochiStorageError(-(range.status as i64)));
        }
        return Ok((range.values[0], range.values[1]));
    }
    Err(MochiStorageError(-2))
}
