use std::error::Error;
use std::fmt;

use mochi_user_platform::storage;

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
    const GPT_SIGNATURE: &[u8; 8] = b"EFI PART";
    const MAX_PARTITIONS: u32 = 128;

    let mut disk = MochiDisk::new(disk_id);
    let mut header = [0u8; 512];
    disk.read_sectors(1, &mut header)?;
    if &header[..8] != GPT_SIGNATURE {
        return Err(MochiStorageError(-22));
    }
    let entries_lba = read_u64(&header, 72).ok_or(MochiStorageError(-22))?;
    let entry_count = read_u32(&header, 80).ok_or(MochiStorageError(-22))?;
    let entry_size = read_u32(&header, 84).ok_or(MochiStorageError(-22))?;
    if entries_lba == 0 || entry_count == 0 || !(128..=512).contains(&entry_size) {
        return Err(MochiStorageError(-22));
    }

    let mut sectors = [0u8; 1024];
    for ordinal in 0..entry_count.min(MAX_PARTITIONS) {
        let byte_offset = u64::from(ordinal)
            .checked_mul(u64::from(entry_size))
            .ok_or(MochiStorageError(-22))?;
        let sector_offset = byte_offset / 512;
        let offset_in_sector = (byte_offset % 512) as usize;
        disk.read_sectors(
            entries_lba
                .checked_add(sector_offset)
                .ok_or(MochiStorageError(-22))?,
            &mut sectors,
        )?;
        let end = offset_in_sector
            .checked_add(entry_size as usize)
            .filter(|end| *end <= sectors.len())
            .ok_or(MochiStorageError(-22))?;
        let entry = &sectors[offset_in_sector..end];
        if entry[..16].iter().all(|byte| *byte == 0) {
            break;
        }
        if entry[..16] != DATA_PARTITION_TYPE {
            continue;
        }
        let first_lba = read_u64(entry, 32).ok_or(MochiStorageError(-22))?;
        let last_lba = read_u64(entry, 40).ok_or(MochiStorageError(-22))?;
        let sector_count = last_lba
            .checked_sub(first_lba)
            .and_then(|span| span.checked_add(1))
            .filter(|count| *count != 0)
            .ok_or(MochiStorageError(-22))?;
        return Ok((first_lba, sector_count));
    }
    Err(MochiStorageError(-2))
}

fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(bytes.get(offset..offset + 4)?.try_into().ok()?))
}

fn read_u64(bytes: &[u8], offset: usize) -> Option<u64> {
    Some(u64::from_le_bytes(bytes.get(offset..offset + 8)?.try_into().ok()?))
}
