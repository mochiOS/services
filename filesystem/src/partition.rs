//! Bounded GPT discovery owned by the user-space filesystem service.

use crate::storage::{SECTOR_BYTES, SectorDevice};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PartitionRange {
    pub first_lba: u64,
    pub sector_count: u64,
}

#[derive(Debug, PartialEq, Eq)]
pub enum DiscoveryError<E> {
    Device(E),
    InvalidTable,
    AmbiguousType,
}

/// Finds one partition of the caller-selected type. Names and filesystem
/// policy are intentionally outside this parser. Empty slots are not EOF.
pub fn find_by_type<D: SectorDevice>(
    disk: &mut D,
    partition_type: [u8; 16],
) -> Result<Option<PartitionRange>, DiscoveryError<D::Error>> {
    let invalid = || DiscoveryError::InvalidTable;
    if partition_type == [0; 16] {
        return Err(invalid());
    }
    let mut header = [0u8; SECTOR_BYTES];
    disk.read_sectors(1, &mut header)
        .map_err(DiscoveryError::Device)?;
    let size = u32_at(&header, 12) as usize;
    if &header[..8] != b"EFI PART"
        || u32_at(&header, 8) != 0x0001_0000
        || !(92..=SECTOR_BYTES).contains(&size)
        || u32_at(&header, 20) != 0
        || u64_at(&header, 24) != 1
    {
        return Err(invalid());
    }
    let expected = u32_at(&header, 16);
    header[16..20].fill(0);
    if crc32(&header[..size]) != expected {
        return Err(invalid());
    }
    let first_usable = u64_at(&header, 40);
    let last_usable = u64_at(&header, 48);
    let entries_lba = u64_at(&header, 72);
    let count = u32_at(&header, 80) as usize;
    let entry_size = u32_at(&header, 84) as usize;
    if count == 0 || count > 128 || !matches!(entry_size, 128 | 256 | 512) {
        return Err(invalid());
    }
    let length = count * entry_size;
    let sectors = length.div_ceil(SECTOR_BYTES);
    let array_end = entries_lba
        .checked_add(sectors as u64)
        .ok_or_else(invalid)?;
    if entries_lba < 2
        || array_end > first_usable
        || first_usable > last_usable
        || u64_at(&header, 32) <= last_usable
    {
        return Err(invalid());
    }
    let mut entries = vec![0u8; sectors * SECTOR_BYTES];
    disk.read_sectors(entries_lba, &mut entries)
        .map_err(DiscoveryError::Device)?;
    if crc32(&entries[..length]) != u32_at(&header, 88) {
        return Err(invalid());
    }
    let mut found = None;
    for entry in entries[..length].chunks_exact(entry_size) {
        if entry[..16] == [0; 16] {
            continue;
        }
        let first_lba = u64_at(entry, 32);
        let last_lba = u64_at(entry, 40);
        if first_lba < first_usable || last_lba > last_usable || first_lba > last_lba {
            return Err(invalid());
        }
        if entry[..16] == partition_type {
            let sector_count = last_lba
                .checked_sub(first_lba)
                .and_then(|length| length.checked_add(1))
                .ok_or_else(invalid)?;
            if found
                .replace(PartitionRange {
                    first_lba,
                    sector_count,
                })
                .is_some()
            {
                return Err(DiscoveryError::AmbiguousType);
            }
        }
    }
    Ok(found)
}

fn u32_at(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

fn u64_at(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}

fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = u32::MAX;
    for byte in bytes {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0xedb8_8320 & 0u32.wrapping_sub(crc & 1));
        }
    }
    !crc
}
