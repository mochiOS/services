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
    find_by_type_ordinal(disk, partition_type, 1, 0)
}

/// Selects from an exact-size set of partitions, ordered by starting LBA.
/// The caller owns the meaning of the ordinal (for example a boot slot).
/// A partial or overlapping set is not safe to select from.
pub fn find_by_type_ordinal<D: SectorDevice>(
    disk: &mut D,
    partition_type: [u8; 16],
    expected_count: usize,
    ordinal: usize,
) -> Result<Option<PartitionRange>, DiscoveryError<D::Error>> {
    let invalid = || DiscoveryError::InvalidTable;
    if partition_type == [0; 16]
        || expected_count == 0
        || expected_count > 128
        || ordinal >= expected_count
    {
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
    let mut found = Vec::new();
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
            found.push(PartitionRange {
                first_lba,
                sector_count,
            });
        }
    }
    if found.is_empty() {
        return Ok(None);
    }
    if found.len() != expected_count {
        return Err(DiscoveryError::AmbiguousType);
    }
    found.sort_unstable_by_key(|range| range.first_lba);
    for pair in found.windows(2) {
        let end = pair[0]
            .first_lba
            .checked_add(pair[0].sector_count)
            .ok_or_else(invalid)?;
        if end > pair[1].first_lba {
            return Err(invalid());
        }
    }
    Ok(Some(found[ordinal]))
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

/// Observed GPT contents. Capacity is the table's declared size, not hardware
/// capacity; consumers must preserve that distinction when inquiry is unavailable.
pub struct Table {
    pub guid: [u8; 16],
    pub sectors: u64,
    pub partitions: Vec<PartitionInfo>,
}
pub struct PartitionInfo {
    pub guid: [u8; 16],
    pub range: PartitionRange,
    pub name: String,
}
/// Reads only bounded GPT metadata. Validates CRCs, all extents and unique IDs.
/// Does not repair a damaged table or open an unmounted filesystem.
pub fn inspect<D: SectorDevice>(disk: &mut D) -> Result<Table, DiscoveryError<D::Error>> {
    let invalid = || DiscoveryError::InvalidTable;
    let mut header = [0; SECTOR_BYTES];
    disk.read_sectors(1, &mut header)
        .map_err(DiscoveryError::Device)?;
    let size = u32_at(&header, 12) as usize;
    if &header[..8] != b"EFI PART"
        || u32_at(&header, 8) != 0x10000
        || !(92..=SECTOR_BYTES).contains(&size)
        || u32_at(&header, 20) != 0
        || u64_at(&header, 24) != 1
    {
        return Err(invalid());
    }
    let checksum = u32_at(&header, 16);
    header[16..20].fill(0);
    if crc32(&header[..size]) != checksum {
        return Err(invalid());
    }
    let sectors = u64_at(&header, 32).checked_add(1).ok_or_else(invalid)?;
    if sectors.checked_mul(SECTOR_BYTES as u64).is_none() {
        return Err(invalid());
    }
    let first = u64_at(&header, 40);
    let last = u64_at(&header, 48);
    let start = u64_at(&header, 72);
    let count = u32_at(&header, 80) as usize;
    let entry_size = u32_at(&header, 84) as usize;
    if count == 0
        || count > 128
        || !matches!(entry_size, 128 | 256 | 512)
        || first > last
        || last >= sectors - 1
        || start < 2
    {
        return Err(invalid());
    }
    let length = count * entry_size;
    let rounded = length.div_ceil(SECTOR_BYTES) * SECTOR_BYTES;
    if start
        .checked_add((rounded / SECTOR_BYTES) as u64)
        .is_none_or(|end| end > first)
    {
        return Err(invalid());
    }
    let guid: [u8; 16] = header[56..72].try_into().unwrap();
    if guid == [0; 16] {
        return Err(invalid());
    }
    let mut bytes = vec![0; rounded];
    disk.read_sectors(start, &mut bytes)
        .map_err(DiscoveryError::Device)?;
    if crc32(&bytes[..length]) != u32_at(&header, 88) {
        return Err(invalid());
    }
    let mut partitions = Vec::new();
    let mut identities = std::collections::BTreeSet::new();
    for entry in bytes[..length].chunks_exact(entry_size) {
        if entry[..16] == [0; 16] {
            continue;
        }
        let start = u64_at(entry, 32);
        let end = u64_at(entry, 40);
        let part_guid: [u8; 16] = entry[16..32].try_into().unwrap();
        if start < first
            || end > last
            || start > end
            || part_guid == [0; 16]
            || !identities.insert(part_guid)
        {
            return Err(invalid());
        }
        let units = entry[56..128]
            .chunks_exact(2)
            .map(|v| u16::from_le_bytes([v[0], v[1]]))
            .take_while(|v| *v != 0)
            .collect::<Vec<_>>();
        let name = String::from_utf16_lossy(&units);
        partitions.push(PartitionInfo {
            guid: part_guid,
            range: PartitionRange {
                first_lba: start,
                sector_count: end - start + 1,
            },
            name,
        });
    }
    partitions.sort_by_key(|part| part.range.first_lba);
    if partitions
        .windows(2)
        .any(|pair| pair[0].range.first_lba + pair[0].range.sector_count > pair[1].range.first_lba)
    {
        return Err(invalid());
    }
    Ok(Table {
        guid,
        sectors,
        partitions,
    })
}
